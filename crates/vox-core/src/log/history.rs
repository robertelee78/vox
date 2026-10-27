//! Authenticated sparse log representation (ADR-036 H-6–H-8).
//!
//! These types verify commitments, not room authority. They never fetch, publish, advance a
//! contiguous feed or apply governance. Missing immutable context is an explicit resumable result.
//! The caller owns allocation permits, durable exact-head obligations and current trust checks.

use super::entry::{Entry, MAX_PAYLOAD_LEN};
use super::feed::MAX_SEQ;
use crate::cbor::{Decoder, Encoder};
use crate::error::{Error, Result};
use crate::hash::{sha256, Digest32, COMPOSITE_SIG_LEN};
use crate::identity::composite::{CompositePublicKey, CompositeSignature, RootSigner};
use crate::wire::{frame, parse_frame, signing_input, StructTag};

/// Largest legal retained payload, unchanged from the entry codec.
pub const MAX_PAYLOAD_BYTES: usize = MAX_PAYLOAD_LEN;
/// Maximum signed body-absent entry or head bytes before copying.
pub const MAX_HEADER_BYTES: usize = 8 * 1024;
/// Full entry envelope bound, including signed header and CBOR payload length.
pub const MAX_ENTRY_WIRE: usize = MAX_PAYLOAD_BYTES + MAX_HEADER_BYTES + 9;
/// Maximum framed context-object bytes before decoding.
pub const MAX_CONTEXT_BYTES: usize = 160 * 1024;
/// Maximum one sync frame or proof object, excluding its length prefix.
pub const MAX_FRAME_BYTES: usize = 256 * 1024;
/// Maximum payload bytes outstanding before persisted-offset credit.
pub const MAX_CHUNK_BYTES: usize = 64 * 1024;
/// Total wire credit for one explicit response quantum, including framing.
pub const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
/// Maximum newly requested entry headers in one logical page.
pub const MAX_PAGE_ENTRIES: usize = 128;
/// Hard protocol frontier cardinality; overflow is never truncated.
pub const MAX_CONTEXT_AUTHORS: usize = 2048;
/// Maximum flat preorder tokens in one control interval proof.
pub const MAX_PROOF_TOKENS: usize = 1024;
/// Maximum expanded control headers in one interval proof.
pub const MAX_CONTROL_HEADERS: usize = 8;
/// Maximum tree depth from the existing 2^48 sequence bound.
pub const MAX_TREE_DEPTH: usize = 48;

/// Audience binding of the public log; private streams do not share its proof namespace.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum LogScope {
    /// Public room feed; reserved private scope is refused.
    Public = 0,
}
impl LogScope {
    /// Decode the exact canonical shape and reject unsupported or out-of-range values.
    pub fn decode(value: u64) -> Result<Self> {
        match value {
            0 => Ok(Self::Public),
            _ => Err(Error::MalformedBundle("unsupported log scope")),
        }
    }
}

/// The signed dispatch kind. It is distinct from v1's payload-inferred EntryKind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum SignedEntryKind {
    /// Ordinary text/read content with no operative control effects.
    Content = 0,
    /// Existing public governance payload and authority checks.
    Governance = 1,
    /// Author authentication checkpoint.
    Checkpoint = 2,
    /// Public Session step policy.
    StepPolicy = 3,
    /// Public Session history floor.
    SessionFloor = 4,
    /// Private transport support declaration, granting no access.
    PrivateSupport = 5,
    /// Addressed key delivery with encrypted namespace/generation.
    KeyPackage = 6,
    /// Empty record explicitly advancing signed causal context.
    ContextUpdate = 7,
    /// Empty terminal record; the feed cannot append after it.
    Termination = 8,
}
impl SignedEntryKind {
    /// Decode the exact canonical shape and reject unsupported or out-of-range values.
    pub fn decode(value: u64) -> Result<Self> {
        match value {
            0 => Ok(Self::Content),
            1 => Ok(Self::Governance),
            2 => Ok(Self::Checkpoint),
            3 => Ok(Self::StepPolicy),
            4 => Ok(Self::SessionFloor),
            5 => Ok(Self::PrivateSupport),
            6 => Ok(Self::KeyPackage),
            7 => Ok(Self::ContextUpdate),
            8 => Ok(Self::Termination),
            _ => Err(Error::MalformedBundle("unknown signed entry kind")),
        }
    }
    /// Whether this signed kind contributes one to the authenticated control count.
    pub const fn is_control(self) -> bool {
        !matches!(self, Self::Content)
    }
}

/// An exact signed author position and entry identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EntryReference {
    /// Identity fingerprint owning this coordinate or tree.
    pub author: Digest32,
    /// One-based monotonic author position.
    pub seq: u64,
    /// Exact committed hash; never a receiver-local authorization verdict.
    pub hash: Digest32,
}
impl EntryReference {
    /// Reject malformed bounds, shape or ordering without granting authority.
    pub fn validate(&self) -> Result<()> {
        if self.seq == 0 || self.seq > MAX_SEQ {
            return Err(Error::MalformedBundle("control coordinate sequence"));
        }
        Ok(())
    }
    pub(crate) fn encode(&self, e: &mut Encoder) {
        e.array(3)
            .bytes(&self.author)
            .uint(self.seq)
            .bytes(&self.hash);
    }
    pub(crate) fn decode(d: &mut Decoder<'_>) -> Result<Self> {
        arity(d, 3, "entry reference arity")?;
        let reference = Self {
            author: digest(d)?,
            seq: d.uint()?,
            hash: digest(d)?,
        };
        reference.validate()?;
        Ok(reference)
    }
}

/// Format-2 metadata carried inside the actual EntrySkeleton signed bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EntryV2 {
    /// Signed handler discriminant; payload inspection cannot override it.
    pub kind: SignedEntryKind,
    /// Explicit audience namespace of the commitment.
    pub scope: LogScope,
    /// Hash of the canonical control context preceding this entry.
    pub pre_context: Digest32,
    /// Exact parent references in strict author order, at most sixteen.
    pub seen: Vec<EntryReference>,
    /// Public recipient of a key package; absent for every other kind.
    pub recipient: Option<Digest32>,
}

/// Stable author/room/scope tree identity; epochs do not reset its positions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TreeBinding {
    /// Exact channel identifier binding these bytes.
    pub room: Digest32,
    /// Explicit audience namespace of the commitment.
    pub scope: LogScope,
    /// Identity fingerprint owning this coordinate or tree.
    pub author: Digest32,
}
impl TreeBinding {
    pub(crate) fn decode(d: &mut Decoder<'_>) -> Result<Self> {
        arity(d, 4, "tree binding arity")?;
        if d.uint()? != 2 {
            return Err(Error::MalformedBundle("tree binding format"));
        }
        Ok(Self {
            room: digest(d)?,
            scope: LogScope::decode(d.uint()?)?,
            author: digest(d)?,
        })
    }
    pub(crate) fn encode(&self, e: &mut Encoder) {
        e.array(4)
            .uint(2)
            .bytes(&self.room)
            .uint(self.scope as u64)
            .bytes(&self.author);
    }
    /// Require a format-2 entry with this exact author, room and scope.
    pub fn matches_entry(&self, entry: &Entry) -> Result<()> {
        let v2 = entry
            .skeleton
            .v2
            .as_ref()
            .ok_or(Error::MalformedBundle("v2 header required"))?;
        entry.skeleton.validate_v2()?;
        if entry.skeleton.channel_id != self.room
            || entry.skeleton.author_id != self.author
            || v2.scope != self.scope
        {
            return Err(Error::MalformedBundle("entry/tree binding mismatch"));
        }
        Ok(())
    }
}

/// Canonical immutable control coordinates. Syntactic membership grants no authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ControlContext {
    /// Exact channel identifier binding these bytes.
    pub room: Digest32,
    /// Explicit audience namespace of the commitment.
    pub scope: LogScope,
    /// Strictly author-sorted nonzero positions, at most 2,048.
    pub coordinates: Vec<EntryReference>,
}
impl ControlContext {
    /// Construct the canonical empty value for the specified binding.
    pub fn empty(room: Digest32, scope: LogScope) -> Self {
        Self {
            room,
            scope,
            coordinates: Vec::new(),
        }
    }
    /// Reject malformed bounds, shape or ordering without granting authority.
    pub fn validate(&self) -> Result<()> {
        if self.coordinates.len() > MAX_CONTEXT_AUTHORS {
            return Err(Error::SizeLimitExceeded("control frontier authors"));
        }
        let mut previous = None;
        for coordinate in &self.coordinates {
            coordinate.validate()?;
            if previous.is_some_and(|author| author >= coordinate.author) {
                return Err(Error::MalformedBundle("control frontier order"));
            }
            previous = Some(coordinate.author);
        }
        Ok(())
    }
    /// Encode exactly the canonical body hashed or signed by this type.
    pub fn canonical_body(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.array(4)
            .uint(2)
            .bytes(&self.room)
            .uint(self.scope as u64)
            .array(self.coordinates.len());
        for coordinate in &self.coordinates {
            coordinate.encode(&mut e);
        }
        e.finish()
    }
    /// Compute the domain-separated immutable context identity.
    pub fn hash(&self) -> Digest32 {
        sha256(&signing_input(
            StructTag::ControlContext,
            &self.canonical_body(),
        ))
    }
    /// Encode the exact framed canonical representation.
    pub fn to_wire(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let wire = frame(StructTag::ControlContext, &self.canonical_body());
        if wire.len() > MAX_CONTEXT_BYTES {
            return Err(Error::SizeLimitExceeded("control context bytes"));
        }
        Ok(wire)
    }
    /// Decode bounded canonical wire bytes without assuming signature validity.
    pub fn from_wire(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_CONTEXT_BYTES {
            return Err(Error::SizeLimitExceeded("control context bytes"));
        }
        let f = parse_frame(bytes)?;
        if f.tag != StructTag::ControlContext {
            return Err(Error::MalformedBundle("context tag"));
        }
        let mut d = Decoder::new(f.body);
        arity(&mut d, 4, "context arity")?;
        if d.uint()? != 2 {
            return Err(Error::MalformedBundle("context format"));
        }
        let room = digest(&mut d)?;
        let scope = LogScope::decode(d.uint()?)?;
        let count = d.array()?;
        if count > MAX_CONTEXT_AUTHORS {
            return Err(Error::SizeLimitExceeded("control frontier authors"));
        }
        let mut coordinates = Vec::with_capacity(count);
        for _ in 0..count {
            coordinates.push(EntryReference::decode(&mut d)?);
        }
        d.finish()?;
        let context = Self {
            room,
            scope,
            coordinates,
        };
        context.validate()?;
        Ok(context)
    }
    /// Pure syntactic join. A higher coordinate still needs separately verified feed continuity.
    pub fn join(&self, other: &Self) -> Result<Self> {
        self.validate()?;
        other.validate()?;
        if self.room != other.room || self.scope != other.scope {
            return Err(Error::MalformedBundle("frontier room/scope mismatch"));
        }
        let mut coordinates = Vec::with_capacity(
            (self.coordinates.len() + other.coordinates.len()).min(MAX_CONTEXT_AUTHORS),
        );
        let (mut a, mut b) = (0, 0);
        while a < self.coordinates.len() || b < other.coordinates.len() {
            let left = self.coordinates.get(a);
            let right = other.coordinates.get(b);
            let next = match (left, right) {
                (Some(l), Some(r)) if l.author == r.author => {
                    if l.seq == r.seq && l.hash != r.hash {
                        return Err(Error::MalformedBundle("conflicting frontier coordinate"));
                    }
                    a += 1;
                    b += 1;
                    if l.seq >= r.seq {
                        l
                    } else {
                        r
                    }
                }
                (Some(l), Some(r)) if l.author < r.author => {
                    a += 1;
                    l
                }
                (Some(_), Some(r)) => {
                    b += 1;
                    r
                }
                (Some(l), None) => {
                    a += 1;
                    l
                }
                (None, Some(r)) => {
                    b += 1;
                    r
                }
                (None, None) => break,
            };
            if coordinates.len() == MAX_CONTEXT_AUTHORS {
                return Err(Error::SizeLimitExceeded("joined frontier authors"));
            }
            coordinates.push(next.clone());
        }
        Ok(Self {
            room: self.room,
            scope: self.scope,
            coordinates,
        })
    }
}

/// A committed subtree with authenticated count and control-frontier summaries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Descriptor {
    /// Number of positions covered by this canonical subtree.
    pub leaves: u64,
    /// Number of signed control-kind leaves committed by this subtree.
    pub controls: u64,
    /// Hash of the subtree's canonical joined control context.
    pub frontier: Digest32,
    /// Exact committed hash; never a receiver-local authorization verdict.
    pub hash: Digest32,
}
impl Descriptor {
    /// Reject malformed bounds, shape or ordering without granting authority.
    pub fn validate(&self) -> Result<()> {
        if self.leaves > MAX_SEQ || self.controls > self.leaves {
            return Err(Error::MalformedBundle("tree descriptor counts"));
        }
        Ok(())
    }
    /// Append this value's exact canonical CBOR representation.
    pub fn encode(&self, e: &mut Encoder) {
        e.array(4)
            .uint(self.leaves)
            .uint(self.controls)
            .bytes(&self.frontier)
            .bytes(&self.hash);
    }
    /// Decode the exact canonical shape and reject unsupported or out-of-range values.
    pub fn decode(d: &mut Decoder<'_>) -> Result<Self> {
        arity(d, 4, "descriptor arity")?;
        let value = Self {
            leaves: d.uint()?,
            controls: d.uint()?,
            frontier: digest(d)?,
            hash: digest(d)?,
        };
        value.validate()?;
        Ok(value)
    }
    /// Construct the canonical empty value for the specified binding.
    pub fn empty(binding: TreeBinding) -> Self {
        let frontier = ControlContext::empty(binding.room, binding.scope).hash();
        let mut e = Encoder::new();
        e.array(2);
        binding.encode(&mut e);
        e.bytes(&frontier);
        Self {
            leaves: 0,
            controls: 0,
            frontier,
            hash: domain_hash(b"vox/log-tree/empty/v1", &e.finish()),
        }
    }
}

/// Immutable object lookup only. Implementations read bounded local sealed objects, never network.
pub trait ContextSource {
    /// Read one bounded local immutable object, or None only when the object is absent.
    fn context(&self, hash: &Digest32) -> Result<Option<ControlContext>>;
}

/// Local immutable range lookup used while appending an authored entry. Like context reads,
/// this is a bounded local-store operation; it never fetches a missing archive range.
pub(crate) trait TreeRangeSource: ContextSource {
    fn range(&self, binding: TreeBinding, range: TreeRange) -> Result<Option<Descriptor>>;
}

/// A single trusted local append has a separate, explicit hard quota. It constructs at
/// most 49 right-spine descriptors and reuses the ordinary inclusion/consistency verifiers.
/// This type cannot be supplied to a peer verifier as a resettable remote-turn budget.
pub(crate) struct LocalAppendBudget {
    work: WorkBudget,
}
impl LocalAppendBudget {
    // Up to sixteen peer-prefix joins, eighteen context loads and bounded hash/compare
    // passes. The metadata reserve covers each admitted author's tip + clock and the
    // selected prefix/head lookups. These are prepaid once, not reset per object.
    const PREP_VISITS: usize =
        (4 * (super::entry::MAX_SEEN + 2) + 6 * super::entry::MAX_SEEN + 24) * MAX_CONTEXT_AUTHORS;
    const PREP_OBJECTS: usize = 2 * MAX_CONTEXT_AUTHORS + 4 * super::entry::MAX_SEEN;
    pub(crate) fn new() -> Self {
        const DESCRIPTORS: usize = 4 * (MAX_TREE_DEPTH + 1);
        Self {
            work: WorkBudget {
                signatures_left: 2,
                descriptors_left: DESCRIPTORS,
                coordinates_left: DESCRIPTORS * 20 * MAX_CONTEXT_AUTHORS + Self::PREP_VISITS,
                object_loads_left: 4 * DESCRIPTORS + Self::PREP_OBJECTS,
            },
        }
    }
    /// Prepay the bounded context selection before any store read or map allocation:
    /// at most 2048 tip/header + clock reads, 16 prefix/context pairs, one own head,
    /// and one updated own context after an inserted ContextUpdate. No archive scan.
    pub(crate) fn reserve_context_preparation(&mut self) -> Result<()> {
        const OBJECTS: usize = LocalAppendBudget::PREP_OBJECTS;
        const VISITS: usize = LocalAppendBudget::PREP_VISITS;
        if self.work.object_loads_left < OBJECTS || self.work.coordinates_left < VISITS {
            return Err(Error::SizeLimitExceeded("local context preparation quota"));
        }
        self.work.object_loads_left -= OBJECTS;
        self.work.coordinates_left -= VISITS;
        Ok(())
    }
    pub(crate) fn check_context(
        &mut self,
        source: &impl ContextSource,
        context: &ControlContext,
    ) -> Result<()> {
        if !self.work.take_context_load() {
            return Err(Error::SizeLimitExceeded("local context comparison quota"));
        }
        if source.context(&context.hash())?.as_ref() != Some(context) {
            return Err(Error::MalformedAtRest(
                "authored context dependency missing",
            ));
        }
        Ok(())
    }
    pub(crate) fn verify_header(
        &mut self,
        entry: &Entry,
        binding: TreeBinding,
        key: &CompositePublicKey,
    ) -> Result<VerifiedHeader> {
        match VerifiedHeader::verify(entry, binding, key, &mut self.work)? {
            HistoryStep::Complete(value) => Ok(value),
            _ => Err(Error::SizeLimitExceeded("local header work quota")),
        }
    }
    pub(crate) fn verify_head(
        &mut self,
        head: &SignedHead,
        key: &CompositePublicKey,
    ) -> Result<VerifiedHead> {
        match head.verify(key, &mut self.work)? {
            HistoryStep::Complete(value) => Ok(value),
            _ => Err(Error::SizeLimitExceeded("local head work quota")),
        }
    }
    pub(crate) fn inclusion(
        &mut self,
        verifier: &mut InclusionVerifier,
        source: &impl ContextSource,
    ) -> Result<HistoryStep<IncludedHeader>> {
        verifier.advance(source, &mut self.work)
    }
    pub(crate) fn consistency(
        &mut self,
        verifier: &mut ConsistencyVerifier,
        source: &impl ContextSource,
    ) -> Result<HistoryStep<ConsistentPrefix>> {
        verifier.advance(source, &mut self.work)
    }
    pub(crate) fn range(
        &mut self,
        source: &impl TreeRangeSource,
        binding: TreeBinding,
        range: TreeRange,
    ) -> Result<Option<Descriptor>> {
        if !self.work.take_object_load() {
            return Err(Error::SizeLimitExceeded("local range work quota"));
        }
        source.range(binding, range)
    }
}

/// One new right-spine range. The caller retains only one shared post-context
/// and scalar descriptors, never an archive of intermediate frontier maps.
pub(crate) enum LocalTreeStep {
    Range {
        start: u64,
        descriptor: Descriptor,
        context: ControlContext,
    },
    Complete(Descriptor),
    MissingContext,
    MissingRange,
    Yielded,
}

/// Bounded canonical right-spine append for an individually signed local v2 header.
/// This constructs bytes only: the ordinary consistency/admission and atomic publication
/// paths still own acceptance. A scheduler must not reset a budget inside a hidden drain loop.
pub(crate) struct LocalTreeAppend {
    binding: TreeBinding,
    header: VerifiedHeader,
    left: Vec<TreeRange>,
    current: Option<Descriptor>,
    start: u64,
}
impl LocalTreeAppend {
    pub(crate) fn new(binding: TreeBinding, header: VerifiedHeader) -> Result<Self> {
        binding.matches_entry(header.entry())?;
        let mut start = 1;
        let mut leaves = header.entry().skeleton.seq;
        let mut left = Vec::new();
        while leaves > 1 {
            let size = split(leaves)?;
            left.push(TreeRange {
                start,
                leaves: size,
            });
            start += size;
            leaves -= size;
        }
        if left.len() > MAX_TREE_DEPTH {
            return Err(Error::SizeLimitExceeded("local append depth"));
        }
        Ok(Self {
            binding,
            header,
            left,
            current: None,
            start,
        })
    }

    pub(crate) fn advance(
        &mut self,
        source: &impl TreeRangeSource,
        budget: &mut LocalAppendBudget,
    ) -> Result<LocalTreeStep> {
        let budget = &mut budget.work;
        let Some(current) = self.current else {
            return match leaf_descriptor(self.binding, self.header.entry(), source, budget)? {
                HistoryStep::Complete((descriptor, context)) => {
                    self.current = Some(descriptor);
                    Ok(LocalTreeStep::Range {
                        start: self.start,
                        descriptor,
                        context,
                    })
                }
                HistoryStep::MissingContext(_) => Ok(LocalTreeStep::MissingContext),
                _ => Ok(LocalTreeStep::Yielded),
            };
        };
        let Some(left) = self.left.last().copied() else {
            return Ok(LocalTreeStep::Complete(current));
        };
        if !budget.take_object_load() {
            return Ok(LocalTreeStep::Yielded);
        }
        let Some(descriptor) = source.range(self.binding, left)? else {
            return Ok(LocalTreeStep::MissingRange);
        };
        if descriptor.leaves != left.leaves
            || left.start.checked_add(left.leaves) != Some(self.start)
        {
            return Err(Error::MalformedAtRest("local append range binding"));
        }
        match join_descriptors(self.binding, descriptor, current, source, budget)? {
            HistoryStep::Complete((descriptor, context)) => {
                self.left.pop();
                self.start = left.start;
                self.current = Some(descriptor);
                Ok(LocalTreeStep::Range {
                    start: self.start,
                    descriptor,
                    context,
                })
            }
            HistoryStep::MissingContext(_) => Ok(LocalTreeStep::MissingContext),
            _ => Ok(LocalTreeStep::Yielded),
        }
    }
}

/// Conservative remaining work in one cooperative verification slice.
#[derive(Clone, Debug)]
pub struct WorkBudget {
    /// Composite verifications still permitted before yielding.
    signatures_left: usize,
    /// Leaf/internal reconstructions still permitted before yielding.
    descriptors_left: usize,
    /// Conservatively charged frontier-coordinate visits remaining.
    coordinates_left: usize,
    /// Local object reads permitted before yielding, charged before allocation.
    object_loads_left: usize,
}
impl Default for WorkBudget {
    fn default() -> Self {
        Self {
            signatures_left: 4,
            descriptors_left: 32,
            coordinates_left: 65_536,
            object_loads_left: 64,
        }
    }
}
impl WorkBudget {
    /// Consume one signature operation, or return false before doing that work.
    pub fn take_signature(&mut self) -> bool {
        if self.signatures_left == 0 {
            return false;
        }
        self.signatures_left -= 1;
        true
    }
    pub(crate) fn take_context_load(&mut self) -> bool {
        // Decode, validation and canonical-hash passes, conservatively charged before a
        // disk-backed provider can allocate or walk even a maximum-sized context.
        let visits = 4 * MAX_CONTEXT_AUTHORS;
        if self.object_loads_left == 0 || self.coordinates_left < visits {
            return false;
        }
        self.object_loads_left -= 1;
        self.coordinates_left -= visits;
        true
    }
    /// A context load charged at the maximum size turned out to hold `coordinates`: the
    /// passes walked that many, and the rest of the charge returns to this slice. The charge
    /// stays conservative before the load, so no work starts that the slice could not afford;
    /// after it, the slice is charged what the load cost. Without this a room of a few members
    /// paid 8,192 coordinates for a context of three and a verifier yielded after four joins,
    /// each yield a commit of its cursor (ADR-038 FX-29).
    pub(crate) fn refund_context_load(&mut self, coordinates: usize) {
        let charged = 4 * MAX_CONTEXT_AUTHORS;
        let walked = 4 * coordinates.saturating_add(1);
        self.coordinates_left = self
            .coordinates_left
            .saturating_add(charged.saturating_sub(walked));
    }
    pub(crate) fn take_control_lookup(&mut self) -> bool {
        // A control source locator, its bounded signed header and its completion receipt,
        // plus binary-search/hash binding work in the already loaded canonical maps.
        if self.object_loads_left < 3 || self.coordinates_left < 32 {
            return false;
        }
        self.object_loads_left -= 3;
        self.coordinates_left -= 32;
        true
    }
    pub(crate) fn take_object_load(&mut self) -> bool {
        if self.object_loads_left == 0 {
            return false;
        }
        self.object_loads_left -= 1;
        true
    }
    fn take_descriptor(&mut self, coordinates: usize) -> bool {
        if self.descriptors_left == 0 || self.coordinates_left < coordinates {
            return false;
        }
        self.descriptors_left -= 1;
        self.coordinates_left -= coordinates;
        true
    }
}

/// Progress must be stored under the exact request/head before another slice. A generated context
/// can be persisted by its hash, making the following reconstruction resumable without a full map.
#[derive(Debug)]
pub enum HistoryStep<T> {
    /// This bounded primitive finished; its type states what was actually proved.
    Complete(T),
    /// One generated immutable context is ready to persist before the next step.
    Progress(ControlContext),
    /// An exact immutable object is absent; it must not be treated as empty.
    MissingContext(Digest32),
    /// Work credit exhausted; retain the cursor and resume in another slice.
    Yielded,
}

fn read_context(
    source: &impl ContextSource,
    hash: &Digest32,
    binding: TreeBinding,
    budget: &mut WorkBudget,
) -> Result<HistoryStep<ControlContext>> {
    if !budget.take_context_load() {
        return Ok(HistoryStep::Yielded);
    }
    let Some(context) = source.context(hash)? else {
        return Ok(HistoryStep::MissingContext(*hash));
    };
    context.validate()?;
    if context.room != binding.room || context.scope != binding.scope || context.hash() != *hash {
        return Err(Error::MalformedBundle("context object binding/hash"));
    }
    budget.refund_context_load(context.coordinates.len());
    Ok(HistoryStep::Complete(context))
}

/// Reconstruct a single leaf. This checks signed-byte structure, not the signature or authority.
pub fn leaf_descriptor(
    binding: TreeBinding,
    entry: &Entry,
    source: &impl ContextSource,
    budget: &mut WorkBudget,
) -> Result<HistoryStep<(Descriptor, ControlContext)>> {
    binding.matches_entry(entry)?;
    if budget.descriptors_left == 0 {
        return Ok(HistoryStep::Yielded);
    }
    let v2 = entry
        .skeleton
        .v2
        .as_ref()
        .ok_or(Error::MalformedBundle("v2 leaf required"))?;
    let pre = match read_context(source, &v2.pre_context, binding, budget)? {
        HistoryStep::Complete(context) => context,
        HistoryStep::MissingContext(hash) => return Ok(HistoryStep::MissingContext(hash)),
        _ => return Ok(HistoryStep::Yielded),
    };
    if pre
        .coordinates
        .iter()
        .any(|c| c.author == binding.author && c.seq >= entry.skeleton.seq)
    {
        return Err(Error::MalformedBundle(
            "entry context names own present/future",
        ));
    }
    if !budget.take_descriptor(4 * (pre.coordinates.len() + 1)) {
        return Ok(HistoryStep::Yielded);
    }
    let post = if v2.kind.is_control() {
        pre.join(&ControlContext {
            room: binding.room,
            scope: binding.scope,
            coordinates: vec![EntryReference {
                author: binding.author,
                seq: entry.skeleton.seq,
                hash: entry.entry_hash(),
            }],
        })?
    } else {
        pre
    };
    let frontier = post.hash();
    let controls = u64::from(v2.kind.is_control());
    let mut e = Encoder::new();
    e.array(4);
    binding.encode(&mut e);
    e.bytes(&entry.entry_hash()).uint(controls).bytes(&frontier);
    let descriptor = Descriptor {
        leaves: 1,
        controls,
        frontier,
        hash: domain_hash(b"vox/log-tree/leaf/v1", &e.finish()),
    };
    Ok(HistoryStep::Complete((descriptor, post)))
}

/// Reconstruct one canonical internal node, checking its child descriptors and frontier join.
pub fn join_descriptors(
    binding: TreeBinding,
    left: Descriptor,
    right: Descriptor,
    source: &impl ContextSource,
    budget: &mut WorkBudget,
) -> Result<HistoryStep<(Descriptor, ControlContext)>> {
    left.validate()?;
    right.validate()?;
    if budget.descriptors_left == 0 {
        return Ok(HistoryStep::Yielded);
    }
    let leaves = left
        .leaves
        .checked_add(right.leaves)
        .ok_or(Error::SizeLimitExceeded("tree count overflow"))?;
    if left.leaves == 0 || right.leaves == 0 || leaves > MAX_SEQ || left.leaves != split(leaves)? {
        return Err(Error::MalformedBundle("noncanonical tree split"));
    }
    let l = match read_context(source, &left.frontier, binding, budget)? {
        HistoryStep::Complete(context) => context,
        HistoryStep::MissingContext(hash) => return Ok(HistoryStep::MissingContext(hash)),
        _ => return Ok(HistoryStep::Yielded),
    };
    let r = match read_context(source, &right.frontier, binding, budget)? {
        HistoryStep::Complete(context) => context,
        HistoryStep::MissingContext(hash) => return Ok(HistoryStep::MissingContext(hash)),
        _ => return Ok(HistoryStep::Yielded),
    };
    if !budget.take_descriptor(3 * (l.coordinates.len() + r.coordinates.len())) {
        return Ok(HistoryStep::Yielded);
    }
    let joined = l.join(&r)?;
    let frontier = joined.hash();
    let controls = left
        .controls
        .checked_add(right.controls)
        .ok_or(Error::SizeLimitExceeded("tree control count overflow"))?;
    let mut e = Encoder::new();
    e.array(4);
    binding.encode(&mut e);
    left.encode(&mut e);
    right.encode(&mut e);
    e.bytes(&frontier);
    Ok(HistoryStep::Complete((
        Descriptor {
            leaves,
            controls,
            frontier,
            hash: domain_hash(b"vox/log-tree/node/v1", &e.finish()),
        },
        joined,
    )))
}

/// An author-signed descriptor; a signature alone does not prove continuity.
#[derive(Clone)]
pub struct SignedHead {
    /// Exact room, scope and author binding.
    pub binding: TreeBinding,
    /// Signed epoch of the terminal leaf; checked against that leaf on inclusion.
    pub tail_epoch: u64,
    /// Complete target descriptor, including counts and context hash.
    pub root: Descriptor,
    /// Author composite signature over the canonical head body/domain.
    pub signature: Box<CompositeSignature>,
}
impl core::fmt::Debug for SignedHead {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SignedHead")
            .field("binding", &self.binding)
            .field("tail_epoch", &self.tail_epoch)
            .field("root", &self.root)
            .finish_non_exhaustive()
    }
}
impl SignedHead {
    fn encode_body(&self, e: &mut Encoder) {
        e.uint(2)
            .bytes(&self.binding.author)
            .bytes(&self.binding.room)
            .uint(self.binding.scope as u64)
            .uint(self.tail_epoch);
        self.root.encode(e);
    }
    /// Encode exactly the canonical body hashed or signed by this type.
    pub fn canonical_body(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.array(6);
        self.encode_body(&mut e);
        e.finish()
    }
    /// Identify the canonical signed head body, excluding randomized signature bytes.
    pub fn id(&self) -> Digest32 {
        sha256(&signing_input(StructTag::LogHead, &self.canonical_body()))
    }
    /// Sign this descriptor with its exact author's root key.
    pub fn sign(
        binding: TreeBinding,
        tail_epoch: u64,
        root: Descriptor,
        signer: &dyn RootSigner,
    ) -> Result<Self> {
        root.validate()?;
        if root.leaves == 0 && root != Descriptor::empty(binding) {
            return Err(Error::MalformedBundle("noncanonical empty head"));
        }
        if signer.fingerprint() != binding.author {
            return Err(Error::MalformedBundle("head signer mismatch"));
        }
        let mut e = Encoder::new();
        e.array(6)
            .uint(2)
            .bytes(&binding.author)
            .bytes(&binding.room)
            .uint(binding.scope as u64)
            .uint(tail_epoch);
        root.encode(&mut e);
        let signature = Box::new(signer.sign(&signing_input(StructTag::LogHead, &e.finish()))?);
        Ok(Self {
            binding,
            tail_epoch,
            root,
            signature,
        })
    }
    /// Verify authentication under the supplied key and available signature work credit.
    pub fn verify(
        &self,
        key: &CompositePublicKey,
        budget: &mut WorkBudget,
    ) -> Result<HistoryStep<VerifiedHead>> {
        self.root.validate()?;
        if key.fingerprint() != self.binding.author {
            return Err(Error::MalformedBundle("head author/key mismatch"));
        }
        if self.root.leaves == 0 && self.root != Descriptor::empty(self.binding) {
            return Err(Error::MalformedBundle("noncanonical empty head"));
        }
        if !budget.take_signature() {
            return Ok(HistoryStep::Yielded);
        }
        key.verify(
            &signing_input(StructTag::LogHead, &self.canonical_body()),
            &self.signature,
        )?;
        Ok(HistoryStep::Complete(VerifiedHead(self.clone())))
    }
    /// Encode the exact framed canonical representation.
    pub fn to_wire(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.array(8);
        self.encode_body(&mut e);
        e.uint(1).bytes(&self.signature.to_bytes());
        frame(StructTag::LogHead, &e.finish())
    }
    /// Decode bounded canonical wire bytes without assuming signature validity.
    pub fn from_wire(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_HEADER_BYTES {
            return Err(Error::SizeLimitExceeded("signed head bytes"));
        }
        let f = parse_frame(bytes)?;
        if f.tag != StructTag::LogHead {
            return Err(Error::MalformedBundle("head tag"));
        }
        let mut d = Decoder::new(f.body);
        arity(&mut d, 8, "head arity")?;
        if d.uint()? != 2 {
            return Err(Error::MalformedBundle("head format"));
        }
        let author = digest(&mut d)?;
        let room = digest(&mut d)?;
        let scope = LogScope::decode(d.uint()?)?;
        let tail_epoch = d.uint()?;
        let root = Descriptor::decode(&mut d)?;
        if d.uint()? != 1 {
            return Err(Error::MalformedBundle("head authenticator type"));
        }
        let sig: &[u8; COMPOSITE_SIG_LEN] = d
            .bytes()?
            .try_into()
            .map_err(|_| Error::MalformedBundle("head signature length"))?;
        let signature = Box::new(CompositeSignature::from_bytes(sig)?);
        d.finish()?;
        Ok(Self {
            binding: TreeBinding {
                room,
                scope,
                author,
            },
            tail_epoch,
            root,
            signature,
        })
    }
}

/// Signature-valid only: not a consistency verdict, admission, control-ready state or a Feed head.
#[derive(Clone, Debug)]
pub struct VerifiedHead(SignedHead);
impl VerifiedHead {
    /// Borrow the signature-valid head; continuity and authority are not implied.
    pub fn head(&self) -> &SignedHead {
        &self.0
    }
}

/// Authenticated exact header; it has not acquired any room authority or causal edge.
#[derive(Clone, Debug)]
pub struct VerifiedHeader(Entry);
impl VerifiedHeader {
    /// Borrow the individually authenticated body-absent entry.
    pub fn entry(&self) -> &Entry {
        &self.0
    }
    /// Verify authentication under the supplied key and available signature work credit.
    pub fn verify(
        entry: &Entry,
        binding: TreeBinding,
        key: &CompositePublicKey,
        budget: &mut WorkBudget,
    ) -> Result<HistoryStep<Self>> {
        binding.matches_entry(entry)?;
        if entry.payload.is_some() || entry.header_wire().len() > MAX_HEADER_BYTES {
            return Err(Error::MalformedBundle(
                "expected bounded body-absent header",
            ));
        }
        if !budget.take_signature() {
            return Ok(HistoryStep::Yielded);
        }
        entry.verify(key)?;
        Ok(HistoryStep::Complete(Self(entry.clone())))
    }
}

fn domain_hash(domain: &[u8], body: &[u8]) -> Digest32 {
    let mut bytes = Vec::with_capacity(domain.len() + body.len());
    bytes.extend_from_slice(domain);
    bytes.extend_from_slice(body);
    sha256(&bytes)
}
fn digest(d: &mut Decoder<'_>) -> Result<Digest32> {
    d.bytes()?
        .try_into()
        .map_err(|_| Error::MalformedBundle("history digest length"))
}
fn arity(d: &mut Decoder<'_>, expected: usize, message: &'static str) -> Result<()> {
    if d.array()? != expected {
        return Err(Error::MalformedBundle(message));
    }
    Ok(())
}
/// Largest power of two strictly smaller than a non-leaf tree.
pub fn split(leaves: u64) -> Result<u64> {
    if !(2..=MAX_SEQ).contains(&leaves) {
        return Err(Error::MalformedBundle("tree split size"));
    }
    Ok(1u64 << (63 - (leaves - 1).leading_zeros()))
}

/// Bottom-up canonical siblings for one exact position under one tree size.
#[derive(Clone, Debug)]
pub struct InclusionProof {
    /// One-based position of the included entry.
    pub position: u64,
    /// Target head's exact number of leaves.
    pub size: u64,
    /// Bottom-up sibling descriptors, never more than the tree depth.
    pub siblings: Vec<Descriptor>,
}
impl InclusionProof {
    /// Reject malformed bounds, shape or ordering without granting authority.
    pub fn validate(&self) -> Result<()> {
        if self.position == 0
            || self.position > self.size
            || self.size > MAX_SEQ
            || self.siblings.len() > MAX_TREE_DEPTH
        {
            return Err(Error::MalformedBundle("inclusion proof bounds"));
        }
        for descriptor in &self.siblings {
            descriptor.validate()?;
        }
        Ok(())
    }
    /// Append this value's exact canonical CBOR representation.
    pub fn encode(&self, e: &mut Encoder) {
        e.array(3)
            .uint(self.position)
            .uint(self.size)
            .array(self.siblings.len());
        for descriptor in &self.siblings {
            descriptor.encode(e);
        }
    }
    /// Decode the exact canonical shape and reject unsupported or out-of-range values.
    pub fn decode(d: &mut Decoder<'_>) -> Result<Self> {
        arity(d, 3, "inclusion proof arity")?;
        let position = d.uint()?;
        let size = d.uint()?;
        let siblings = decode_descriptors(d, MAX_TREE_DEPTH)?;
        let proof = Self {
            position,
            size,
            siblings,
        };
        proof.validate()?;
        Ok(proof)
    }
    /// Decode one bounded canonical proof object and reject trailing bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        bounded_proof(bytes)?;
        let mut d = Decoder::new(bytes);
        let proof = Self::decode(&mut d)?;
        d.finish()?;
        Ok(proof)
    }
    /// Encode one bounded canonical proof object.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut e = Encoder::new();
        self.encode(&mut e);
        Ok(e.finish())
    }
}

/// Canonical consistency path between two prefix sizes of the same tree.
#[derive(Clone, Debug)]
pub struct ConsistencyProof {
    /// Earlier committed prefix size.
    pub from: u64,
    /// Later target tree size.
    pub to: u64,
    /// Canonical consistency path, at most depth plus one descriptors.
    pub nodes: Vec<Descriptor>,
}
impl ConsistencyProof {
    /// Reject malformed bounds, shape or ordering without granting authority.
    pub fn validate(&self) -> Result<()> {
        if self.from > self.to || self.to > MAX_SEQ || self.nodes.len() > MAX_TREE_DEPTH + 1 {
            return Err(Error::MalformedBundle("consistency proof bounds"));
        }
        if (self.from == 0 || self.from == self.to) && !self.nodes.is_empty() {
            return Err(Error::MalformedBundle("consistency empty/equal proof"));
        }
        for descriptor in &self.nodes {
            descriptor.validate()?;
        }
        Ok(())
    }
    /// Append this value's exact canonical CBOR representation.
    pub fn encode(&self, e: &mut Encoder) {
        e.array(3)
            .uint(self.from)
            .uint(self.to)
            .array(self.nodes.len());
        for descriptor in &self.nodes {
            descriptor.encode(e);
        }
    }
    /// Decode the exact canonical shape and reject unsupported or out-of-range values.
    pub fn decode(d: &mut Decoder<'_>) -> Result<Self> {
        arity(d, 3, "consistency proof arity")?;
        let from = d.uint()?;
        let to = d.uint()?;
        let nodes = decode_descriptors(d, MAX_TREE_DEPTH + 1)?;
        let proof = Self { from, to, nodes };
        proof.validate()?;
        Ok(proof)
    }
    /// Decode one bounded canonical proof object and reject trailing bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        bounded_proof(bytes)?;
        let mut d = Decoder::new(bytes);
        let proof = Self::decode(&mut d)?;
        d.finish()?;
        Ok(proof)
    }
    /// Encode one bounded canonical proof object.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut e = Encoder::new();
        self.encode(&mut e);
        Ok(e.finish())
    }
}

/// Exact signed-header inclusion; control closure and authority are still pending.
#[derive(Clone, Debug)]
pub struct IncludedHeader {
    /// Domain-separated identity of the exact signed target head body.
    head_id: Digest32,
    /// Exact room, scope and author binding.
    binding: TreeBinding,
    /// Complete target descriptor, including counts and context hash.
    root: Descriptor,
    /// Individually authenticated body-absent entry.
    header: VerifiedHeader,
}
impl IncludedHeader {
    pub(crate) fn local_receipt(&self) -> Result<Vec<u8>> {
        let mut e = Encoder::new();
        e.array(5).uint(1).bytes(&self.head_id);
        self.binding.encode(&mut e);
        self.root.encode(&mut e);
        e.bytes(&self.header.entry().header_wire());
        checkpoint_bytes(e)
    }
    /// Only bytes authenticated by the local sealed receipt store may call this. This is
    /// not a wire decoder or an alternate peer signature/inclusion verification path.
    pub(crate) fn from_authenticated_receipt(bytes: &[u8]) -> Result<Self> {
        let mut d = checkpoint_decoder(bytes)?;
        arity(&mut d, 5, "included receipt arity")?;
        if d.uint()? != 1 {
            return Err(Error::MalformedAtRest("included receipt version"));
        }
        let head_id = digest(&mut d)?;
        let binding = TreeBinding::decode(&mut d)?;
        let root = Descriptor::decode(&mut d)?;
        let header = local_header(&mut d)?;
        d.finish()?;
        binding.matches_entry(header.entry())?;
        if header.entry().skeleton.seq > root.leaves {
            return Err(Error::MalformedAtRest("included receipt position"));
        }
        Ok(Self {
            head_id,
            binding,
            root,
            header,
        })
    }
    /// Exact authenticated target head identity.
    pub fn head_id(&self) -> Digest32 {
        self.head_id
    }
    /// Exact room, scope and author of the verified statement.
    pub fn binding(&self) -> TreeBinding {
        self.binding
    }
    /// Authenticated target descriptor.
    pub fn root(&self) -> Descriptor {
        self.root
    }
    /// Exact individually authenticated and included header.
    pub fn header(&self) -> &VerifiedHeader {
        &self.header
    }
}

/// Maximum transient range trace from one existing bounded proof, including reconstructed
/// parents. It is not a larger wire allowance or a new scheduling limit.
pub(crate) const PROOF_RANGE_SLOTS: usize = 2 * MAX_PROOF_TOKENS + 4 * MAX_TREE_DEPTH + 4;
pub(crate) const PROOF_RANGE_BYTES: usize =
    PROOF_RANGE_SLOTS * std::mem::size_of::<(u64, Descriptor)>();
fn retain_range(ranges: &mut Vec<(u64, Descriptor)>, start: u64, value: Descriptor) -> Result<()> {
    if ranges.len() == PROOF_RANGE_SLOTS {
        return Err(Error::SizeLimitExceeded("verified proof range trace"));
    }
    ranges.push((start, value));
    Ok(())
}

/// Bounded inclusion reconstruction. Keep this cursor with its exact immutable proof/head.
#[derive(Clone, Debug)]
pub struct InclusionVerifier {
    head: VerifiedHead,
    header: VerifiedHeader,
    proof: InclusionProof,
    next: usize,
    index: u64,
    last: u64,
    current: Option<Descriptor>,
    // Transient only: publication requires the exact completed root below.
    ranges: Vec<(u64, Descriptor)>,
}
impl InclusionVerifier {
    /// Exact immutable target of an authenticated local checkpoint, checked by its store slot.
    pub(crate) fn checkpoint_target(&self) -> (Digest32, TreeBinding, u64, u64) {
        let (from, through) = (self.proof.position, self.proof.position);
        (
            self.head.head().id(),
            self.head.head().binding,
            from,
            through,
        )
    }
    /// Bind this reconstruction cursor to its exact immutable inputs.
    pub fn new(head: VerifiedHead, header: VerifiedHeader, proof: InclusionProof) -> Result<Self> {
        proof.validate()?;
        head.head().binding.matches_entry(header.entry())?;
        if proof.position != header.entry().skeleton.seq || proof.size != head.head().root.leaves {
            return Err(Error::MalformedBundle("inclusion target mismatch"));
        }
        if proof.position == proof.size && header.entry().skeleton.epoch != head.head().tail_epoch {
            return Err(Error::MalformedBundle("head terminal epoch mismatch"));
        }
        let coordinates = inclusion_ranges(proof.position, proof.size)?;
        if coordinates.len() != proof.siblings.len() {
            return Err(Error::MalformedBundle("inclusion range count"));
        }
        let mut ranges = Vec::with_capacity(2 * MAX_TREE_DEPTH + 1);
        for (range, descriptor) in coordinates.into_iter().zip(&proof.siblings) {
            if range.leaves != descriptor.leaves {
                return Err(Error::MalformedBundle("inclusion range length"));
            }
            retain_range(&mut ranges, range.start, *descriptor)?;
        }
        Ok(Self {
            index: proof.position - 1,
            last: proof.size - 1,
            head,
            header,
            proof,
            next: 0,
            current: None,
            ranges,
        })
    }
    pub(crate) fn take_verified_ranges(&mut self) -> Result<Vec<(u64, Descriptor)>> {
        if self.last != 0
            || self.next != self.proof.siblings.len()
            || self.current != Some(self.head.head().root)
        {
            return Err(Error::MalformedBundle("incomplete inclusion range trace"));
        }
        Ok(std::mem::take(&mut self.ranges))
    }
    /// Advance bounded work; persist generated context and cursor before another slice.
    pub fn advance(
        &mut self,
        source: &impl ContextSource,
        budget: &mut WorkBudget,
    ) -> Result<HistoryStep<IncludedHeader>> {
        let binding = self.head.head().binding;
        let Some(current) = self.current else {
            return match leaf_descriptor(binding, self.header.entry(), source, budget)? {
                HistoryStep::Complete((descriptor, context)) => {
                    self.current = Some(descriptor);
                    retain_range(&mut self.ranges, self.proof.position, descriptor)?;
                    Ok(HistoryStep::Progress(context))
                }
                HistoryStep::MissingContext(hash) => Ok(HistoryStep::MissingContext(hash)),
                HistoryStep::Yielded => Ok(HistoryStep::Yielded),
                HistoryStep::Progress(context) => Ok(HistoryStep::Progress(context)),
            };
        };
        let Some(sibling) = self.proof.siblings.get(self.next).copied() else {
            if self.last != 0 || current != self.head.head().root {
                return Err(Error::MalformedBundle("inclusion root mismatch"));
            }
            return Ok(HistoryStep::Complete(IncludedHeader {
                head_id: self.head.head().id(),
                binding,
                root: current,
                header: self.header.clone(),
            }));
        };
        if self.last == 0 {
            return Err(Error::MalformedBundle("extra inclusion sibling"));
        }
        let sibling_left = self.index & 1 == 1 || self.index == self.last;
        let (left, right) = if sibling_left {
            (sibling, current)
        } else {
            (current, sibling)
        };
        match join_descriptors(binding, left, right, source, budget)? {
            HistoryStep::Complete((descriptor, context)) => {
                let mut start = self.proof.position;
                for range in inclusion_ranges(self.proof.position, self.proof.size)?
                    .into_iter()
                    .take(self.next + 1)
                {
                    start = start.min(range.start);
                }
                retain_range(&mut self.ranges, start, descriptor)?;
                self.current = Some(descriptor);
                self.next += 1;
                if sibling_left {
                    while self.index & 1 == 0 && self.index != 0 {
                        self.index >>= 1;
                        self.last >>= 1;
                    }
                }
                self.index >>= 1;
                self.last >>= 1;
                Ok(HistoryStep::Progress(context))
            }
            HistoryStep::MissingContext(hash) => Ok(HistoryStep::MissingContext(hash)),
            HistoryStep::Yielded => Ok(HistoryStep::Yielded),
            HistoryStep::Progress(context) => Ok(HistoryStep::Progress(context)),
        }
    }
}

/// Prefix identity only. It is not a claim that omitted entry semantics or control were checked.
#[derive(Clone, Debug)]
pub struct ConsistentPrefix {
    /// Domain-separated identity of the exact signed target head body.
    head_id: Digest32,
    /// Exact room, scope and author binding.
    binding: TreeBinding,
    /// Exact earlier prefix descriptor, not just its size.
    prefix: Descriptor,
    /// Complete target descriptor, including counts and context hash.
    root: Descriptor,
}
impl ConsistentPrefix {
    /// Construct the only consistency receipt that needs no tree source: a verified
    /// canonical empty head against its canonical empty prefix. New sparse rooms persist
    /// this exact author-signed head so another member can acknowledge an empty feed.
    pub(crate) fn empty(head: &VerifiedHead) -> Result<Self> {
        let signed = head.head();
        let empty = Descriptor::empty(signed.binding);
        if signed.root != empty {
            return Err(Error::MalformedBundle("nonempty head used as empty prefix"));
        }
        Ok(Self {
            head_id: signed.id(),
            binding: signed.binding,
            prefix: empty,
            root: empty,
        })
    }
    pub(crate) fn local_receipt(&self) -> Result<Vec<u8>> {
        let mut e = Encoder::new();
        e.array(5).uint(1).bytes(&self.head_id);
        self.binding.encode(&mut e);
        self.prefix.encode(&mut e);
        self.root.encode(&mut e);
        checkpoint_bytes(e)
    }
    /// Restore only from the authenticated local receipt store, never peer bytes.
    pub(crate) fn from_authenticated_receipt(bytes: &[u8]) -> Result<Self> {
        let mut d = checkpoint_decoder(bytes)?;
        arity(&mut d, 5, "prefix receipt arity")?;
        if d.uint()? != 1 {
            return Err(Error::MalformedAtRest("prefix receipt version"));
        }
        let head_id = digest(&mut d)?;
        let binding = TreeBinding::decode(&mut d)?;
        let prefix = Descriptor::decode(&mut d)?;
        let root = Descriptor::decode(&mut d)?;
        d.finish()?;
        if prefix.leaves > root.leaves
            || (prefix.leaves == 0 && prefix != Descriptor::empty(binding))
        {
            return Err(Error::MalformedAtRest("prefix receipt bounds"));
        }
        Ok(Self {
            head_id,
            binding,
            prefix,
            root,
        })
    }
    /// Exact authenticated target head identity.
    pub fn head_id(&self) -> Digest32 {
        self.head_id
    }
    /// Exact room, scope and author of the verified statement.
    pub fn binding(&self) -> TreeBinding {
        self.binding
    }
    /// Earlier descriptor proven consistent with the target.
    pub fn prefix(&self) -> Descriptor {
        self.prefix
    }
    /// Authenticated target descriptor.
    pub fn root(&self) -> Descriptor {
        self.root
    }
}

/// RFC 9162 consistency traversal over Vox's augmented descriptors. A left step updates two
/// accumulators, so its phase is retained across yields rather than repeating the first join.
#[derive(Clone, Debug)]
pub struct ConsistencyVerifier {
    head: VerifiedHead,
    prefix: Descriptor,
    proof: ConsistencyProof,
    next: usize,
    index: u64,
    last: u64,
    old_acc: Descriptor,
    new_acc: Descriptor,
    old_joined: bool,
    ranges: Vec<(u64, Descriptor)>,
}
impl ConsistencyVerifier {
    /// Exact immutable target of an authenticated local checkpoint, checked by its store slot.
    pub(crate) fn checkpoint_target(&self) -> (Digest32, TreeBinding, u64, u64) {
        let (from, through) = (self.proof.from, self.proof.to);
        (
            self.head.head().id(),
            self.head.head().binding,
            from,
            through,
        )
    }
    /// Bind this reconstruction cursor to its exact immutable inputs.
    pub fn new(head: VerifiedHead, prefix: Descriptor, proof: ConsistencyProof) -> Result<Self> {
        proof.validate()?;
        prefix.validate()?;
        if proof.from != prefix.leaves || proof.to != head.head().root.leaves {
            return Err(Error::MalformedBundle("consistency target mismatch"));
        }
        let mut index = proof.from.saturating_sub(1);
        let mut last = proof.to.saturating_sub(1);
        while index & 1 == 1 {
            index >>= 1;
            last >>= 1;
        }
        let (acc, next) =
            if proof.from == 0 || proof.from == proof.to || proof.from.is_power_of_two() {
                (prefix, 0)
            } else {
                (
                    *proof
                        .nodes
                        .first()
                        .ok_or(Error::MalformedBundle("missing consistency seed"))?,
                    1,
                )
            };
        if proof.from > 0 && proof.from < proof.to && proof.nodes.is_empty() {
            return Err(Error::MalformedBundle("empty advancing consistency proof"));
        }
        let coordinates = consistency_ranges(proof.from, proof.to)?;
        if coordinates.len() != proof.nodes.len() {
            return Err(Error::MalformedBundle("consistency range count"));
        }
        let mut ranges = Vec::with_capacity(4 * MAX_TREE_DEPTH + 4);
        if prefix.leaves != 0 {
            retain_range(&mut ranges, 1, prefix)?;
        }
        for (range, descriptor) in coordinates.into_iter().zip(&proof.nodes) {
            if range.leaves != descriptor.leaves {
                return Err(Error::MalformedBundle("consistency range length"));
            }
            retain_range(&mut ranges, range.start, *descriptor)?;
        }
        Ok(Self {
            head,
            prefix,
            proof,
            next,
            index,
            last,
            old_acc: acc,
            new_acc: acc,
            old_joined: false,
            ranges,
        })
    }
    pub(crate) fn take_verified_ranges(&mut self) -> Result<Vec<(u64, Descriptor)>> {
        let complete = if self.proof.from == 0 {
            self.prefix == Descriptor::empty(self.head.head().binding)
        } else if self.proof.from == self.proof.to {
            self.prefix == self.head.head().root
        } else {
            !self.old_joined
                && self.next == self.proof.nodes.len()
                && self.last == 0
                && self.old_acc == self.prefix
                && self.new_acc == self.head.head().root
        };
        if !complete {
            return Err(Error::MalformedBundle("incomplete consistency range trace"));
        }
        if self.head.head().root.leaves != 0 {
            retain_range(&mut self.ranges, 1, self.head.head().root)?;
        }
        Ok(std::mem::take(&mut self.ranges))
    }
    fn accumulator_starts(&self) -> Result<(u64, u64)> {
        let ranges = consistency_ranges(self.proof.from, self.proof.to)?;
        let seeded = self.proof.from != 0
            && self.proof.from != self.proof.to
            && !self.proof.from.is_power_of_two();
        let mut old = if seeded {
            ranges
                .first()
                .ok_or(Error::MalformedBundle("consistency seed range"))?
                .start
        } else {
            1
        };
        let mut new = old;
        for range in ranges.iter().take(self.next).skip(usize::from(seeded)) {
            if range.start < new {
                old = old.min(range.start);
                new = range.start;
            }
        }
        if self.old_joined {
            old = old.min(
                ranges
                    .get(self.next)
                    .ok_or(Error::MalformedBundle("consistency partial range"))?
                    .start,
            );
        }
        Ok((old, new))
    }
    /// Advance bounded work; persist generated context and cursor before another slice.
    pub fn advance(
        &mut self,
        source: &impl ContextSource,
        budget: &mut WorkBudget,
    ) -> Result<HistoryStep<ConsistentPrefix>> {
        let binding = self.head.head().binding;
        let result = || ConsistentPrefix {
            head_id: self.head.head().id(),
            binding,
            prefix: self.prefix,
            root: self.head.head().root,
        };
        if self.proof.from == 0 {
            if self.prefix != Descriptor::empty(binding) {
                return Err(Error::MalformedBundle("consistency empty prefix"));
            }
            // Caller must still reject an empty baseline if it has an accepted root/legacy boundary.
            return Ok(HistoryStep::Complete(result()));
        }
        if self.proof.from == self.proof.to {
            if self.prefix != self.head.head().root {
                return Err(Error::MalformedBundle("equal-size head conflict"));
            }
            return Ok(HistoryStep::Complete(result()));
        }
        let Some(node) = self.proof.nodes.get(self.next).copied() else {
            if self.old_joined
                || self.last != 0
                || self.old_acc != self.prefix
                || self.new_acc != self.head.head().root
            {
                return Err(Error::MalformedBundle("consistency root mismatch"));
            }
            return Ok(HistoryStep::Complete(result()));
        };
        if self.last == 0 {
            return Err(Error::MalformedBundle("extra consistency node"));
        }
        let on_left = self.index & 1 == 1 || self.index == self.last;
        let update_old = on_left && !self.old_joined;
        let (left, right) = if update_old {
            (node, self.old_acc)
        } else if on_left {
            (node, self.new_acc)
        } else {
            (self.new_acc, node)
        };
        match join_descriptors(binding, left, right, source, budget)? {
            HistoryStep::Complete((descriptor, context)) => {
                let (old_start, new_start) = self.accumulator_starts()?;
                let node_start = consistency_ranges(self.proof.from, self.proof.to)?
                    .get(self.next)
                    .ok_or(Error::MalformedBundle("consistency node range"))?
                    .start;
                retain_range(
                    &mut self.ranges,
                    if update_old {
                        old_start.min(node_start)
                    } else {
                        new_start.min(node_start)
                    },
                    descriptor,
                )?;
                if update_old {
                    self.old_acc = descriptor;
                    self.old_joined = true;
                } else {
                    self.new_acc = descriptor;
                    self.old_joined = false;
                    self.next += 1;
                    if on_left {
                        while self.index & 1 == 0 && self.index != 0 {
                            self.index >>= 1;
                            self.last >>= 1;
                        }
                    }
                    self.index >>= 1;
                    self.last >>= 1;
                }
                Ok(HistoryStep::Progress(context))
            }
            HistoryStep::MissingContext(hash) => Ok(HistoryStep::MissingContext(hash)),
            HistoryStep::Yielded => Ok(HistoryStep::Yielded),
            HistoryStep::Progress(context) => Ok(HistoryStep::Progress(context)),
        }
    }
}

/// One flat preorder action; branch orientation comes from the canonical tree split.
#[derive(Clone, Debug)]
pub enum ControlToken {
    /// Commit a subtree; within the requested interval its control count must be zero.
    Collapse(Descriptor),
    /// Expand one signed control header at its exact tree position.
    Leaf(Box<Entry>),
    /// Visit canonical left and right children next.
    Branch,
}
/// Counted coverage of a precise interval under one exact head identity.
#[derive(Clone, Debug)]
pub struct ControlRangeProof {
    /// Domain-separated identity of the exact signed target head body.
    pub head_id: Digest32,
    /// First covered one-based position, inclusive.
    pub lo: u64,
    /// Last covered one-based position, inclusive.
    pub hi: u64,
    /// Flat preorder proof actions, bounded before allocation.
    pub tokens: Vec<ControlToken>,
}
impl ControlRangeProof {
    fn validate(&self) -> Result<()> {
        if self.lo == 0
            || self.lo > self.hi
            || self.hi > MAX_SEQ
            || self.tokens.len() > MAX_PROOF_TOKENS
        {
            return Err(Error::MalformedBundle("control proof bounds"));
        }
        let mut headers = 0;
        for token in &self.tokens {
            match token {
                ControlToken::Collapse(descriptor) => descriptor.validate()?,
                ControlToken::Leaf(entry) => {
                    headers += 1;
                    if headers > MAX_CONTROL_HEADERS
                        || entry.payload.is_some()
                        || entry.header_wire().len() > MAX_HEADER_BYTES
                    {
                        return Err(Error::SizeLimitExceeded("control proof headers"));
                    }
                }
                ControlToken::Branch => {}
            }
        }
        Ok(())
    }
    /// Encode one bounded canonical proof object.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut e = Encoder::new();
        e.array(4)
            .bytes(&self.head_id)
            .uint(self.lo)
            .uint(self.hi)
            .array(self.tokens.len());
        for token in &self.tokens {
            match token {
                ControlToken::Collapse(descriptor) => {
                    e.array(2).uint(0);
                    descriptor.encode(&mut e);
                }
                ControlToken::Leaf(entry) => {
                    e.array(2).uint(1).bytes(&entry.header_wire());
                }
                ControlToken::Branch => {
                    e.array(1).uint(2);
                }
            }
        }
        let bytes = e.finish();
        bounded_proof(&bytes)?;
        Ok(bytes)
    }
    /// Decode one bounded canonical proof object and reject trailing bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        bounded_proof(bytes)?;
        let mut d = Decoder::new(bytes);
        arity(&mut d, 4, "control proof arity")?;
        let head_id = digest(&mut d)?;
        let lo = d.uint()?;
        let hi = d.uint()?;
        let count = d.array()?;
        if count > MAX_PROOF_TOKENS {
            return Err(Error::SizeLimitExceeded("control proof tokens"));
        }
        let mut tokens = Vec::with_capacity(count);
        let mut headers = 0;
        for _ in 0..count {
            let len = d.array()?;
            let token = match (d.uint()?, len) {
                (0, 2) => ControlToken::Collapse(Descriptor::decode(&mut d)?),
                (1, 2) => {
                    headers += 1;
                    let bytes = d.bytes()?;
                    if headers > MAX_CONTROL_HEADERS || bytes.len() > MAX_HEADER_BYTES {
                        return Err(Error::SizeLimitExceeded("control proof headers"));
                    }
                    ControlToken::Leaf(Box::new(Entry::from_wire(bytes)?))
                }
                (2, 1) => ControlToken::Branch,
                _ => return Err(Error::MalformedBundle("control proof token")),
            };
            tokens.push(token);
        }
        d.finish()?;
        let proof = Self {
            head_id,
            lo,
            hi,
            tokens,
        };
        proof.validate()?;
        Ok(proof)
    }
}

/// Counted coverage and authenticated headers only. Required bodies, contexts, parent receipts
/// and authority evaluation remain separate, durable obligations before control-ready publication.
#[derive(Clone, Debug)]
pub struct VerifiedControlRange {
    /// Domain-separated identity of the exact signed target head body.
    head_id: Digest32,
    /// Exact room, scope and author binding.
    binding: TreeBinding,
    /// Complete target descriptor, including counts and context hash.
    root: Descriptor,
    /// First covered one-based position, inclusive.
    lo: u64,
    /// Last covered one-based position, inclusive.
    hi: u64,
    /// Authenticated control headers; bodies and authority remain separate obligations.
    headers: Vec<VerifiedHeader>,
}
impl VerifiedControlRange {
    /// Exact authenticated target head identity.
    pub fn head_id(&self) -> Digest32 {
        self.head_id
    }
    /// Exact room, scope and author of the verified statement.
    pub fn binding(&self) -> TreeBinding {
        self.binding
    }
    /// Authenticated target descriptor.
    pub fn root(&self) -> Descriptor {
        self.root
    }
    /// First verified interval position, inclusive.
    pub fn lo(&self) -> u64 {
        self.lo
    }
    /// Last verified interval position, inclusive.
    pub fn hi(&self) -> u64 {
        self.hi
    }
    /// Authenticated counted headers; control authority remains unresolved.
    pub fn headers(&self) -> &[VerifiedHeader] {
        &self.headers
    }
}

#[derive(Clone, Debug)]
enum RangeTask {
    Visit { start: u64, leaves: u64 },
    Join,
}
/// Bounded preorder reconstruction with signature and context work retained across slices.
#[derive(Clone, Debug)]
pub struct ControlRangeVerifier {
    head: VerifiedHead,
    proof: ControlRangeProof,
    tasks: Vec<RangeTask>,
    values: Vec<Descriptor>,
    next: usize,
    signed_leaf: Option<usize>,
    headers: Vec<VerifiedHeader>,
    ranges: Vec<(u64, Descriptor)>,
}
impl ControlRangeVerifier {
    /// Exact immutable target of an authenticated local checkpoint, checked by its store slot.
    pub(crate) fn checkpoint_target(&self) -> (Digest32, TreeBinding, u64, u64) {
        let (from, through) = (self.proof.lo, self.proof.hi);
        (
            self.head.head().id(),
            self.head.head().binding,
            from,
            through,
        )
    }
    /// Bind this reconstruction cursor to its exact immutable inputs.
    pub fn new(head: VerifiedHead, proof: ControlRangeProof) -> Result<Self> {
        proof.validate()?;
        if proof.head_id != head.head().id() || proof.hi > head.head().root.leaves {
            return Err(Error::MalformedBundle("control proof head/range mismatch"));
        }
        let tasks = vec![RangeTask::Visit {
            start: 1,
            leaves: head.head().root.leaves,
        }];
        let mut ranges = Vec::with_capacity(PROOF_RANGE_SLOTS);
        let mut coordinates = vec![(1, head.head().root.leaves)];
        for token in &proof.tokens {
            let (start, leaves) = coordinates
                .pop()
                .ok_or(Error::MalformedBundle("control trace extra token"))?;
            match token {
                ControlToken::Collapse(descriptor) => {
                    if descriptor.leaves != leaves {
                        return Err(Error::MalformedBundle("control trace range length"));
                    }
                    retain_range(&mut ranges, start, *descriptor)?;
                }
                ControlToken::Leaf(_) => {}
                ControlToken::Branch => {
                    let left = split(leaves)?;
                    coordinates.push((start + left, leaves - left));
                    coordinates.push((start, left));
                    if coordinates.len() > MAX_TREE_DEPTH + 1 {
                        return Err(Error::SizeLimitExceeded("control trace depth"));
                    }
                }
            }
        }
        if !coordinates.is_empty() {
            return Err(Error::MalformedBundle("control trace missing token"));
        }
        Ok(Self {
            head,
            proof,
            tasks,
            values: Vec::new(),
            next: 0,
            signed_leaf: None,
            headers: Vec::new(),
            ranges,
        })
    }
    pub(crate) fn take_verified_ranges(&mut self) -> Result<Vec<(u64, Descriptor)>> {
        if !self.tasks.is_empty()
            || self.next != self.proof.tokens.len()
            || self.values.as_slice() != [self.head.head().root]
        {
            return Err(Error::MalformedBundle("incomplete control range trace"));
        }
        Ok(std::mem::take(&mut self.ranges))
    }
    /// Advance bounded work; persist generated context and cursor before another slice.
    pub fn advance(
        &mut self,
        key: &CompositePublicKey,
        source: &impl ContextSource,
        budget: &mut WorkBudget,
    ) -> Result<HistoryStep<VerifiedControlRange>> {
        let binding = self.head.head().binding;
        // Flat token transitions are bounded too; returning Yielded retains completed work.
        for _ in 0..MAX_TREE_DEPTH * 2 + 1 {
            let Some(task) = self.tasks.last().cloned() else {
                if self.next != self.proof.tokens.len()
                    || self.values.len() != 1
                    || self.values[0] != self.head.head().root
                {
                    return Err(Error::MalformedBundle(
                        "control proof reconstruction mismatch",
                    ));
                }
                return Ok(HistoryStep::Complete(VerifiedControlRange {
                    head_id: self.proof.head_id,
                    binding,
                    root: self.head.head().root,
                    lo: self.proof.lo,
                    hi: self.proof.hi,
                    headers: self.headers.clone(),
                }));
            };
            match task {
                RangeTask::Join => {
                    let n = self.values.len();
                    if n < 2 {
                        return Err(Error::MalformedBundle("control proof operand underflow"));
                    }
                    match join_descriptors(
                        binding,
                        self.values[n - 2],
                        self.values[n - 1],
                        source,
                        budget,
                    )? {
                        HistoryStep::Complete((descriptor, context)) => {
                            let start = self.values[..n - 2]
                                .iter()
                                .try_fold(1u64, |start, value| start.checked_add(value.leaves))
                                .ok_or(Error::MalformedBundle("control trace range overflow"))?;
                            retain_range(&mut self.ranges, start, descriptor)?;
                            self.values.truncate(n - 2);
                            self.values.push(descriptor);
                            self.tasks.pop();
                            return Ok(HistoryStep::Progress(context));
                        }
                        HistoryStep::MissingContext(hash) => {
                            return Ok(HistoryStep::MissingContext(hash))
                        }
                        HistoryStep::Yielded => return Ok(HistoryStep::Yielded),
                        HistoryStep::Progress(context) => {
                            return Ok(HistoryStep::Progress(context))
                        }
                    }
                }
                RangeTask::Visit { start, leaves } => {
                    let token = self
                        .proof
                        .tokens
                        .get(self.next)
                        .ok_or(Error::MalformedBundle("missing control proof token"))?;
                    let end = start
                        .checked_add(leaves)
                        .and_then(|n| n.checked_sub(1))
                        .ok_or(Error::MalformedBundle("control range overflow"))?;
                    let intersects = start <= self.proof.hi && end >= self.proof.lo;
                    match token {
                        ControlToken::Collapse(descriptor) => {
                            if descriptor.leaves != leaves
                                || (intersects && descriptor.controls != 0)
                            {
                                return Err(Error::MalformedBundle(
                                    "control proof hides control interval",
                                ));
                            }
                            self.values.push(*descriptor);
                            self.tasks.pop();
                            self.next += 1;
                        }
                        ControlToken::Branch => {
                            if !intersects {
                                return Err(Error::MalformedBundle(
                                    "expanded outside control interval",
                                ));
                            }
                            let left = split(leaves)?;
                            self.tasks.pop();
                            self.tasks.push(RangeTask::Join);
                            self.tasks.push(RangeTask::Visit {
                                start: start + left,
                                leaves: leaves - left,
                            });
                            self.tasks.push(RangeTask::Visit {
                                start,
                                leaves: left,
                            });
                            self.next += 1;
                            if self.tasks.len() > MAX_TREE_DEPTH * 2 + 1 {
                                return Err(Error::SizeLimitExceeded("control proof depth"));
                            }
                        }
                        ControlToken::Leaf(entry) => {
                            binding.matches_entry(entry)?;
                            if leaves != 1
                                || !intersects
                                || entry.skeleton.seq != start
                                || !entry
                                    .skeleton
                                    .v2
                                    .as_ref()
                                    .is_some_and(|v| v.kind.is_control())
                            {
                                return Err(Error::MalformedBundle("control leaf position/kind"));
                            }
                            if start == self.head.head().root.leaves
                                && entry.skeleton.epoch != self.head.head().tail_epoch
                            {
                                return Err(Error::MalformedBundle("control terminal epoch"));
                            }
                            if self.signed_leaf != Some(self.next) {
                                if !budget.take_signature() {
                                    return Ok(HistoryStep::Yielded);
                                }
                                entry.verify(key)?;
                                self.signed_leaf = Some(self.next);
                            }
                            match leaf_descriptor(binding, entry, source, budget)? {
                                HistoryStep::Complete((descriptor, context)) => {
                                    retain_range(&mut self.ranges, start, descriptor)?;
                                    self.values.push(descriptor);
                                    self.tasks.pop();
                                    self.headers.push(VerifiedHeader((**entry).clone()));
                                    self.next += 1;
                                    self.signed_leaf = None;
                                    return Ok(HistoryStep::Progress(context));
                                }
                                HistoryStep::MissingContext(hash) => {
                                    return Ok(HistoryStep::MissingContext(hash))
                                }
                                HistoryStep::Yielded => return Ok(HistoryStep::Yielded),
                                HistoryStep::Progress(context) => {
                                    return Ok(HistoryStep::Progress(context))
                                }
                            }
                        }
                    }
                }
            }
        }
        Ok(HistoryStep::Yielded)
    }
}

/// Derived parent evidence. Its two proofs MUST target the same authenticated head.
#[derive(Clone, Debug)]
pub struct ParentReceipt {
    /// Domain-separated identity of the exact signed target head body.
    pub head_id: Digest32,
    /// Body-absent signed parent whose identity must match the supplied verified header.
    pub parent: Entry,
    /// Exact parent-position inclusion under the receipt's target head.
    pub inclusion: InclusionProof,
    /// Exact earlier prefix descriptor, not just its size.
    pub prefix: Descriptor,
    /// Proof connecting the parent prefix descriptor to that same head.
    pub consistency: ConsistencyProof,
}
impl ParentReceipt {
    /// Decode one bounded canonical proof object and reject trailing bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        bounded_proof(bytes)?;
        let mut d = Decoder::new(bytes);
        arity(&mut d, 5, "parent receipt arity")?;
        let head_id = digest(&mut d)?;
        let wire = d.bytes()?;
        if wire.len() > MAX_HEADER_BYTES {
            return Err(Error::SizeLimitExceeded("parent header bytes"));
        }
        let parent = Entry::from_wire(wire)?;
        if parent.payload.is_some() {
            return Err(Error::MalformedBundle("parent receipt contains payload"));
        }
        let inclusion = InclusionProof::decode(&mut d)?;
        let prefix = Descriptor::decode(&mut d)?;
        let consistency = ConsistencyProof::decode(&mut d)?;
        d.finish()?;
        let receipt = Self {
            head_id,
            parent,
            inclusion,
            prefix,
            consistency,
        };
        receipt.validate()?;
        Ok(receipt)
    }
    fn validate(&self) -> Result<()> {
        self.inclusion.validate()?;
        self.consistency.validate()?;
        self.prefix.validate()?;
        let p = self.parent.skeleton.seq;
        if self.parent.skeleton.v2.is_none()
            || self.parent.payload.is_some()
            || self.parent.header_wire().len() > MAX_HEADER_BYTES
            || self.inclusion.position != p
            || self.prefix.leaves != p
            || self.consistency.from != p
            || self.consistency.to != self.inclusion.size
        {
            return Err(Error::MalformedBundle("parent receipt position binding"));
        }
        Ok(())
    }
    /// Encode one bounded canonical proof object.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut e = Encoder::new();
        e.array(5)
            .bytes(&self.head_id)
            .bytes(&self.parent.header_wire());
        self.inclusion.encode(&mut e);
        self.prefix.encode(&mut e);
        self.consistency.encode(&mut e);
        let bytes = e.finish();
        bounded_proof(&bytes)?;
        Ok(bytes)
    }
    /// The header must already be authenticated. Neither successful cursor resolves the required
    /// control range through p; that separate coverage remains the integration owner's obligation.
    pub fn verifiers(
        &self,
        head: VerifiedHead,
        parent: VerifiedHeader,
    ) -> Result<(InclusionVerifier, ConsistencyVerifier)> {
        self.validate()?;
        if head.head().id() != self.head_id
            || parent.entry().header_wire() != self.parent.header_wire()
        {
            return Err(Error::MalformedBundle(
                "parent receipt exact head/header mismatch",
            ));
        }
        Ok((
            InclusionVerifier::new(head.clone(), parent, self.inclusion.clone())?,
            ConsistencyVerifier::new(head, self.prefix, self.consistency.clone())?,
        ))
    }
}

/// Canonical descriptor positions needed to serve proofs from the existing disk index.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TreeRange {
    /// First one-based position in this canonical subtree.
    pub start: u64,
    /// Number of positions covered by this canonical subtree.
    pub leaves: u64,
}
/// Return canonical sibling ranges in bottom-up proof order for disk-backed serving.
pub fn inclusion_ranges(position: u64, size: u64) -> Result<Vec<TreeRange>> {
    if position == 0 || position > size || size > MAX_SEQ {
        return Err(Error::MalformedBundle("inclusion range bounds"));
    }
    let (mut start, mut leaves, mut index) = (1, size, position - 1);
    let mut ranges = Vec::new();
    while leaves > 1 {
        let left = split(leaves)?;
        if index < left {
            ranges.push(TreeRange {
                start: start + left,
                leaves: leaves - left,
            });
            leaves = left;
        } else {
            ranges.push(TreeRange {
                start,
                leaves: left,
            });
            start += left;
            leaves -= left;
            index -= left;
        }
    }
    ranges.reverse();
    Ok(ranges)
}
/// Return canonical prefix-consistency ranges in proof order for disk-backed serving.
pub fn consistency_ranges(from: u64, to: u64) -> Result<Vec<TreeRange>> {
    if from > to || to > MAX_SEQ {
        return Err(Error::MalformedBundle("consistency range bounds"));
    }
    if from == 0 || from == to {
        return Ok(Vec::new());
    }
    let (mut start, mut m, mut n, mut complete) = (1, from, to, true);
    let mut siblings = Vec::new();
    while m != n {
        let left = split(n)?;
        if m <= left {
            siblings.push(TreeRange {
                start: start + left,
                leaves: n - left,
            });
            n = left;
        } else {
            siblings.push(TreeRange {
                start,
                leaves: left,
            });
            start += left;
            m -= left;
            n -= left;
            complete = false;
        }
    }
    let mut ranges = Vec::new();
    if !complete {
        ranges.push(TreeRange { start, leaves: n });
    }
    siblings.reverse();
    ranges.extend(siblings);
    Ok(ranges)
}
fn decode_descriptors(d: &mut Decoder<'_>, maximum: usize) -> Result<Vec<Descriptor>> {
    let count = d.array()?;
    if count > maximum {
        return Err(Error::SizeLimitExceeded("proof descriptors"));
    }
    let mut values = Vec::with_capacity(count);
    for _ in 0..count {
        values.push(Descriptor::decode(d)?);
    }
    Ok(values)
}
fn bounded_proof(bytes: &[u8]) -> Result<()> {
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(Error::SizeLimitExceeded("history proof bytes"));
    }
    Ok(())
}

// These checkpoints are accepted only from the node's authenticated sealed local state. They are
// deliberately crate-private: a peer's proof bytes must take the signature-checking constructors.
const MAX_CHECKPOINT_BYTES: usize = MAX_FRAME_BYTES + 12 * MAX_HEADER_BYTES;

impl InclusionVerifier {
    pub(crate) fn checkpoint(&self) -> Result<Vec<u8>> {
        let mut e = Encoder::new();
        e.array(8)
            .uint(1)
            .bytes(&self.head.head().to_wire())
            .bytes(&self.header.entry().header_wire())
            .bytes(&self.proof.to_bytes()?)
            .uint(self.next as u64)
            .uint(self.index)
            .uint(self.last)
            .array(usize::from(self.current.is_some()));
        if let Some(descriptor) = self.current {
            descriptor.encode(&mut e);
        }
        checkpoint_bytes(e)
    }
    pub(crate) fn from_authenticated_checkpoint(bytes: &[u8]) -> Result<Self> {
        let mut d = checkpoint_decoder(bytes)?;
        arity(&mut d, 8, "inclusion checkpoint arity")?;
        if d.uint()? != 1 {
            return Err(Error::MalformedAtRest("inclusion checkpoint kind"));
        }
        let head = local_head(&mut d)?;
        let header = local_header(&mut d)?;
        let proof = InclusionProof::from_bytes(d.bytes()?)?;
        let mut verifier = Self::new(head, header, proof)?;
        verifier.next = bounded_usize(
            d.uint()?,
            verifier.proof.siblings.len(),
            "inclusion checkpoint offset",
        )?;
        verifier.index = d.uint()?;
        verifier.last = d.uint()?;
        verifier.current = match d.array()? {
            0 => None,
            1 => Some(Descriptor::decode(&mut d)?),
            _ => return Err(Error::MalformedAtRest("inclusion checkpoint accumulator")),
        };
        if verifier.index > verifier.proof.position - 1
            || verifier.last > verifier.proof.size - 1
            || (verifier.current.is_none() && verifier.next != 0)
        {
            return Err(Error::MalformedAtRest("inclusion checkpoint traversal"));
        }
        d.finish()?;
        Ok(verifier)
    }
}
impl ConsistencyVerifier {
    pub(crate) fn checkpoint(&self) -> Result<Vec<u8>> {
        let mut e = Encoder::new();
        e.array(10).uint(2).bytes(&self.head.head().to_wire());
        self.prefix.encode(&mut e);
        e.bytes(&self.proof.to_bytes()?)
            .uint(self.next as u64)
            .uint(self.index)
            .uint(self.last);
        self.old_acc.encode(&mut e);
        self.new_acc.encode(&mut e);
        e.uint(u64::from(self.old_joined));
        checkpoint_bytes(e)
    }
    pub(crate) fn from_authenticated_checkpoint(bytes: &[u8]) -> Result<Self> {
        let mut d = checkpoint_decoder(bytes)?;
        arity(&mut d, 10, "consistency checkpoint arity")?;
        if d.uint()? != 2 {
            return Err(Error::MalformedAtRest("consistency checkpoint kind"));
        }
        let head = local_head(&mut d)?;
        let prefix = Descriptor::decode(&mut d)?;
        let proof = ConsistencyProof::from_bytes(d.bytes()?)?;
        let mut verifier = Self::new(head, prefix, proof)?;
        verifier.next = bounded_usize(
            d.uint()?,
            verifier.proof.nodes.len(),
            "consistency checkpoint offset",
        )?;
        verifier.index = d.uint()?;
        verifier.last = d.uint()?;
        verifier.old_acc = Descriptor::decode(&mut d)?;
        verifier.new_acc = Descriptor::decode(&mut d)?;
        verifier.old_joined = match d.uint()? {
            0 => false,
            1 => true,
            _ => return Err(Error::MalformedAtRest("consistency checkpoint phase")),
        };
        if verifier.index > verifier.proof.from.saturating_sub(1)
            || verifier.last > verifier.proof.to.saturating_sub(1)
        {
            return Err(Error::MalformedAtRest("consistency checkpoint traversal"));
        }
        d.finish()?;
        Ok(verifier)
    }
}
impl ControlRangeVerifier {
    pub(crate) fn checkpoint(&self) -> Result<Vec<u8>> {
        let mut e = Encoder::new();
        e.array(8)
            .uint(3)
            .bytes(&self.head.head().to_wire())
            .bytes(&self.proof.to_bytes()?)
            .uint(self.next as u64)
            .array(usize::from(self.signed_leaf.is_some()));
        if let Some(index) = self.signed_leaf {
            e.uint(index as u64);
        }
        e.array(self.tasks.len());
        for task in &self.tasks {
            match task {
                RangeTask::Visit { start, leaves } => {
                    e.array(3).uint(0).uint(*start).uint(*leaves);
                }
                RangeTask::Join => {
                    e.array(1).uint(1);
                }
            }
        }
        e.array(self.values.len());
        for value in &self.values {
            value.encode(&mut e);
        }
        e.array(self.headers.len());
        for header in &self.headers {
            e.bytes(&header.entry().header_wire());
        }
        checkpoint_bytes(e)
    }
    pub(crate) fn from_authenticated_checkpoint(bytes: &[u8]) -> Result<Self> {
        let mut d = checkpoint_decoder(bytes)?;
        arity(&mut d, 8, "control checkpoint arity")?;
        if d.uint()? != 3 {
            return Err(Error::MalformedAtRest("control checkpoint kind"));
        }
        let head = local_head(&mut d)?;
        let proof = ControlRangeProof::from_bytes(d.bytes()?)?;
        let mut verifier = Self::new(head, proof)?;
        verifier.next = bounded_usize(
            d.uint()?,
            verifier.proof.tokens.len(),
            "control checkpoint offset",
        )?;
        verifier.signed_leaf = match d.array()? {
            0 => None,
            1 => {
                let index = bounded_usize(
                    d.uint()?,
                    verifier.proof.tokens.len(),
                    "signed checkpoint leaf",
                )?;
                if index != verifier.next
                    || !matches!(
                        verifier.proof.tokens.get(index),
                        Some(ControlToken::Leaf(_))
                    )
                {
                    return Err(Error::MalformedAtRest("signed checkpoint token"));
                }
                Some(index)
            }
            _ => return Err(Error::MalformedAtRest("signed checkpoint option")),
        };
        let tasks = d.array()?;
        if tasks > MAX_TREE_DEPTH * 2 + 1 {
            return Err(Error::SizeLimitExceeded("checkpoint task stack"));
        }
        verifier.tasks.clear();
        for _ in 0..tasks {
            let arity = d.array()?;
            let task = match (d.uint()?, arity) {
                (0, 3) => {
                    let start = d.uint()?;
                    let leaves = d.uint()?;
                    if start == 0
                        || leaves == 0
                        || start
                            .checked_add(leaves - 1)
                            .is_none_or(|end| end > verifier.head.head().root.leaves)
                    {
                        return Err(Error::MalformedAtRest("checkpoint task range"));
                    }
                    RangeTask::Visit { start, leaves }
                }
                (1, 1) => RangeTask::Join,
                _ => return Err(Error::MalformedAtRest("checkpoint task kind")),
            };
            verifier.tasks.push(task);
        }
        verifier.values = decode_descriptors(&mut d, MAX_TREE_DEPTH + 1)?;
        let count = d.array()?;
        if count > MAX_CONTROL_HEADERS {
            return Err(Error::SizeLimitExceeded("checkpoint headers"));
        }
        for _ in 0..count {
            verifier.headers.push(local_header(&mut d)?);
        }
        d.finish()?;
        Ok(verifier)
    }
}
fn checkpoint_bytes(e: Encoder) -> Result<Vec<u8>> {
    let bytes = e.finish();
    if bytes.len() > MAX_CHECKPOINT_BYTES {
        return Err(Error::SizeLimitExceeded("history checkpoint bytes"));
    }
    Ok(bytes)
}
fn checkpoint_decoder(bytes: &[u8]) -> Result<Decoder<'_>> {
    if bytes.len() > MAX_CHECKPOINT_BYTES {
        return Err(Error::SizeLimitExceeded("history checkpoint bytes"));
    }
    Ok(Decoder::new(bytes))
}
fn local_head(d: &mut Decoder<'_>) -> Result<VerifiedHead> {
    Ok(VerifiedHead(SignedHead::from_wire(d.bytes()?)?))
}
fn local_header(d: &mut Decoder<'_>) -> Result<VerifiedHeader> {
    let bytes = d.bytes()?;
    if bytes.len() > MAX_HEADER_BYTES {
        return Err(Error::SizeLimitExceeded("checkpoint header bytes"));
    }
    let entry = Entry::from_wire(bytes)?;
    if entry.payload.is_some() || entry.skeleton.v2.is_none() || !entry.is_signed() {
        return Err(Error::MalformedAtRest("checkpoint signed header"));
    }
    Ok(VerifiedHeader(entry))
}
fn bounded_usize(value: u64, maximum: usize, message: &'static str) -> Result<usize> {
    let value = usize::try_from(value).map_err(|_| Error::SizeLimitExceeded(message))?;
    if value > maximum {
        return Err(Error::SizeLimitExceeded(message));
    }
    Ok(value)
}
