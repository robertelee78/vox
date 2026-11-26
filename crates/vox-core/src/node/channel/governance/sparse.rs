//! Evidence-complete sparse input to the existing governance fold. None of the types in
//! this module grant authority or claim that a control's effect has been applied.

use super::super::entry_store;
use crate::error::{Error, Result};
use crate::hash::{sha256, Digest32};
use crate::log::entry::Entry;
use crate::log::history::{
    ConsistentPrefix, ControlContext, Descriptor, EntryReference, IncludedHeader, SignedEntryKind,
    TreeBinding, WorkBudget,
};

/// The `seen` parents whose exact receipts, control closure and frontier domination an
/// entry's admission requires (ADR-053 M0). An ordinary signed-format Content entry names
/// other authors' tips only as nonblocking references: one this node already published can
/// lift where the entry is first displayed, but no receipt is fetched or awaited for them,
/// and no authority, membership, cut, key, private-access or required-ancestor decision
/// may read them as evidence. Every control kind keeps a checked parent for each reference.
/// (Typed Content binds the room's own channel, `TypedSparseBody::verify`, so a legacy Drive
/// carrier never takes this path.)
pub(crate) fn checked_seen(v2: &crate::log::history::EntryV2) -> &[EntryReference] {
    if v2.kind == SignedEntryKind::Content {
        &[]
    } else {
        &v2.seen
    }
}

/// Exact authenticated input with complete signed causal evidence: its own prefix, every
/// coordinate of its signed context and, for a control, every `seen` parent. An ordinary
/// Content entry's `seen` references are ordering hints only (ADR-053 M0) and are not part of
/// this claim. A control may enter the existing evaluator through this token; its authority
/// and effect are still unresolved.
pub(crate) struct ValidatedSparseEntry {
    included: IncludedHeader,
    pre_context: ControlContext,
    payload_state: SparsePayloadState,
}
impl ValidatedSparseEntry {
    pub(crate) fn included(&self) -> &IncludedHeader {
        &self.included
    }
    pub(crate) fn pre_context(&self) -> &ControlContext {
        &self.pre_context
    }
    pub(crate) fn head_id(&self) -> Digest32 {
        self.included.head_id()
    }
    pub(crate) fn binding(&self) -> TreeBinding {
        self.included.binding()
    }
    pub(crate) fn entry_hash(&self) -> Digest32 {
        self.included.header().entry().entry_hash()
    }
    pub(crate) fn payload_state(&self) -> SparsePayloadState {
        self.payload_state
    }
}

/// An exact parent and its authenticated prefix, both proven under the same signed head.
/// Control-source completion is checked separately against the durable exact-head receipt.
pub(crate) struct VerifiedParentPrefix {
    included: IncludedHeader,
    prefix: ConsistentPrefix,
}
impl VerifiedParentPrefix {
    pub(crate) fn included(&self) -> &IncludedHeader {
        &self.included
    }
    pub(crate) fn prefix(&self) -> &ConsistentPrefix {
        &self.prefix
    }
    pub(crate) fn checkpoint(&self) -> Result<Vec<u8>> {
        let mut e = crate::cbor::Encoder::new();
        e.array(3)
            .uint(1)
            .bytes(&self.included.local_receipt()?)
            .bytes(&self.prefix.local_receipt()?);
        let bytes = e.finish();
        if bytes.len() > 32 * 1024 {
            return Err(Error::SizeLimitExceeded("parent receipt"));
        }
        Ok(bytes)
    }
    /// Authenticated sealed-local state only; peer bytes must use the normal verifiers.
    pub(crate) fn from_authenticated_checkpoint(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > 32 * 1024 {
            return Err(Error::SizeLimitExceeded("parent receipt"));
        }
        let mut d = crate::cbor::Decoder::new(bytes);
        if d.array()? != 3 || d.uint()? != 1 {
            return Err(Error::MalformedAtRest("parent receipt format"));
        }
        let included = IncludedHeader::from_authenticated_receipt(d.bytes()?)?;
        let prefix = ConsistentPrefix::from_authenticated_receipt(d.bytes()?)?;
        d.finish()?;
        Self::new(included, prefix)
    }

    pub(crate) fn new(included: IncludedHeader, prefix: ConsistentPrefix) -> Result<Self> {
        if included.head_id() != prefix.head_id()
            || included.binding() != prefix.binding()
            || included.root() != prefix.root()
            || included.header().entry().skeleton.seq != prefix.prefix().leaves
        {
            return Err(Error::MalformedBundle(
                "parent receipt proof bindings differ",
            ));
        }
        Ok(Self { included, prefix })
    }
}

/// One parent of an entry under validation, as the validator needs it: the parent's header at
/// its author and position, a committed head of its author covering it, and the accepted
/// chain's prefix [1, seq] that ends with it (its frontier is the parent's control context).
/// Located by author and position (`admission::parent_evidence`), never by the head an answer
/// named.
// Both variants are per-parent of every entry under validation, kept inline in its parents
// list; boxing either would allocate per parent.
#[allow(clippy::large_enum_variant)]
pub(crate) enum SparseParent {
    /// Proven by one answer: inclusion and own prefix against one root.
    Receipt(VerifiedParentPrefix),
    /// Published here: its own admission validated it under a committed head of its author,
    /// which stays committed; `head` is the author's committed head when it was looked up, and
    /// `prefix` the range [1, seq] that admission required before validating it.
    Published {
        head: Digest32,
        binding: TreeBinding,
        header: Entry,
        prefix: Descriptor,
    },
}
impl SparseParent {
    pub(crate) fn head_id(&self) -> Digest32 {
        match self {
            Self::Receipt(receipt) => receipt.included.head_id(),
            Self::Published { head, .. } => *head,
        }
    }
    fn binding(&self) -> TreeBinding {
        match self {
            Self::Receipt(receipt) => receipt.included.binding(),
            Self::Published { binding, .. } => *binding,
        }
    }
    pub(crate) fn header(&self) -> &Entry {
        match self {
            Self::Receipt(receipt) => receipt.included.header().entry(),
            Self::Published { header, .. } => header,
        }
    }
    pub(crate) fn prefix(&self) -> Descriptor {
        match self {
            Self::Receipt(receipt) => receipt.prefix.prefix(),
            Self::Published { prefix, .. } => *prefix,
        }
    }
    /// A published parent's positional prefix [1, seq] must end with this exact parent: its
    /// frontier must be the whole context the parent leaves, derived from its own signed header
    /// by the leaf rule (`leaf_descriptor`): its pre-context for a content entry, its pre-context
    /// joined with its own coordinate for a control. A receipt's two proofs bind the two under
    /// one root already. Checked where admission takes the parent, before anything follows the
    /// frontier (`admission::start_entry`, `preflight`). A prefix of another history (an older
    /// program kept a forking author's other branch in that slot; the accepted one cannot be
    /// kept beside it) is a fault of this store, never evidence and never a need.
    pub(crate) fn check_published(&self, input: &entry_store::Read<'_>) -> Result<()> {
        let Self::Published {
            binding,
            header,
            prefix,
            ..
        } = self
        else {
            return Ok(());
        };
        let other =
            || Error::MalformedAtRest("published parent's prefix range is another history's");
        let v2 = header.skeleton.v2.as_ref().ok_or_else(other)?;
        let leaves = if v2.kind.is_control() {
            let pre = input
                .history_context(&v2.pre_context)?
                .ok_or(Error::MalformedAtRest(
                    "published parent pre-context missing",
                ))?;
            pre.join(&ControlContext {
                room: binding.room,
                scope: binding.scope,
                coordinates: vec![EntryReference {
                    author: header.skeleton.author_id,
                    seq: header.skeleton.seq,
                    hash: header.entry_hash(),
                }],
            })
            .map_err(|_| other())?
            .hash()
        } else {
            v2.pre_context
        };
        if leaves != prefix.frontier {
            return Err(other());
        }
        Ok(())
    }
    /// A receipt keeps its format-1 bytes (`VerifiedParentPrefix::checkpoint`); a published
    /// parent is format 2.
    fn checkpoint(&self) -> Result<Vec<u8>> {
        let (head, binding, header, prefix) = match self {
            Self::Receipt(receipt) => return receipt.checkpoint(),
            Self::Published {
                head,
                binding,
                header,
                prefix,
            } => (head, binding, header, prefix),
        };
        let mut e = crate::cbor::Encoder::new();
        e.array(5).uint(2).bytes(head);
        binding.encode(&mut e);
        e.bytes(&header.header_wire());
        prefix.encode(&mut e);
        let bytes = e.finish();
        if bytes.len() > 32 * 1024 {
            return Err(Error::SizeLimitExceeded("parent receipt"));
        }
        Ok(bytes)
    }
    fn from_authenticated_checkpoint(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > 32 * 1024 {
            return Err(Error::SizeLimitExceeded("parent receipt"));
        }
        let mut d = crate::cbor::Decoder::new(bytes);
        if (d.array()?, d.uint()?) != (5, 2) {
            return VerifiedParentPrefix::from_authenticated_checkpoint(bytes).map(Self::Receipt);
        }
        let head = d
            .bytes()?
            .try_into()
            .map_err(|_| Error::MalformedAtRest("published parent head"))?;
        let binding = TreeBinding::decode(&mut d)?;
        let header = Entry::from_wire(d.bytes()?)?;
        let prefix = Descriptor::decode(&mut d)?;
        d.finish()?;
        if header.payload.is_some() || prefix.leaves != header.skeleton.seq {
            return Err(Error::MalformedAtRest("published parent checkpoint"));
        }
        Ok(Self::Published {
            head,
            binding,
            header,
            prefix,
        })
    }
}

/// Typed payload shape/binding only. In particular this is not the governance verdict or a
/// recipient-side key application result. Private ciphertext is never decrypted here.
pub(crate) struct TypedSparseBody {
    hash: Digest32,
    state: SparsePayloadState,
}

/// Holding an addressed ciphertext is not applying its key. Key installation and private
/// access always retain their existing recipient, namespace, generation and trust checks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SparsePayloadState {
    Held,
    ContentAbsent,
    KeyPackagePending { recipient: Digest32 },
}

pub(crate) enum PayloadValidation {
    Complete(TypedSparseBody),
    BodyRequired,
    Yielded,
}

// A bounded transient result covered by the existing verifier working reservation.
#[allow(clippy::large_enum_variant)]
pub(crate) enum SparseValidationStep {
    Complete(ValidatedSparseEntry),
    Progress,
    MissingContext(Digest32),
    MissingControl(EntryReference),
    ControlPrefixPending { head: Digest32, through: u64 },
    Yielded,
}

/// At most seventeen parent receipts are resident. Contexts are loaded for one bounded slice
/// and dropped before returning; only the completed token temporarily owns the signed map.
pub(crate) struct SparseValidation {
    included: IncludedHeader,
    parents: Vec<SparseParent>,
    parent: usize,
    parent_coordinate: usize,
    coordinate: usize,
    finished: bool,
    payload_state: SparsePayloadState,
}

impl TypedSparseBody {
    pub(crate) fn entry_hash(&self) -> Digest32 {
        self.hash
    }
    pub(crate) fn state(&self) -> SparsePayloadState {
        self.state
    }

    /// The caller already owns the large-record envelope for a present payload. Borrow the
    /// content ciphertext rather than making another maximum-sized allocation just to type it.
    pub(crate) fn verify(
        entry: &Entry,
        key: &crate::identity::composite::CompositePublicKey,
        budget: &mut WorkBudget,
    ) -> Result<PayloadValidation> {
        use crate::governance::entry::GovEntry;
        use SignedEntryKind::*;
        entry.skeleton.validate_v2()?;
        let v2 = entry
            .skeleton
            .v2
            .as_ref()
            .ok_or(Error::MalformedBundle("v2 body required"))?;
        let hash = entry.entry_hash();
        let Some(payload) = entry.payload.as_deref() else {
            let state = match v2.kind {
                Content => SparsePayloadState::ContentAbsent,
                KeyPackage => SparsePayloadState::KeyPackagePending {
                    recipient: v2
                        .recipient
                        .ok_or(Error::MalformedBundle("key recipient missing"))?,
                },
                ContextUpdate | Termination => SparsePayloadState::Held,
                _ => return Ok(PayloadValidation::BodyRequired),
            };
            return Ok(PayloadValidation::Complete(Self { hash, state }));
        };
        if payload.len() as u64 != entry.skeleton.payload_len
            || sha256(payload) != entry.skeleton.payload_hash
        {
            return Err(Error::MalformedBundle(
                "typed payload differs from signed commitment",
            ));
        }
        match v2.kind {
            Governance | StepPolicy => {
                if !budget.take_signature() {
                    return Ok(PayloadValidation::Yielded);
                }
                let body = GovEntry::body_bound_to(entry)?;
                body.verify(key)?;
            }
            Content => {
                use crate::cbor::Decoder;
                use crate::group::message::MessageHeader;
                use crate::group::wire::GROUP_MSG_SIGN_DOMAIN;
                let bytes = payload
                    .strip_prefix(GROUP_MSG_SIGN_DOMAIN.as_bytes())
                    .ok_or(Error::MalformedBundle("ordinary content carrier"))?;
                let mut decoder = Decoder::new(bytes);
                if decoder.array()? != 3 {
                    return Err(Error::MalformedBundle("ordinary content arity"));
                }
                let header = MessageHeader::from_canonical_body(decoder.bytes()?)?;
                if header.channel_id != entry.skeleton.channel_id
                    || header.epoch != entry.skeleton.epoch
                    || header.author_id != entry.skeleton.author_id
                {
                    return Err(Error::MalformedBundle("ordinary content header binding"));
                }
                let _ciphertext = decoder.bytes()?;
                let signature: &[u8; crate::hash::COMPOSITE_SIG_LEN] = decoder
                    .bytes()?
                    .try_into()
                    .map_err(|_| Error::MalformedBundle("ordinary content signature length"))?;
                crate::identity::composite::CompositeSignature::from_bytes(signature)?;
                decoder.finish()?;
            }
            Checkpoint => {
                let checkpoint = crate::log::checkpoint::Checkpoint::from_payload(payload)?.ok_or(
                    Error::MalformedBundle("checkpoint signed kind differs from body"),
                )?;
                if checkpoint.seq >= entry.skeleton.seq {
                    return Err(Error::MalformedBundle("checkpoint names present or future"));
                }
            }
            SessionFloor => {
                let floor = super::super::session_floor::Floor::read(payload).ok_or(
                    Error::MalformedBundle("floor signed kind differs from body"),
                )?;
                if floor.room != entry.skeleton.channel_id
                    || floor.author != entry.skeleton.author_id
                    || floor.epoch != entry.skeleton.epoch
                {
                    return Err(Error::MalformedBundle(
                        "floor signed binding differs from body",
                    ));
                }
            }
            PrivateSupport => {
                if payload
                    != super::super::private_session::support_body(
                        &entry.skeleton.channel_id,
                        &entry.skeleton.author_id,
                    )
                {
                    return Err(Error::MalformedBundle(
                        "support signed binding differs from body",
                    ));
                }
            }
            KeyPackage => {
                let package = crate::node::keypackage::KeyPackage::from_wire(payload)?;
                if Some(package.recipient) != v2.recipient {
                    return Err(Error::MalformedBundle(
                        "key recipient differs from signed header",
                    ));
                }
            }
            ContextUpdate | Termination => {
                if !payload.is_empty() {
                    return Err(Error::MalformedBundle("empty control has body"));
                }
            }
        }
        Ok(PayloadValidation::Complete(Self {
            hash,
            state: SparsePayloadState::Held,
        }))
    }
}

impl SparseValidation {
    pub(crate) fn checkpoint_target(&self) -> (Digest32, TreeBinding, u64, u64) {
        let seq = self.included.header().entry().skeleton.seq;
        (self.included.head_id(), self.included.binding(), seq, seq)
    }
    pub(crate) fn checkpoint(&self) -> Result<Vec<u8>> {
        let mut e = crate::cbor::Encoder::new();
        e.array(8)
            .uint(1)
            .bytes(&self.included.local_receipt()?)
            .array(self.parents.len());
        for parent in &self.parents {
            e.bytes(&parent.checkpoint()?);
        }
        e.uint(self.parent as u64)
            .uint(self.parent_coordinate as u64)
            .uint(self.coordinate as u64)
            .uint(u64::from(self.finished));
        match self.payload_state {
            SparsePayloadState::Held => {
                e.array(1).uint(0);
            }
            SparsePayloadState::ContentAbsent => {
                e.array(1).uint(1);
            }
            SparsePayloadState::KeyPackagePending { recipient } => {
                e.array(2).uint(2).bytes(&recipient);
            }
        }
        let bytes = e.finish();
        if bytes.len() > 352 * 1024 {
            return Err(Error::SizeLimitExceeded("sparse validation checkpoint"));
        }
        Ok(bytes)
    }
    /// Restore only an authenticated local operation; all source/authority facts are still
    /// rechecked by advance. Peer input has no route to this decoder.
    pub(crate) fn from_authenticated_checkpoint(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > 352 * 1024 {
            return Err(Error::SizeLimitExceeded("sparse validation checkpoint"));
        }
        let mut d = crate::cbor::Decoder::new(bytes);
        if d.array()? != 8 || d.uint()? != 1 {
            return Err(Error::MalformedAtRest("sparse validation checkpoint"));
        }
        let included = IncludedHeader::from_authenticated_receipt(d.bytes()?)?;
        let count = d.array()?;
        if count > 17 {
            return Err(Error::MalformedAtRest("sparse checkpoint parent count"));
        }
        let mut parents = Vec::with_capacity(count);
        for _ in 0..count {
            parents.push(SparseParent::from_authenticated_checkpoint(d.bytes()?)?);
        }
        let parent = usize::try_from(d.uint()?)
            .map_err(|_| Error::MalformedAtRest("sparse checkpoint offset"))?;
        let parent_coordinate = usize::try_from(d.uint()?)
            .map_err(|_| Error::MalformedAtRest("sparse checkpoint offset"))?;
        let coordinate = usize::try_from(d.uint()?)
            .map_err(|_| Error::MalformedAtRest("sparse checkpoint offset"))?;
        let finished = match d.uint()? {
            0 => false,
            1 => true,
            _ => return Err(Error::MalformedAtRest("sparse checkpoint finished")),
        };
        let shape = (d.array()?, d.uint()?);
        let state = match shape {
            (1, 0) => SparsePayloadState::Held,
            (1, 1) => SparsePayloadState::ContentAbsent,
            (2, 2) => SparsePayloadState::KeyPackagePending {
                recipient: d
                    .bytes()?
                    .try_into()
                    .map_err(|_| Error::MalformedAtRest("sparse checkpoint recipient"))?,
            },
            _ => return Err(Error::MalformedAtRest("sparse checkpoint body state")),
        };
        d.finish()?;
        if parent > count
            || parent_coordinate > crate::log::history::MAX_CONTEXT_AUTHORS
            || coordinate > crate::log::history::MAX_CONTEXT_AUTHORS
            || (parent == count && parent_coordinate != 0)
        {
            return Err(Error::MalformedAtRest("sparse checkpoint cursor bounds"));
        }
        let header = included.header().entry();
        let v2 = header
            .skeleton
            .v2
            .as_ref()
            .ok_or(Error::MalformedAtRest("sparse checkpoint header"))?;
        if matches!(state, SparsePayloadState::ContentAbsent) && v2.kind != SignedEntryKind::Content
            || matches!(state, SparsePayloadState::KeyPackagePending { recipient } if v2.kind != SignedEntryKind::KeyPackage || v2.recipient != Some(recipient))
        {
            return Err(Error::MalformedAtRest("sparse checkpoint body binding"));
        }
        let body = TypedSparseBody {
            hash: header.entry_hash(),
            state,
        };
        // A format-1 Content cursor captured before ADR-053 M0 also carries a receipt for
        // each `seen` hint. Keep its exact own-parent receipt and its position, and drop
        // only the hint receipts: a cursor already past the own parent restarts at the
        // context-coordinate phase, whose own cursor is unchanged.
        let (mut parents, mut parent, mut parent_coordinate) = (parents, parent, parent_coordinate);
        let own = usize::from(header.skeleton.seq > 1);
        if v2.kind == SignedEntryKind::Content && parents.len() == own + v2.seen.len() {
            parents.truncate(own);
            if parent > own || (parent == own && parent_coordinate != 0) {
                parent = own;
                parent_coordinate = 0;
            }
        }
        let mut cursor = Self::new(included, body, parents)?;
        cursor.parent = parent;
        cursor.parent_coordinate = parent_coordinate;
        cursor.coordinate = coordinate;
        cursor.finished = finished;
        Ok(cursor)
    }
    pub(crate) fn new(
        included: IncludedHeader,
        body: TypedSparseBody,
        parents: Vec<SparseParent>,
    ) -> Result<Self> {
        let entry = included.header().entry();
        let v2 = entry
            .skeleton
            .v2
            .as_ref()
            .ok_or(Error::MalformedBundle("sparse entry lacks v2 header"))?;
        let own = usize::from(entry.skeleton.seq > 1);
        let seen = checked_seen(v2);
        if body.hash != entry.entry_hash()
            || parents.len() != own + seen.len()
            || parents.len() > 17
        {
            return Err(Error::MalformedBundle(
                "sparse entry body or parent count differs",
            ));
        }
        for (at, parent) in parents.iter().enumerate() {
            let expected = if own == 1 && at == 0 {
                EntryReference {
                    author: entry.skeleton.author_id,
                    seq: entry.skeleton.seq - 1,
                    hash: entry.skeleton.prev_hash,
                }
            } else {
                seen[at - own].clone()
            };
            let header = parent.header();
            if header.skeleton.channel_id != entry.skeleton.channel_id
                || parent.binding().scope != v2.scope
                || header.skeleton.author_id != expected.author
                || header.skeleton.seq != expected.seq
                || header.entry_hash() != expected.hash
                || (own == 1 && at == 0 && header.skeleton.end_of_feed)
            {
                return Err(Error::MalformedBundle(
                    "sparse parent receipt differs from signed reference",
                ));
            }
        }
        Ok(Self {
            included,
            parents,
            parent: 0,
            parent_coordinate: 0,
            coordinate: 0,
            finished: false,
            payload_state: body.state,
        })
    }

    /// No network operation or await occurs under this snapshot. The caller persists/reloads
    /// proof inputs by exact IDs and reserves the common 4-MiB verifier envelope before entry.
    pub(crate) fn advance(
        &mut self,
        input: &entry_store::Read<'_>,
        budget: &mut WorkBudget,
    ) -> Result<SparseValidationStep> {
        if self.finished {
            return Err(Error::MalformedAtRest(
                "sparse validation already completed",
            ));
        }
        if !budget.take_context_load() {
            return Ok(SparseValidationStep::Yielded);
        }
        let entry = self.included.header().entry();
        let v2 = entry
            .skeleton
            .v2
            .as_ref()
            .ok_or(Error::MalformedBundle("sparse v2 binding"))?;
        let Some(pre) = input.history_context(&v2.pre_context)? else {
            return Ok(SparseValidationStep::MissingContext(v2.pre_context));
        };
        if pre.room != self.included.binding().room
            || pre.scope != self.included.binding().scope
            || pre.hash() != v2.pre_context
            || pre.coordinates.iter().any(|coordinate| {
                coordinate.author == entry.skeleton.author_id
                    && coordinate.seq >= entry.skeleton.seq
            })
        {
            return Err(Error::MalformedBundle("sparse signed context binding"));
        }
        if self.coordinate > pre.coordinates.len() {
            return Err(Error::MalformedAtRest(
                "sparse checkpoint coordinate exceeds context",
            ));
        }
        if !input.history_head_committed(&self.included.head_id(), self.included.binding())? {
            return Err(Error::MalformedBundle(
                "sparse head has no accepted consistency",
            ));
        }
        if self.parent < self.parents.len() {
            let parent = &self.parents[self.parent];
            if !input.history_head_committed(&parent.head_id(), parent.binding())? {
                return Err(Error::MalformedBundle(
                    "parent head has no accepted consistency",
                ));
            }
            let through = parent.prefix().leaves;
            // ADR-053 MP-10: the author-local termination evidence. The own parent's prefix
            // is this author's own signed head and positions; every control it commits,
            // a Termination among them, must be a held source before a later position is
            // usable, so a withheld termination keeps this entry pending, never accepted.
            let own_parent = self.parent == 0 && entry.skeleton.seq > 1;
            if !input.control_sources_complete(&parent.head_id(), through)? {
                return Ok(SparseValidationStep::ControlPrefixPending {
                    head: parent.head_id(),
                    through,
                });
            }
            // A termination in that prefix is now recorded: a later position is the
            // author's fault, refused here rather than at publication.
            if own_parent
                && input
                    .history_termination(&entry.skeleton.author_id)?
                    .is_some_and(|end| entry.skeleton.seq > end)
            {
                return Err(Error::MalformedBundle(
                    "sparse entry follows its author's termination",
                ));
            }
            if !budget.take_context_load() {
                return Ok(SparseValidationStep::Yielded);
            }
            // The same whole-context check admission made before preflight (`check_published`),
            // again here, where the parent's context is consumed for authority.
            parent.check_published(input)?;
            let hash = parent.prefix().frontier;
            let Some(frontier) = input.history_context(&hash)? else {
                return Ok(SparseValidationStep::MissingContext(hash));
            };
            if self.parent_coordinate > frontier.coordinates.len() {
                return Err(Error::MalformedAtRest(
                    "sparse checkpoint coordinate exceeds parent",
                ));
            }
            if frontier.room != pre.room || frontier.scope != pre.scope {
                return Err(Error::MalformedBundle(
                    "parent frontier room or scope differs",
                ));
            }
            if self.parent == 0
                && entry.skeleton.seq > 1
                && v2.kind == SignedEntryKind::Content
                && pre != frontier
            {
                return Err(Error::MalformedBundle(
                    "content changes control context without a control",
                ));
            }
            let stop = self
                .parent_coordinate
                .saturating_add(16)
                .min(frontier.coordinates.len());
            while self.parent_coordinate < stop {
                let earlier = &frontier.coordinates[self.parent_coordinate];
                let Ok(at) = pre
                    .coordinates
                    .binary_search_by_key(&earlier.author, |coordinate| coordinate.author)
                else {
                    return Err(Error::MalformedBundle(
                        "signed context omits parent control",
                    ));
                };
                let later = &pre.coordinates[at];
                if later.seq < earlier.seq
                    || (later.seq == earlier.seq && later.hash != earlier.hash)
                {
                    return Err(Error::MalformedBundle(
                        "signed context underclaims parent control",
                    ));
                }
                // A higher coordinate is not by itself a continuity proof. Both endpoints
                // must belong to this node's consistency-accepted author commitment. This
                // also rejects a malformed context hidden in an omitted content leaf.
                if !budget.take_control_lookup() {
                    return Ok(SparseValidationStep::Yielded);
                }
                if let Some(pending) = validate_control_coordinate(input, &pre, earlier)? {
                    return Ok(pending);
                }
                self.parent_coordinate += 1;
            }
            if self.parent_coordinate < frontier.coordinates.len() {
                return Ok(SparseValidationStep::Progress);
            }
            self.parent += 1;
            self.parent_coordinate = 0;
            return Ok(SparseValidationStep::Progress);
        }
        let stop = self
            .coordinate
            .saturating_add(16)
            .min(pre.coordinates.len());
        while self.coordinate < stop {
            let coordinate = &pre.coordinates[self.coordinate];
            if !budget.take_control_lookup() {
                return Ok(SparseValidationStep::Yielded);
            }
            if let Some(pending) = validate_control_coordinate(input, &pre, coordinate)? {
                return Ok(pending);
            }
            self.coordinate += 1;
        }
        if self.coordinate < pre.coordinates.len() {
            return Ok(SparseValidationStep::Progress);
        }
        self.finished = true;
        Ok(SparseValidationStep::Complete(ValidatedSparseEntry {
            included: self.included.clone(),
            pre_context: pre,
            payload_state: self.payload_state,
        }))
    }
}

fn validate_control_coordinate(
    input: &entry_store::Read<'_>,
    context: &ControlContext,
    coordinate: &EntryReference,
) -> Result<Option<SparseValidationStep>> {
    let Some((head, control)) =
        input.history_validated_header(&coordinate.author, coordinate.seq)?
    else {
        return Ok(Some(SparseValidationStep::MissingControl(
            coordinate.clone(),
        )));
    };
    let Some(v2) = &control.skeleton.v2 else {
        return Err(Error::MalformedAtRest("validated control is legacy"));
    };
    if control.entry_hash() != coordinate.hash
        || control.skeleton.channel_id != context.room
        || v2.scope != context.scope
        || !v2.kind.is_control()
    {
        return Err(Error::MalformedBundle(
            "signed context coordinate is not the exact validated control",
        ));
    }
    if !input.control_sources_complete(&head, coordinate.seq)? {
        return Ok(Some(SparseValidationStep::ControlPrefixPending {
            head,
            through: coordinate.seq,
        }));
    }
    Ok(None)
}

/// An existing governance evaluation has finished at this published generation. This is not
/// a claim that the control was Applied: the unchanged evaluator may have found it inert.
pub(crate) struct SettledGovernanceControl {
    entry_hash: Digest32,
}
impl SettledGovernanceControl {
    pub(crate) fn entry_hash(&self) -> Digest32 {
        self.entry_hash
    }
}

pub(crate) enum ControlEvaluation {
    Pending,
    /// Its own typed handler, rather than the room governance fold, decides completion.
    NotGovernance,
    Settled(SettledGovernanceControl),
}

pub(crate) fn sparse_control_evaluation(
    store: &crate::node::store::Store,
    sek: &crate::atrest::sek::Sek,
    room: &Digest32,
    entry: &Entry,
    now: u64,
) -> Result<ControlEvaluation> {
    use super::facts::{hash_key, Read, Table};
    let v2 = entry
        .skeleton
        .v2
        .as_ref()
        .ok_or(Error::MalformedAtRest("sparse control is legacy"))?;
    if entry.skeleton.channel_id != *room {
        return Err(Error::MalformedAtRest("sparse control room differs"));
    }
    if !matches!(
        v2.kind,
        SignedEntryKind::Governance | SignedEntryKind::StepPolicy
    ) {
        return Ok(ControlEvaluation::NotGovernance);
    }
    let facts = Read::open(store, sek, room)?;
    let hash = entry.entry_hash();
    if !facts.ready(now)? || facts.get(Table::Complete, &hash_key(&hash))?.is_none() {
        return Ok(ControlEvaluation::Pending);
    }
    // Hashes holds only fully body-bound, independently authenticated governance source.
    // An absent/pruned source has not become an inert verdict merely by waiting.
    if facts.locator(&hash)?.is_none() {
        return Ok(ControlEvaluation::Pending);
    }
    Ok(ControlEvaluation::Settled(SettledGovernanceControl {
        entry_hash: hash,
    }))
}
