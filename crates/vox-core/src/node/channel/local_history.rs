//! Bounded authored format-2 history. These objects join the existing append transaction;
//! no remote hint, archive fetch, legacy scan or new authority engine participates here.

use super::*;
use crate::log::history::{
    consistency_ranges, inclusion_ranges, ConsistencyProof, ConsistencyVerifier, ConsistentPrefix,
    ContextSource, ControlContext, Descriptor, EntryReference, EntryV2, HistoryStep,
    IncludedHeader, InclusionProof, InclusionVerifier, LocalAppendBudget, LocalTreeAppend,
    LocalTreeStep, LogScope, SignedEntryKind, SignedHead, TreeBinding, TreeRange, TreeRangeSource,
    VerifiedHead, VerifiedHeader, MAX_CONTEXT_AUTHORS, MAX_TREE_DEPTH,
};

pub(super) struct Prepared {
    pub(super) header: VerifiedHeader,
    pub(super) head: VerifiedHead,
    pub(super) consistency: ConsistentPrefix,
    pub(super) included: IncludedHeader,
    pub(super) pre: ControlContext,
    pub(super) post: ControlContext,
    pub(super) ranges: Vec<(u64, Descriptor)>,
}

struct Source<'a, 'read> {
    read: &'a entry_store::Read<'read>,
    pre: &'a ControlContext,
    pre_id: Digest32,
    post: Option<&'a ControlContext>,
    post_id: Option<Digest32>,
    ranges: &'a [(u64, Descriptor)],
}
impl ContextSource for Source<'_, '_> {
    fn context(&self, hash: &Digest32) -> Result<Option<ControlContext>> {
        if self.pre_id == *hash {
            return Ok(Some(self.pre.clone()));
        }
        if let Some(post) = self.post.filter(|_| self.post_id == Some(*hash)) {
            return Ok(Some(post.clone()));
        }
        self.read.history_context(hash)
    }
}
impl TreeRangeSource for Source<'_, '_> {
    fn range(&self, binding: TreeBinding, range: TreeRange) -> Result<Option<Descriptor>> {
        if let Some((_, descriptor)) = self
            .ranges
            .iter()
            .find(|(start, d)| *start == range.start && d.leaves == range.leaves)
        {
            return Ok(Some(*descriptor));
        }
        self.read.history_range(binding, range.start, range.leaves)
    }
}

fn missing() -> Error {
    Error::MalformedAtRest("authored history dependency missing")
}

fn authored_missing(stage: &'static str) -> Error {
    Error::MalformedAtRest(stage)
}

fn classify(payload: &[u8]) -> Result<(SignedEntryKind, Option<Digest32>)> {
    use SignedEntryKind::*;
    let kind = if payload.is_empty() {
        ContextUpdate
    } else if crate::governance::step_policy::is_step_policy(payload) {
        StepPolicy
    } else if session_floor::is_session_floor(payload) {
        SessionFloor
    } else if private_session::is_support(payload) {
        PrivateSupport
    } else if crate::node::keypackage::KeyPackage::is_key_package(payload) {
        return Ok((
            KeyPackage,
            Some(crate::node::keypackage::KeyPackage::from_wire(payload)?.recipient),
        ));
    } else {
        match classify_payload(payload)? {
            EntryKind::Governance => Governance,
            EntryKind::Checkpoint => Checkpoint,
            EntryKind::Content => Content,
        }
    };
    Ok((kind, None))
}

impl ChannelState {
    /// The actor also checks this before dispatching a mutating command. In particular a
    /// remote publication already in progress must not be discovered only after encryption.
    pub(crate) fn ensure_local_append_available(&self, store: &Store) -> Result<()> {
        self.ensure_local_append_available_for(store, false)
    }

    /// An automatic append may not pass this identity's departure, and neither may a person's
    /// post, which a left room refuses. The only caller that may set `after_departure` is the
    /// authenticated return presence written while a rejoin settles.
    pub(super) fn ensure_local_append_available_for(
        &self,
        store: &Store,
        after_departure: bool,
    ) -> Result<()> {
        self.ensure_local_append_available_mode(store, after_departure, false)
    }

    pub(super) fn ensure_local_append_available_mode(
        &self,
        store: &Store,
        after_departure: bool,
        recover_own: bool,
    ) -> Result<()> {
        if self.poisoned {
            return Err(self.save_failure());
        }
        if self.post_pending() {
            return Err(Error::Profile(
                "room publication is busy; retry this operation",
            ));
        }
        let read = self.local_append_eligible_mode(store, after_departure, recover_own)?;
        if read.publication_busy()
            || (read.sparse_enabled() && read.history_obligation_capacity() < 2)
        {
            return Err(if recover_own {
                Error::OwnHistoryBehind
            } else {
                Error::Profile("room publication is busy; retry this operation")
            });
        }
        Ok(())
    }

    /// Eligibility is independent of capacity for an entry a no-op will never append.
    /// Return the same read so actual append admission does not reopen the index.
    pub(super) fn local_append_eligible_for<'a>(
        &'a self,
        store: &Store,
        after_departure: bool,
    ) -> Result<entry_store::Read<'a>> {
        self.local_append_eligible_mode(store, after_departure, false)
    }

    fn local_append_eligible_mode<'a>(
        &'a self,
        store: &Store,
        after_departure: bool,
        recover_own: bool,
    ) -> Result<entry_store::Read<'a>> {
        // The departure statement must remain this author's tail until another member has
        // acknowledged it. Background key, receipt, session, or share work cannot make a node
        // appear to rejoin after the person chose Leave.
        if self.has_left(&self.me()) && !after_departure {
            return Err(Error::Profile("this identity has left the room"));
        }
        let read = self.entries.read(store, &self.sek, &self.channel_id)?;
        if read.legacy_provisional().is_some() || read.legacy_required_any() {
            return Err(Error::Profile(super::UNSUPPORTED_ROOM_FORMAT));
        }
        if !recover_own && read.sparse_enabled() {
            self.require_own_history_safe_in(&read)?;
        }
        Ok(read)
    }

    /// At most sixteen actual settled tips are named. Their prefixes are local cached proof
    /// results; missing evidence is a readiness error, never an implicit archive request.
    fn authored_context(
        &self,
        store: &Store,
        author: &Digest32,
        kind: SignedEntryKind,
    ) -> Result<(ControlContext, Vec<EntryReference>, bool)> {
        let read = self.entries.read(store, &self.sek, &self.channel_id)?;
        let required = required_cut(
            store,
            &self.sek,
            &self.channel_id,
            &read,
            author,
            kind,
            self.now_hint,
        )?;
        authored_context(
            &read,
            self.channel_id,
            &self.authors,
            self.dag.feed(author).map_or(0, |feed| feed.max_seq()),
            author,
            required.as_slice(),
        )
    }

    /// The readmission cut this author's next restricted entry must name, decided once under
    /// the room lock at preparation (#1171). REFRESHING is the existing retryable deferral.
    pub(super) fn authoring_cut(
        &self,
        store: &Store,
        author: &Digest32,
    ) -> Result<Option<Digest32>> {
        required_cut(
            store,
            &self.sek,
            &self.channel_id,
            &self.entries.read(store, &self.sek, &self.channel_id)?,
            author,
            SignedEntryKind::Content,
            self.now_hint,
        )
    }

    /// Every required governance ancestor (a readmission's covered removals) must already be
    /// within reach of this author's next authored context, checked before signing, any
    /// reservation or write. A validated removal whose author's history has not settled here
    /// is the existing retryable REFRESHING; more distinct uncovered required authors than
    /// `seen` can name is the existing capacity refusal. Neither is the authored-frontier
    /// MalformedAtRest, which remains the run-time invariant guard.
    pub(super) fn require_authored_ancestors(
        &self,
        store: &Store,
        author: &Digest32,
        required: &[Digest32],
    ) -> Result<()> {
        if required.is_empty() {
            return Ok(());
        }
        let read = self.entries.read(store, &self.sek, &self.channel_id)?;
        // A sparse feed joins its committed frontier and settled tips; a legacy feed names
        // each uncovered required author in `seen` beside its already referenced positions.
        let reach = if read.sparse_enabled() {
            Some(AuthoredReach::new(&read, author)?)
        } else {
            None
        };
        let own_seq = self.dag.feed(author).map_or(0, |feed| feed.max_seq());
        let mut named = [[0u8; 32]; crate::log::entry::MAX_SEEN];
        let mut count = 0;
        for hash in required {
            let Some((ancestor_author, seq)) = read.locate(hash)? else {
                return Err(Error::Profile(governance::REFRESHING));
            };
            let covered = match &reach {
                Some(reach) => {
                    if reach.committed(&ancestor_author, seq) {
                        true
                    } else if reach.settled(&ancestor_author, seq)? {
                        false
                    } else {
                        return Err(Error::Profile(governance::REFRESHING));
                    }
                }
                None if ancestor_author == *author => seq <= own_seq,
                None => read.referenced(author, &ancestor_author)? >= seq,
            };
            if covered {
                continue;
            }
            if !named[..count].contains(&ancestor_author) {
                if count == named.len() {
                    return Err(Error::SizeLimitExceeded("readmission causal frontier"));
                }
                named[count] = ancestor_author;
                count += 1;
            }
        }
        Ok(())
    }

    /// Fill the real EntrySkeleton's v2 fields. Changed context is explicitly carried by a
    /// control before ordinary content, so content cannot smuggle a new governance dependency.
    pub(super) fn authored_v2(
        &mut self,
        profile: &Profile,
        author: &Digest32,
        payload: &[u8],
        claimed_ms: u64,
    ) -> Result<Option<(EntryV2, Vec<Digest32>)>> {
        if !self
            .entries
            .read(profile.store(), &self.sek, &self.channel_id)?
            .sparse_enabled()
        {
            return Ok(None);
        }
        let (kind, recipient) = classify(payload)?;
        self.authored_kind(profile, author, kind, recipient, claimed_ms, false)
            .map(Some)
    }

    fn authored_kind(
        &mut self,
        profile: &Profile,
        author: &Digest32,
        kind: SignedEntryKind,
        recipient: Option<Digest32>,
        claimed_ms: u64,
        after_departure: bool,
    ) -> Result<(EntryV2, Vec<Digest32>)> {
        let mut budget = LocalAppendBudget::new();
        budget.reserve_context_preparation()?;
        let (mut context, seen, changed) = self.authored_context(profile.store(), author, kind)?;
        if kind == SignedEntryKind::Content && changed {
            self.append_control_kind(
                profile,
                &[],
                claimed_ms,
                EntryKind::Content,
                after_departure,
            )?;
            // The inserted control has exactly the selected context and seen references.
            // Reuse that selection; only its new own coordinate changes the post-context.
            let read = self
                .entries
                .read(profile.store(), &self.sek, &self.channel_id)?;
            let id = read
                .sparse_author(author, LogScope::Public)?
                .and_then(|state| state.committed)
                .ok_or_else(missing)?;
            let head = read.history_head(&id)?.ok_or_else(missing)?;
            context = read
                .history_context(&head.root.frontier)?
                .ok_or_else(missing)?;
        }
        let hashes = seen.iter().map(|reference| reference.hash).collect();
        let v2 = EntryV2 {
            kind,
            scope: LogScope::Public,
            pre_context: context.hash(),
            seen,
            recipient,
        };
        self.local_pre_context = Some(context);
        self.local_append_budget = Some(budget);
        Ok((v2, hashes))
    }

    /// Prepare metadata without publishing it. Every range/context enters the final existing
    /// append Batch after its contiguous root switch, never as a separately visible head.
    pub(super) fn prepare_local_entry(
        &mut self,
        profile: &Profile,
        entry: &Entry,
        kind: EntryKind,
        key: &CompositePublicKey,
        now_ms: u64,
    ) -> Result<()> {
        if entry.skeleton.v2.is_some() {
            let pre = self.local_pre_context.take().ok_or_else(missing)?;
            let read = self
                .entries
                .read(profile.store(), &self.sek, &self.channel_id)?;
            let budget = self.local_append_budget.take().ok_or_else(missing)?;
            self.local_history = Some(prepare(&read, profile.signer()?, entry, pre, budget)?);
        }
        self.prepare_entry(profile.store(), entry, kind, key, now_ms)
    }
}

/// The readmission cut a fresh local Content, KeyPackage or ContextUpdate entry must name
/// once this node's checked fold has one (#1171), so a readmitted member can receive what is
/// authored after its readmission. Governance, presence, retention and other controls never
/// wait on it. When it applies it is always required, never skipped: if neither this author's
/// committed frontier nor the cut author's settled tip reaches it yet, this one append is the
/// existing retryable REFRESHING (nothing committed), re-driven by the governance progress
/// that settles it. A legacy feed names it as an ordinary seen ancestor without that wait.
pub(super) fn required_cut(
    store: &Store,
    sek: &crate::atrest::sek::Sek,
    room: &Digest32,
    read: &entry_store::Read<'_>,
    author: &Digest32,
    kind: SignedEntryKind,
    now: u64,
) -> Result<Option<Digest32>> {
    if !matches!(
        kind,
        SignedEntryKind::Content | SignedEntryKind::KeyPackage | SignedEntryKind::ContextUpdate
    ) {
        return Ok(None);
    }
    let Some(cut) = governance::View::room_cut(store, sek, room, now)? else {
        return Ok(None);
    };
    let Some((cut_author, seq)) = read.locate(&cut)? else {
        return Err(Error::Profile(governance::REFRESHING));
    };
    if !read.sparse_enabled() {
        return Ok(Some(cut));
    }
    let reach = AuthoredReach::new(read, author)?;
    if !reach.committed(&cut_author, seq) && !reach.settled(&cut_author, seq)? {
        return Err(Error::Profile(governance::REFRESHING));
    }
    Ok(Some(cut))
}

/// The sources `authored_context` joins for one author, read once: its own committed
/// position and frontier, and (per ancestor) the other author's settled tip. Reads only; it
/// never selects or widens what is authored.
struct AuthoredReach<'r, 'a> {
    read: &'r entry_store::Read<'a>,
    author: Digest32,
    own_seq: u64,
    frontier: Option<ControlContext>,
}

impl<'r, 'a> AuthoredReach<'r, 'a> {
    fn new(read: &'r entry_store::Read<'a>, author: &Digest32) -> Result<Self> {
        let head = match read
            .sparse_author(author, LogScope::Public)?
            .and_then(|state| state.committed)
        {
            Some(id) => read.history_head(&id)?,
            None => None,
        };
        let (own_seq, frontier) = match head {
            Some(head) => (head.root.leaves, read.history_context(&head.root.frontier)?),
            None => (0, None),
        };
        Ok(Self {
            read,
            author: *author,
            own_seq,
            frontier,
        })
    }

    /// Already inside the author's committed history: its own position, or a coordinate
    /// of its committed frontier. Such an ancestor needs no `seen` slot.
    fn committed(&self, ancestor_author: &Digest32, seq: u64) -> bool {
        if *ancestor_author == self.author {
            return seq <= self.own_seq;
        }
        self.frontier.as_ref().is_some_and(|context| {
            context
                .coordinates
                .iter()
                .any(|coordinate| coordinate.author == *ancestor_author && coordinate.seq >= seq)
        })
    }

    /// Reachable through another author's settled tip, which `seen` must then name.
    fn settled(&self, ancestor_author: &Digest32, seq: u64) -> Result<bool> {
        Ok(*ancestor_author != self.author
            && self
                .read
                .history_settled_tip(ancestor_author)?
                .is_some_and(|tip| tip.skeleton.seq >= seq))
    }
}

pub(super) fn authored_context(
    read: &entry_store::Read<'_>,
    channel_id: Digest32,
    authors: &BTreeMap<Digest32, CompositePublicKey>,
    own_seq: u64,
    author: &Digest32,
    required: &[Digest32],
) -> Result<(ControlContext, Vec<EntryReference>, bool)> {
    if authors.len() > MAX_CONTEXT_AUTHORS {
        return Err(Error::SizeLimitExceeded("local context authors"));
    }
    let binding = TreeBinding {
        room: channel_id,
        scope: LogScope::Public,
        author: *author,
    };
    let mut context = if own_seq == 0 {
        ControlContext::empty(channel_id, LogScope::Public)
    } else {
        let head_id = read
            .sparse_author(author, LogScope::Public)?
            .and_then(|state| state.committed)
            .ok_or_else(|| authored_missing("authored history own committed head missing"))?;
        let head = read
            .history_head(&head_id)?
            .ok_or_else(|| authored_missing("authored history own head record missing"))?;
        if head.binding != binding || head.root.leaves != own_seq {
            return Err(authored_missing(
                "authored history own head binding differs",
            ));
        }
        read.history_context(&head.root.frontier)?
            .ok_or_else(|| authored_missing("authored history own frontier context missing"))?
    };
    let original = context.hash();
    let mut required_positions = Vec::with_capacity(required.len());
    for hash in required {
        let (required_author, seq) = read
            .locate(hash)?
            .ok_or_else(|| authored_missing("required governance ancestor missing"))?;
        required_positions.push((required_author, seq));
    }
    let mut tips = BTreeMap::new();
    for other in authors.keys().filter(|other| *other != author) {
        let Some(tip) = read.history_settled_tip(other)? else {
            continue;
        };
        let hash = tip.entry_hash();
        let Some(clock) = read.clock(&hash)? else {
            return Err(authored_missing(
                "authored history settled peer clock missing",
            ));
        };
        tips.insert(
            (
                // Only a required position the initial own committed context does not
                // already reach needs a `seen` slot; covered authors keep ordinary priority.
                required_positions.iter().any(|(required_author, seq)| {
                    required_author == other
                        && !context
                            .coordinates
                            .iter()
                            .any(|coordinate| coordinate.author == *other && coordinate.seq >= *seq)
                }),
                clock,
                hash,
            ),
            EntryReference {
                author: *other,
                seq: tip.skeleton.seq,
                hash,
            },
        );
        if tips.len() > crate::log::entry::MAX_SEEN {
            tips.pop_first();
        }
    }
    let mut seen: Vec<_> = tips.into_values().collect();
    seen.sort_unstable_by_key(|reference| reference.author);
    for reference in &seen {
        let binding = TreeBinding {
            author: reference.author,
            ..binding
        };
        let prefix = read
            .history_range(binding, 1, reference.seq)?
            .ok_or_else(|| authored_missing("authored history settled peer prefix missing"))?;
        let frontier = read.history_context(&prefix.frontier)?.ok_or_else(|| {
            authored_missing("authored history settled peer frontier context missing")
        })?;
        context = context.join(&frontier)?;
    }
    for (required_author, seq) in required_positions {
        let reached = if required_author == *author {
            own_seq
        } else {
            context
                .coordinates
                .iter()
                .find(|coordinate| coordinate.author == required_author)
                .map_or(0, |coordinate| coordinate.seq)
        };
        if reached < seq {
            return Err(authored_missing(
                "required governance ancestors exceed the authored frontier",
            ));
        }
    }
    let changed = context.hash() != original;
    Ok((context, seen, changed))
}

pub(super) fn prepare(
    read: &entry_store::Read<'_>,
    signer: &dyn crate::identity::composite::RootSigner,
    entry: &Entry,
    pre: ControlContext,
    mut budget: LocalAppendBudget,
) -> Result<Prepared> {
    let v2 = entry.skeleton.v2.as_ref().ok_or_else(missing)?;
    let binding = TreeBinding {
        room: entry.skeleton.channel_id,
        scope: v2.scope,
        author: entry.skeleton.author_id,
    };
    if signer.fingerprint() != binding.author || pre.hash() != v2.pre_context {
        return Err(missing());
    }
    let previous = if entry.skeleton.seq == 1 {
        Descriptor::empty(binding)
    } else {
        let id = read
            .sparse_author(&binding.author, binding.scope)?
            .and_then(|state| state.committed)
            .ok_or_else(missing)?;
        let head = read.history_head(&id)?.ok_or_else(missing)?;
        if head.binding != binding || head.root.leaves + 1 != entry.skeleton.seq {
            return Err(missing());
        }
        head.root
    };
    let header_entry = Entry::from_wire(&entry.header_wire())?;
    let header = budget.verify_header(&header_entry, binding, &signer.public_key())?;
    let mut tree = LocalTreeAppend::new(binding, header.clone())?;
    let mut ranges = Vec::with_capacity(MAX_TREE_DEPTH + 1);
    let mut post: Option<ControlContext> = None;
    let pre_id = pre.hash();
    let mut post_id = None;
    let root = loop {
        let source = Source {
            read,
            pre: &pre,
            pre_id,
            post: post.as_ref(),
            post_id,
            ranges: &ranges,
        };
        match tree.advance(&source, &mut budget)? {
            LocalTreeStep::Range {
                start,
                descriptor,
                context,
            } => {
                if post.as_ref().is_some_and(|post| *post != context) {
                    return Err(Error::MalformedAtRest(
                        "local pre-context does not dominate own prefix",
                    ));
                }
                if post.is_none() {
                    post_id = Some(context.hash());
                    post = Some(context);
                }
                ranges.push((start, descriptor));
                if ranges.len() > MAX_TREE_DEPTH + 1 {
                    return Err(Error::SizeLimitExceeded("local append range count"));
                }
            }
            LocalTreeStep::Complete(root) => break root,
            LocalTreeStep::MissingContext | LocalTreeStep::MissingRange => return Err(missing()),
            LocalTreeStep::Yielded => {
                return Err(Error::SizeLimitExceeded("local append work quota"))
            }
        }
    };
    let post = post.ok_or_else(missing)?;
    let source = Source {
        read,
        pre: &pre,
        pre_id,
        post: Some(&post),
        post_id,
        ranges: &ranges,
    };
    let signed = SignedHead::sign(binding, entry.skeleton.epoch, root, signer)?;
    let head = budget.verify_head(&signed, &signer.public_key())?;
    let mut siblings = Vec::new();
    for range in inclusion_ranges(entry.skeleton.seq, root.leaves)? {
        siblings.push(budget.range(&source, binding, range)?.ok_or_else(missing)?);
    }
    let mut inclusion = InclusionVerifier::new(
        head.clone(),
        header.clone(),
        InclusionProof {
            position: entry.skeleton.seq,
            size: root.leaves,
            siblings,
        },
    )?;
    let included = loop {
        match budget.inclusion(&mut inclusion, &source)? {
            HistoryStep::Complete(value) => break value,
            HistoryStep::Progress(context) => budget.check_context(&source, &context)?,
            HistoryStep::MissingContext(_) => return Err(missing()),
            HistoryStep::Yielded => {
                return Err(Error::SizeLimitExceeded("local inclusion work quota"))
            }
        }
    };
    let mut nodes = Vec::new();
    for range in consistency_ranges(previous.leaves, root.leaves)? {
        nodes.push(budget.range(&source, binding, range)?.ok_or_else(missing)?);
    }
    let mut proof = ConsistencyVerifier::new(
        head.clone(),
        previous,
        ConsistencyProof {
            from: previous.leaves,
            to: root.leaves,
            nodes,
        },
    )?;
    let consistency = loop {
        match budget.consistency(&mut proof, &source)? {
            HistoryStep::Complete(value) => break value,
            HistoryStep::Progress(context) => budget.check_context(&source, &context)?,
            HistoryStep::MissingContext(_) => return Err(missing()),
            HistoryStep::Yielded => {
                return Err(Error::SizeLimitExceeded("local consistency work quota"))
            }
        }
    };
    Ok(Prepared {
        header,
        head,
        consistency,
        included,
        pre,
        post,
        ranges,
    })
}
