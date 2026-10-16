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

    /// An automatic append may not pass this identity's departure. The only callers that may
    /// set `after_departure` are an intentional post, which explicitly undoes a pending leave,
    /// and the authenticated return presence written while a rejoin settles.
    pub(super) fn ensure_local_append_available_for(
        &self,
        store: &Store,
        after_departure: bool,
    ) -> Result<()> {
        // The departure statement must remain this author's tail until another member has
        // acknowledged it. Background key, receipt, session, or share work cannot make a node
        // appear to rejoin after the person chose Leave.
        if self.has_left(&self.me()) && !after_departure {
            return Err(Error::Profile("this identity has left the room"));
        }
        let read = self.entries.read(store, &self.sek, &self.channel_id)?;
        if read.legacy_provisional().is_some() || read.legacy_required_any() {
            return Err(Error::Profile(
                "Legacy history required; resume explicit recovery before posting in this room",
            ));
        }
        if read.publication_busy()
            || (read.sparse_enabled() && read.history_obligation_capacity() < 2)
        {
            return Err(Error::Profile(
                "room publication is busy; retry this operation",
            ));
        }
        Ok(())
    }

    /// At most sixteen actual settled tips are named. Their prefixes are local cached proof
    /// results; missing evidence is a readiness error, never an implicit archive request.
    fn authored_context(
        &self,
        store: &Store,
        author: &Digest32,
    ) -> Result<(ControlContext, Vec<EntryReference>, bool)> {
        if self.authors.len() > MAX_CONTEXT_AUTHORS {
            return Err(Error::SizeLimitExceeded("local context authors"));
        }
        let read = self.entries.read(store, &self.sek, &self.channel_id)?;
        let binding = TreeBinding {
            room: self.channel_id,
            scope: LogScope::Public,
            author: *author,
        };
        let own_seq = self.dag.feed(author).map_or(0, |feed| feed.max_seq());
        let mut context = if own_seq == 0 {
            ControlContext::empty(self.channel_id, LogScope::Public)
        } else {
            let head_id = read
                .sparse_author(author, LogScope::Public)?
                .and_then(|state| state.committed)
                .ok_or_else(missing)?;
            let head = read.history_head(&head_id)?.ok_or_else(missing)?;
            if head.binding != binding || head.root.leaves != own_seq {
                return Err(missing());
            }
            read.history_context(&head.root.frontier)?
                .ok_or_else(missing)?
        };
        let original = context.hash();
        let mut tips = BTreeMap::new();
        for other in self.authors.keys().filter(|other| *other != author) {
            let Some(tip) = read.history_settled_tip(other)? else {
                continue;
            };
            let hash = tip.entry_hash();
            let Some(clock) = read.clock(&hash)? else {
                return Err(missing());
            };
            tips.insert(
                (clock, hash),
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
            let b = TreeBinding {
                author: reference.author,
                ..binding
            };
            let prefix = read
                .history_range(b, 1, reference.seq)?
                .ok_or_else(missing)?;
            let frontier = read
                .history_context(&prefix.frontier)?
                .ok_or_else(missing)?;
            context = context.join(&frontier)?;
        }
        let changed = context.hash() != original;
        Ok((context, seen, changed))
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
        if kind == SignedEntryKind::Content {
            if let Some(prepared) = self.local_content_header.take() {
                return Ok(Some(prepared));
            }
        }
        self.authored_kind(profile, author, kind, recipient, claimed_ms, false)
            .map(Some)
    }

    /// Resolve local proof dependencies and append any context control before the sender
    /// ratchet is advanced. A retryable dependency failure cannot consume a message key.
    pub(super) fn prepare_content_context(
        &mut self,
        profile: &Profile,
        author: &Digest32,
        claimed_ms: u64,
        after_departure: bool,
    ) -> Result<()> {
        if !self
            .entries
            .read(profile.store(), &self.sek, &self.channel_id)?
            .sparse_enabled()
        {
            return Ok(());
        }
        self.local_content_header = None;
        // An intentional post's context control, when required, is part of that same operation
        // and shares its departure exception. Automatic read records pass false.
        let prepared = self.authored_kind(
            profile,
            author,
            SignedEntryKind::Content,
            None,
            claimed_ms,
            after_departure,
        )?;
        self.local_content_header = Some(prepared);
        Ok(())
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
        let (mut context, seen, changed) = self.authored_context(profile.store(), author)?;
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

fn prepare(
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
            LocalTreeStep::MissingContext(_) | LocalTreeStep::MissingRange(_) => {
                return Err(missing())
            }
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
