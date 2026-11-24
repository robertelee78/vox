//! Cooperative repair of one proof-serving range from independently committed source metadata.
//! No pending header, payload, missing-body request, or newly computed prefix grants authority.
//! The asked head need not be held here (ADR-053 P): ranges under it are rebuilt from material
//! authenticated on one committed source head of the same author at least as large.
use super::sparse_history::HistoryAdmissionRoom;
use super::*;
use crate::log::history::{
    join_descriptors, leaf_descriptor, split, ContextSource, ControlContext, Descriptor,
    HeadTarget, HistoryStep, SignedHead, TreeBinding, TreeRange, VerifiedHeader, WorkBudget,
    MAX_CONTEXT_BYTES, MAX_HEADER_BYTES, MAX_TREE_DEPTH,
};

/// A head an asker named that this holder resolved for serving (ADR-053 P): the asker's
/// unsigned target and the independently committed source head of the same room, scope and
/// author, at least as large, whose authenticated material serves it. Resolution compared the
/// target's complete root with the prefix computed from that material, unless the target is
/// itself a head this node committed (`source == id`).
#[derive(Clone, Copy, Debug)]
pub(crate) struct ResolvedTarget {
    pub(crate) id: Digest32,
    pub(crate) target: HeadTarget,
    pub(crate) source: Digest32,
}
impl ResolvedTarget {
    /// A head this node committed serves from its own material, as before P.
    pub(crate) fn exact(head: &SignedHead) -> Self {
        Self {
            id: head.id(),
            target: head.target(),
            source: head.id(),
        }
    }
    /// An unsigned target, to be compared with the prefix of `source` before anything is served.
    pub(crate) fn pinned(target: HeadTarget, source: Digest32) -> Self {
        Self {
            id: target.id(),
            target,
            source,
        }
    }
}

/// Serving reads contexts this repair generated (kept only in the serving cache) before the
/// durable ones; both are content-addressed, so either answer is the same object.
struct ServingContexts<'a, 'b> {
    read: &'a entry_store::Read<'b>,
    room: Digest32,
}
impl ContextSource for ServingContexts<'_, '_> {
    fn context(&self, hash: &Digest32) -> Result<Option<ControlContext>> {
        if let Some(context) = entry_store::sparse::serving_context(&self.room, hash) {
            return Ok(Some(context));
        }
        self.read.history_context(hash)
    }
}

#[derive(Clone)]
enum Task {
    Visit(TreeRange),
    Join { start: u64 },
}
/// Scalar, request-owned DFS; completed children live in the daemon's bounded serving cache.
/// Cache eviction or cancellation loses no canonical source metadata.
pub(crate) struct ProofRangeRestore {
    /// The asked head's ID.
    head: Digest32,
    /// The committed source head whose material serves it (the asked head itself if committed).
    source: Digest32,
    binding: TreeBinding,
    root: Descriptor,
    requested: TreeRange,
    scope: Option<([u8; 16], u64, u64, u64)>,
    tasks: Vec<Task>,
    values: Vec<Descriptor>,
    /// The next earlier head to read a linked piece of this range under (see `restore`).
    linked: Option<(TreeRange, Digest32)>,
    /// A node no linked head kept: its descendants are not searched again (see `restore`).
    unlinked: Option<TreeRange>,
}
pub(crate) enum ProofRangeStep {
    Complete(Descriptor),
    Progress,
    Busy,
    Missing,
}
impl ProofRangeRestore {
    /// Directory/B-tree decode scratch is charged separately. This bounds overlapping
    /// context decode/hash/join/encoding copies, canonical header records and exact DFS capacity.
    pub(crate) const WORK_BYTES: usize = 8 * MAX_CONTEXT_BYTES
        + 4 * MAX_HEADER_BYTES
        + (2 * MAX_TREE_DEPTH + 1) * std::mem::size_of::<Task>()
        + (MAX_TREE_DEPTH + 1) * std::mem::size_of::<Descriptor>();
    pub(crate) fn new(target: &ResolvedTarget, start: u64, leaves: u64) -> Result<Self> {
        if start == 0
            || leaves == 0
            || start
                .checked_add(leaves - 1)
                .is_none_or(|end| end > target.target.root.leaves)
        {
            return Err(Error::MalformedBundle("proof repair range exceeds head"));
        }
        let requested = TreeRange { start, leaves };
        let mut tasks = Vec::with_capacity(2 * MAX_TREE_DEPTH + 1);
        tasks.push(Task::Visit(requested));
        Ok(Self {
            head: target.id,
            source: target.source,
            binding: target.target.binding,
            root: target.target.root,
            requested,
            scope: None,
            tasks,
            values: Vec::with_capacity(MAX_TREE_DEPTH + 1),
            linked: None,
            unlinked: None,
        })
    }
}
pub(crate) struct PendingProofRange {
    admission: super::sparse_history::PendingHistoryAdmission,
    authority: Option<(u64, u64, u64, bool)>,
}

impl PendingProofRange {
    pub(crate) fn advance(
        self,
        store: &Store,
        cursor: &mut ProofRangeRestore,
    ) -> Result<ProofRangeStep> {
        self.admission
            .with(|room| ProofRangeRestore::restore(room, store, self.authority, cursor))
    }
}

impl ChannelState {
    pub(crate) fn prepare_proof_range(
        &self,
        store: &Store,
        peer: Digest32,
        cursor: &ProofRangeRestore,
        authorization: Option<(Digest32, Digest32)>,
    ) -> Result<PendingProofRange> {
        let authority = self
            .history_inventory_incarnation(&peer)
            .zip(self.history_author_inventory_incarnation(&cursor.binding.author))
            .map(|(peer, author)| {
                (
                    self.epoch(),
                    peer,
                    author,
                    self.dag.is_frozen(&cursor.binding.author),
                )
            });
        Ok(PendingProofRange {
            admission: self.prepare_history_admission(store, authorization)?,
            authority,
        })
    }
}

impl ProofRangeRestore {
    /// At most one newly reconstructed node advances per call. Cache/index/context reads and
    /// reconstruction consume the existing WorkBudget; total old-data work can be O(interval).
    /// Nothing is written: a generated context and descriptor go to the serving caches only.
    fn restore(
        room: &impl HistoryAdmissionRoom,
        store: &Store,
        authority: Option<(u64, u64, u64, bool)>,
        cursor: &mut ProofRangeRestore,
    ) -> Result<ProofRangeStep> {
        let mut work = WorkBudget::default();
        // Source object, independent commitment and current author/fork state.
        for _ in 0..8 {
            if !work.take_object_load() {
                return Ok(ProofRangeStep::Progress);
            }
        }
        let read = room.history_read(store)?;
        if read.publication_busy() {
            return Ok(ProofRangeStep::Busy);
        }
        let Some((epoch, peer_life, author_life, frozen)) = authority else {
            return Ok(ProofRangeStep::Missing);
        };
        let scope = (
            read.sparse_history_instance(),
            epoch,
            peer_life,
            author_life,
        );
        if scope.0 == [0; 16] || cursor.scope.is_some_and(|old| old != scope) {
            return Err(Error::Unreachable(
                "proof repair authority or room lifetime changed",
            ));
        }
        cursor.scope = Some(scope);
        if cursor.binding.room != room.channel_id() {
            return Ok(ProofRangeStep::Missing);
        }
        // The pinned source: the asked head itself when this node committed it, otherwise the
        // committed head of the same author that resolution compared the asked root with.
        let exact = cursor.source == cursor.head;
        let source = read
            .history_head(&cursor.source)?
            .ok_or(Error::MalformedAtRest("proof repair source disappeared"))?;
        if source.binding != cursor.binding
            || (exact && source.root != cursor.root)
            || source.root.leaves < cursor.root.leaves
        {
            return Err(Error::MalformedAtRest("proof repair source changed"));
        }
        let reconstruction_allowed = read.history_head_committed(&cursor.source, cursor.binding)?
            && !frozen
            && read
                .sparse_author(&cursor.binding.author, cursor.binding.scope)?
                .is_none_or(|state| state.observed_conflict.is_none());
        let contexts = ServingContexts {
            read: &read,
            room: cursor.binding.room,
        };
        loop {
            let Some(task) = cursor.tasks.last().cloned() else {
                let [result] = cursor.values.as_slice() else {
                    return Err(Error::MalformedAtRest("proof repair result stack"));
                };
                if result.leaves != cursor.requested.leaves {
                    return Err(Error::MalformedAtRest("proof repair range length differs"));
                }
                if cursor.requested.start == 1
                    && result.leaves == cursor.root.leaves
                    && *result != cursor.root
                {
                    // A committed head's own root is corruption here. An asked head this node
                    // never committed is simply not this source's prefix: unavailable.
                    if exact {
                        return Err(Error::MalformedAtRest(
                            "proof repair reconstructed root differs",
                        ));
                    }
                    // The P guards' forked provider answers with its own prefix anyway.
                    if !bad_prefix("fork") {
                        return Ok(ProofRangeStep::Missing);
                    }
                }
                return Ok(ProofRangeStep::Complete(*result));
            };
            let (start, descriptor, context, operands) = match task {
                Task::Visit(range) => {
                    // Both indexed keys and their sealed descriptor records.
                    for _ in 0..4 {
                        if !work.take_object_load() {
                            return Ok(ProofRangeStep::Progress);
                        }
                    }
                    // The canonical acceptance index first. A piece kept under the source is
                    // that source's node; for an asked head this node never committed only a
                    // full aligned block is reused, the same node in every head containing it,
                    // and every partial or right-edge node is rebuilt for the asked size.
                    let aligned =
                        range.leaves.is_power_of_two() && (range.start - 1) % range.leaves == 0;
                    let mut found =
                        read.history_range(cursor.binding, range.start, range.leaves)?;
                    if found.is_none() && (exact || aligned) {
                        found = read.history_proof_range(
                            &cursor.source,
                            cursor.binding,
                            range.start,
                            range.leaves,
                        )?;
                    }
                    if let Some(value) = found {
                        // Its frontier context, unless it is held, means rebuilding it.
                        if !work.take_object_load() {
                            return Ok(ProofRangeStep::Progress);
                        }
                        if frontier_held(&contexts, &value)? {
                            if cursor.values.len() == MAX_TREE_DEPTH + 1 {
                                return Err(Error::SizeLimitExceeded("proof repair value depth"));
                            }
                            cursor.tasks.pop();
                            cursor.values.push(value);
                            continue;
                        }
                    }
                    // Existing verified serving material may satisfy a local verifier even
                    // before promotion. Only NEW reconstruction requires independently
                    // committed, nonforked target/source roots; no cache is acceptance
                    // evidence. A known fork does not invalidate existing historical math.
                    if !reconstruction_allowed {
                        return Ok(ProofRangeStep::Missing);
                    }
                    // A full aligned block inside an earlier head is the same tree node, with the
                    // same descriptor, in every head that extends it. Serve the piece kept under
                    // an earlier head only along the source's own commit links: each link is the
                    // consistency proof it verified when it committed the later head from the
                    // earlier one (`history_prior_head`), so no unlinked or forked head is used.
                    // Partial and unaligned nodes differ between heads and are never reused
                    // (ADR-053 MP-7). The asker verifies every piece under its own head. One
                    // search per node that no link kept, not one per descendant: below it this
                    // repair reconstructs as before.
                    let end = range.start + range.leaves - 1;
                    let searched = cursor.unlinked.is_some_and(|above| {
                        above.start <= range.start && end < above.start + above.leaves
                    });
                    if !searched && !linked_mutant() && aligned {
                        let mut at = match cursor.linked {
                            Some((linked, at)) if linked == range => at,
                            _ => cursor.source,
                        };
                        let mut found = None;
                        loop {
                            // The link, the earlier head record and the piece's index and record.
                            for _ in 0..4 {
                                if !work.take_object_load() {
                                    cursor.linked = Some((range, at));
                                    return Ok(ProofRangeStep::Progress);
                                }
                            }
                            let Some(prior) = read.history_prior_head(&at)? else {
                                break;
                            };
                            if prior.binding != cursor.binding {
                                return Err(Error::MalformedAtRest("linked head binding differs"));
                            }
                            if prior.root.leaves < end {
                                break;
                            }
                            found = read.history_proof_range(
                                &prior.id(),
                                cursor.binding,
                                range.start,
                                range.leaves,
                            )?;
                            if let Some(value) = found {
                                if !work.take_object_load() {
                                    cursor.linked = Some((range, at));
                                    return Ok(ProofRangeStep::Progress);
                                }
                                if !frontier_held(&contexts, &value)? {
                                    found = None;
                                }
                                break;
                            }
                            at = prior.id();
                        }
                        cursor.linked = None;
                        if found.is_none() {
                            cursor.unlinked = Some(range);
                        }
                        if let Some(value) = found {
                            if cursor.values.len() == MAX_TREE_DEPTH + 1 {
                                return Err(Error::SizeLimitExceeded("proof repair value depth"));
                            }
                            cursor.tasks.pop();
                            cursor.values.push(value);
                            continue;
                        }
                    }
                    if range.leaves != 1 {
                        if cursor.tasks.len() + 2 > 2 * MAX_TREE_DEPTH + 1 {
                            return Err(Error::SizeLimitExceeded("proof repair depth"));
                        }
                        let left = split(range.leaves)?;
                        cursor.tasks.pop();
                        cursor.tasks.push(Task::Join { start: range.start });
                        cursor.tasks.push(Task::Visit(TreeRange {
                            start: range.start + left,
                            leaves: range.leaves - left,
                        }));
                        cursor.tasks.push(Task::Visit(TreeRange {
                            start: range.start,
                            leaves: left,
                        }));
                        continue;
                    }
                    // Indexed header, source-Head object, commitment and exact receipt loads.
                    for _ in 0..12 {
                        if !work.take_object_load() {
                            return Ok(ProofRangeStep::Progress);
                        }
                    }
                    let Some((leaf_source, header)) =
                        read.history_validated_header(&cursor.binding.author, range.start)?
                    else {
                        return Ok(ProofRangeStep::Missing);
                    };
                    let source_head = read
                        .history_head(&leaf_source)?
                        .ok_or(Error::MalformedAtRest("proof repair source head missing"))?;
                    if source_head.binding != cursor.binding {
                        return Err(Error::MalformedAtRest(
                            "proof repair source binding differs",
                        ));
                    }
                    // A header may have been admitted under an older prefix accepted through
                    // a consistency proof. Without an independent commitment this repair does
                    // not use it as a new tree source; unavailable evidence is not corruption.
                    if !read.history_head_committed(&leaf_source, source_head.binding)? {
                        return Ok(ProofRangeStep::Missing);
                    }
                    let included = read
                        .history_inclusion_receipt(
                            &leaf_source,
                            &cursor.binding.author,
                            range.start,
                        )?
                        .ok_or(Error::MalformedAtRest(
                            "proof repair canonical inclusion missing",
                        ))?;
                    if included.head_id() != leaf_source
                        || included.binding() != cursor.binding
                        || included.root() != source_head.root
                        || included.header().entry().header_wire() != header.header_wire()
                    {
                        return Err(Error::MalformedAtRest(
                            "proof repair canonical inclusion differs",
                        ));
                    }
                    let key = room
                        .history_author_key(&cursor.binding.author)
                        .ok_or(Error::MalformedAtRest("proof repair author key missing"))?;
                    let HistoryStep::Complete(verified) =
                        VerifiedHeader::verify(&header, cursor.binding, &key, &mut work)?
                    else {
                        return Ok(ProofRangeStep::Progress);
                    };
                    match leaf_descriptor(cursor.binding, verified.entry(), &contexts, &mut work)? {
                        HistoryStep::Complete((value, context)) => (range.start, value, context, 0),
                        HistoryStep::MissingContext(_) => return Ok(ProofRangeStep::Missing),
                        _ => return Ok(ProofRangeStep::Progress),
                    }
                }
                Task::Join { start } => {
                    // Children may have been reconstructed in an earlier slice. A newly observed
                    // fork/lifetime state cannot authorize another reconstructed parent.
                    if !reconstruction_allowed {
                        return Ok(ProofRangeStep::Missing);
                    }
                    let n = cursor.values.len();
                    if n < 2 {
                        return Err(Error::MalformedAtRest("proof repair operand stack"));
                    }
                    match join_descriptors(
                        cursor.binding,
                        cursor.values[n - 2],
                        cursor.values[n - 1],
                        &contexts,
                        &mut work,
                    )? {
                        HistoryStep::Complete((value, context)) => (start, value, context, 2),
                        HistoryStep::MissingContext(_) => return Ok(ProofRangeStep::Missing),
                        _ => return Ok(ProofRangeStep::Progress),
                    }
                }
            };
            // The generated context and descriptor are disposable serving material: never a
            // durable row, never part of the acceptance-range namespace (ADR-053 P). The
            // descriptor is that range of the source's branch, so it is cached under the source.
            entry_store::sparse::cache_serving_context(&context);
            entry_store::sparse::cache_history_proof_range(
                cursor.source,
                cursor.binding,
                start,
                descriptor,
            )?;
            // The P guards' mutant: this serving-only state becomes durable rows.
            #[cfg(feature = "test-knobs")]
            if persist_mutant() {
                drop(read);
                room.history_write_tracked(
                    store,
                    &std::sync::atomic::AtomicBool::new(false),
                    |index| {
                        index.keep_history_context(&context)?;
                        index.keep_history_proof_range(
                            cursor.head,
                            cursor.binding,
                            start,
                            descriptor,
                        )
                    },
                )?;
            }
            cursor.tasks.pop();
            cursor.values.truncate(cursor.values.len() - operands);
            if cursor.values.len() == MAX_TREE_DEPTH + 1 {
                return Err(Error::SizeLimitExceeded("proof repair value depth"));
            }
            cursor.values.push(descriptor);
            return Ok(ProofRangeStep::Progress);
        }
    }
}

/// A kept or cached descriptor is reused only while its frontier context is obtainable here,
/// durable or in the serving cache: a join above it reads that context, and an asker that is
/// served it as a proof node asks for it next (`Query::Context`). The serving-context cache
/// evicts on its own, so a descriptor can outlive the context a serving repair generated with
/// it; such a descriptor is treated as absent and rebuilt, which caches its context again.
fn frontier_held(contexts: &impl ContextSource, value: &Descriptor) -> Result<bool> {
    Ok(contexts.context(&value.frontier)?.is_some())
}

/// `VOX_MUTANT_PREFIX_PERSIST=1`: every context and range a serving repair generates is kept
/// as a durable row under the asked head, as if a requested size owned evidence (against
/// ADR-053 P rule 6). Says so once when the daemon first reads it.
#[cfg(feature = "test-knobs")]
fn persist_mutant() -> bool {
    static ON: std::sync::LazyLock<bool> = std::sync::LazyLock::new(|| {
        let on = std::env::var_os("VOX_MUTANT_PREFIX_PERSIST").is_some();
        if on {
            eprintln!("vox: VOX_MUTANT_PREFIX_PERSIST engaged: serving repair writes durable rows");
        }
        on
    });
    *ON
}

/// `VOX_MUTANT_LINKED_OFF=1`: a piece kept under an earlier linked head is never served under
/// the later head (before ADR-053 MP-7). Says so once when the daemon first reads it.
#[cfg(feature = "test-knobs")]
fn linked_mutant() -> bool {
    static ON: std::sync::LazyLock<bool> = std::sync::LazyLock::new(|| {
        let on = std::env::var_os("VOX_MUTANT_LINKED_OFF").is_some();
        if on {
            eprintln!("vox: VOX_MUTANT_LINKED_OFF engaged: no linked proof pieces");
        }
        on
    });
    *ON
}

#[cfg(not(feature = "test-knobs"))]
const fn linked_mutant() -> bool {
    false
}

/// `VOX_TEST_BAD_PREFIX_FILE=<path>` (the ADR-053 P guards): while `<path>` holds `mode`, this
/// holder is a bad provider under a head it never committed. `corrupt`: every inclusion,
/// consistency and control proof it serves under such a head has one descriptor changed. `fork`:
/// it serves under such a head the prefix of its own committed head without comparing roots, as
/// a holder on another fork of the author that answers anyway.
#[cfg(feature = "test-knobs")]
pub(crate) fn bad_prefix(mode: &str) -> bool {
    std::env::var_os("VOX_TEST_BAD_PREFIX_FILE")
        .and_then(|path| std::fs::read_to_string(path).ok())
        .is_some_and(|text| text.trim() == mode)
}

#[cfg(not(feature = "test-knobs"))]
pub(crate) const fn bad_prefix(_mode: &str) -> bool {
    false
}
