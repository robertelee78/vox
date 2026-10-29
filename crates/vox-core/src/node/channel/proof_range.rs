//! Cooperative repair of one proof-serving range from independently committed source metadata.
//! No pending header, payload, missing-body request, or newly computed prefix grants authority.
use super::sparse_history::HistoryAdmissionRoom;
use super::*;
use crate::log::history::{
    join_descriptors, leaf_descriptor, split, Descriptor, HistoryStep, SignedHead, TreeBinding,
    TreeRange, VerifiedHeader, WorkBudget, MAX_CONTEXT_BYTES, MAX_HEADER_BYTES, MAX_TREE_DEPTH,
};

#[derive(Clone)]
enum Task {
    Visit(TreeRange),
    Join { start: u64 },
}
/// Scalar, request-owned DFS; completed children live in the sealed serving cache, so a
/// cancelled/restarted request keeps real progress without a new durable job or scheduler.
pub(crate) struct ProofRangeRestore {
    head: Digest32,
    binding: TreeBinding,
    root: Descriptor,
    requested: TreeRange,
    scope: Option<([u8; 16], u64, u64, u64)>,
    tasks: Vec<Task>,
    values: Vec<Descriptor>,
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
    pub(crate) fn new(head: &SignedHead, start: u64, leaves: u64) -> Result<Self> {
        if start == 0
            || leaves == 0
            || start
                .checked_add(leaves - 1)
                .is_none_or(|end| end > head.root.leaves)
        {
            return Err(Error::MalformedBundle("proof repair range exceeds head"));
        }
        let requested = TreeRange { start, leaves };
        let mut tasks = Vec::with_capacity(2 * MAX_TREE_DEPTH + 1);
        tasks.push(Task::Visit(requested));
        Ok(Self {
            head: head.id(),
            binding: head.binding,
            root: head.root,
            requested,
            scope: None,
            tasks,
            values: Vec::with_capacity(MAX_TREE_DEPTH + 1),
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
        committed: &std::sync::atomic::AtomicBool,
    ) -> Result<ProofRangeStep> {
        self.admission
            .with(|room| ProofRangeRestore::restore(room, store, self.authority, cursor, committed))
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
    /// At most one newly reconstructed node commits per call. Cache/index/context reads and
    /// reconstruction consume the existing WorkBudget; total old-data work can be O(interval).
    fn restore(
        room: &impl HistoryAdmissionRoom,
        store: &Store,
        authority: Option<(u64, u64, u64, bool)>,
        cursor: &mut ProofRangeRestore,
        committed: &std::sync::atomic::AtomicBool,
    ) -> Result<ProofRangeStep> {
        let mut work = WorkBudget::default();
        // Target object, independent commitment and current author/fork state.
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
        let target = read
            .history_head(&cursor.head)?
            .ok_or(Error::MalformedAtRest("proof repair target disappeared"))?;
        if target.binding != cursor.binding || target.root != cursor.root {
            return Err(Error::MalformedAtRest("proof repair target changed"));
        }
        let reconstruction_allowed = read.history_head_committed(&cursor.head, cursor.binding)?
            && !frozen
            && read
                .sparse_author(&cursor.binding.author, cursor.binding.scope)?
                .is_none_or(|state| state.observed_conflict.is_none());
        loop {
            let Some(task) = cursor.tasks.last().cloned() else {
                let [result] = cursor.values.as_slice() else {
                    return Err(Error::MalformedAtRest("proof repair result stack"));
                };
                if result.leaves != cursor.requested.leaves
                    || (cursor.requested.start == 1
                        && result.leaves == cursor.root.leaves
                        && *result != cursor.root)
                {
                    return Err(Error::MalformedAtRest(
                        "proof repair reconstructed root differs",
                    ));
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
                    let found = read
                        .history_range(cursor.binding, range.start, range.leaves)?
                        .or(read.history_proof_range(
                            &cursor.head,
                            cursor.binding,
                            range.start,
                            range.leaves,
                        )?);
                    if let Some(value) = found {
                        if cursor.values.len() == MAX_TREE_DEPTH + 1 {
                            return Err(Error::SizeLimitExceeded("proof repair value depth"));
                        }
                        cursor.tasks.pop();
                        cursor.values.push(value);
                        continue;
                    }
                    // Existing verified serving material may satisfy a local verifier even
                    // before promotion. Only NEW reconstruction requires independently
                    // committed, nonforked target/source roots; no cache is acceptance
                    // evidence. A known fork does not invalidate existing historical math.
                    if !reconstruction_allowed {
                        return Ok(ProofRangeStep::Missing);
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
                    let Some((source, header)) =
                        read.history_validated_header(&cursor.binding.author, range.start)?
                    else {
                        return Ok(ProofRangeStep::Missing);
                    };
                    let source_head = read
                        .history_head(&source)?
                        .ok_or(Error::MalformedAtRest("proof repair source head missing"))?;
                    if source_head.binding != cursor.binding {
                        return Err(Error::MalformedAtRest(
                            "proof repair source binding differs",
                        ));
                    }
                    // A header may have been admitted under an older prefix accepted through
                    // a consistency proof. Without an independent commitment this repair does
                    // not use it as a new tree source; unavailable evidence is not corruption.
                    if !read.history_head_committed(&source, source_head.binding)? {
                        return Ok(ProofRangeStep::Missing);
                    }
                    let included = read
                        .history_inclusion_receipt(&source, &cursor.binding.author, range.start)?
                        .ok_or(Error::MalformedAtRest(
                            "proof repair canonical inclusion missing",
                        ))?;
                    if included.head_id() != source
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
                    match leaf_descriptor(cursor.binding, verified.entry(), &read, &mut work)? {
                        HistoryStep::Complete((value, context)) => (range.start, value, context, 0),
                        HistoryStep::MissingContext(_) => return Ok(ProofRangeStep::Missing),
                        _ => return Ok(ProofRangeStep::Progress),
                    }
                }
                Task::Join { start } => {
                    // Children may have committed in an earlier slice. A newly observed
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
                        &read,
                        &mut work,
                    )? {
                        HistoryStep::Complete((value, context)) => (start, value, context, 2),
                        HistoryStep::MissingContext(_) => return Ok(ProofRangeStep::Missing),
                        _ => return Ok(ProofRangeStep::Progress),
                    }
                }
            };
            drop(read);
            // No scalar progress is installed until both the descriptor and its generated
            // context commit. These objects never populate the acceptance-range namespace.
            room.history_write_tracked(store, committed, |index| {
                index.keep_history_context(&context)?;
                index.keep_history_proof_range(cursor.head, cursor.binding, start, descriptor)
            })?;
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
