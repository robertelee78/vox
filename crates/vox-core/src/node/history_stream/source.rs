//! Bounded disk reads used by one response. No pinned read or room lock crosses network I/O.

use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use tokio::sync::Mutex;
use tokio::time::Instant;

use crate::error::{Error, Result};
use crate::hash::Digest32;
use crate::log::entry::Entry;
use crate::log::history::{
    consistency_ranges, inclusion_ranges, join_descriptors, leaf_descriptor, split,
    ConsistencyProof, ControlRangeProof, ControlToken, Descriptor, HistoryStep, InclusionProof,
    LogScope, SignedHead, WorkBudget, MAX_CONTROL_HEADERS, MAX_PROOF_TOKENS, MAX_TREE_DEPTH,
};
use crate::node::channel::ChannelState;
use crate::node::history_budget::{BufferCharge, Job};
use crate::node::store::Store;
use crate::transport::stream_transport::Fence;

use super::{Proof, ProofKind, RequestId};

pub(super) enum InventoryOffer {
    /// A serving read could not be admitted; no inventory filter callback ran.
    Unavailable,
    ConnectionChanged,
    Offered(super::hints::Offer),
    Publication(crate::node::channel::HistoryPublicationWait),
}

pub(super) enum DeclineResult {
    Publication(crate::node::channel::HistoryPublicationWait),
    Stored {
        remembered: bool,
        captured: Digest32,
        current: Digest32,
    },
    AuthorizationChanged {
        captured: Digest32,
        current: Digest32,
    },
}

#[cfg(feature = "test-knobs")]
pub(super) fn request_text(request: &RequestId) -> String {
    use std::fmt::Write as _;
    let mut text = String::with_capacity(request.len() * 2);
    for byte in request {
        let _ = write!(text, "{byte:02x}");
    }
    text
}

/// Canonical public-identity selectors for the isolated overlap spike only. Unknown legacy
/// decline-file contents retain their prior hold-all behavior at the caller.
#[cfg(feature = "test-knobs")]
pub(super) fn proof_selector<const N: usize>(text: &str, keys: [&str; N]) -> Option<[Digest32; N]> {
    use std::fmt::Write as _;
    let mut words = text.split_whitespace();
    let mut values = [[0; 32]; N];
    let mut canonical = String::new();
    for (index, key) in keys.into_iter().enumerate() {
        let value = words.next()?.strip_prefix(key)?.strip_prefix('=')?;
        let digest = crate::node::link::b32_decode(value, "publication proof selector").ok()?;
        if crate::node::link::b32_encode(&digest) != value {
            return None;
        }
        if index != 0 {
            canonical.push(' ');
        }
        write!(&mut canonical, "{key}={value}").ok()?;
        values[index] = digest;
    }
    canonical.push('\n');
    (words.next().is_none() && text == canonical).then_some(values)
}

// Directory plaintext is capped at 1 MiB before copy/decrypt. This also covers its sealed
// bytes and bounded decoded author/presence maps. It is temporary, not part of Held's output.
const DIRECTORY_ENVELOPE: usize = 4 * 1024 * 1024;

/// The charge follows both the blocking read and the returned allocation. Cancelling an async
/// caller cannot release memory credit while an already running disk read still owns buffers.
pub(super) struct Held<T> {
    pub(super) value: T,
    _charge: BufferCharge,
}

pub(super) struct InventoryPayload {
    pub(super) hints: Vec<super::HeadHint>,
    pub(super) snapshot: super::AnnouncementSnapshot,
}

impl<T> Held<T> {
    pub(super) fn job(&self) -> Job {
        self._charge.job()
    }
}

pub(super) enum Lookup<T> {
    Found(Held<T>),
    Busy,
    Missing,
}

/// Capacity for an exact read, reserved before the durable operation it must follow. It owns
/// no room lock or store snapshot; the actual read still checks current lifecycle and authority.
pub(super) struct PreparedRead {
    charge: BufferCharge,
    scratch: BufferCharge,
}

#[derive(Clone, Copy)]
enum RangeTask {
    Visit {
        start: u64,
        leaves: u64,
    },
    Join {
        start: u64,
        left: Descriptor,
        right: Descriptor,
    },
}
enum RangeStep {
    Found(Descriptor),
    Split,
    Busy,
}

#[derive(Clone, Copy)]
enum ReadBoundary {
    Observing,
    Committed,
}

#[derive(Clone)]
pub(super) struct Source {
    pub(super) room: Arc<Mutex<ChannelState>>,
    pub(super) store: Arc<Store>,
    pub(super) epoch: u64,
    pub(super) peer: Digest32,
    pub(super) fence: Arc<Fence>,
    pub(super) deadline: Instant,
    /// The exact authorization grant captured by a client flow. A server source has no client
    /// grant and cannot persist a refusal. The refusal transaction rechecks this pair in its
    /// own store batch instead of relabeling an old flow with a later grant.
    authorization: Option<(Digest32, Digest32)>,
    // Only a server clone bound to Control/Head(peer) may return a departed peer receipt.
    own_head_receipt: bool,
    connection: Option<u64>,
    work_committed: Arc<AtomicBool>,
    #[cfg(feature = "test-knobs")]
    pub(super) proof_hold_elapsed: Arc<std::sync::Mutex<std::time::Duration>>,
}

impl Source {
    #[cfg(feature = "test-knobs")]
    async fn hold_decline_for_proof(&self, author: Digest32, head: Digest32, request: RequestId) {
        const VARIABLE: &str = "VOX_TEST_HOLD_HISTORY_DECLINE_FILE";
        let Some(path) = std::env::var_os(VARIABLE) else {
            return;
        };
        if !std::path::Path::new(&path).exists() {
            return;
        }
        let selector = match std::fs::read_to_string(&path) {
            Ok(selector) => selector,
            Err(error) => {
                eprintln!("APPARATUS: could not read decline hold selector: {error}");
                return;
            }
        };
        if let Some([peer, selected_author]) = proof_selector(&selector, ["peer", "author"]) {
            if peer != self.peer || selected_author != author {
                return;
            }
        }
        // Empty and all unrecognized legacy contents still hold every real refusal.
        let entered =
            std::path::PathBuf::from(format!("{}.entered", std::path::Path::new(&path).display()));
        let Some((_, captured)) = self.authorization else {
            return;
        };
        let identity = format!(
            "peer={} author={} head={} request={} captured={}\n",
            crate::node::link::b32_encode(&self.peer),
            crate::node::link::b32_encode(&author),
            crate::node::link::b32_encode(&head),
            request_text(&request),
            crate::node::link::b32_encode(&captured),
        );
        let temporary = std::path::PathBuf::from(format!(
            "{}.tmp-{}-{}",
            entered.display(),
            std::process::id(),
            request_text(&request)
        ));
        if let Err(error) = std::fs::write(&temporary, identity)
            .and_then(|()| std::fs::rename(&temporary, &entered))
        {
            let _ = std::fs::remove_file(&temporary);
            eprintln!("APPARATUS: could not publish decline hold marker: {error}");
            return;
        }
        let mut held_from = None;
        while std::path::Path::new(&path).exists() {
            held_from.get_or_insert_with(Instant::now);
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        if let Some(started) = held_from {
            *self
                .proof_hold_elapsed
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) += started.elapsed();
        }
        let _ = std::fs::remove_file(entered);
    }

    #[cfg(not(feature = "test-knobs"))]
    async fn hold_decline_for_proof(
        &self,
        _author: Digest32,
        _head: Digest32,
        _request: RequestId,
    ) {
    }

    /// Durably remember that this exact source refused this author's advertised head before the
    /// live flow treats the refusal as complete. A restart reconstructs the inbox from it.
    pub(super) async fn remember_decline(
        &self,
        job: &Job,
        author: Digest32,
        head: Digest32,
        request: RequestId,
    ) -> Result<DeclineResult> {
        // The marker is apparatus only: it proves that a real shipped flow carrying its captured
        // authorization has reached the durability edge before a proof changes trust.
        self.hold_decline_for_proof(author, head, request).await;
        let peer = self.peer;
        let authorization = self.authorization.ok_or(Error::Unreachable(
            "history refusal has no captured authorization",
        ))?;
        let committed = Arc::clone(&self.work_committed);
        match self
            .read_charged(job, 0, 0, move |room, store| {
                Ok(Some(room.remember_history_decline(
                    store,
                    peer,
                    author,
                    head,
                    authorization,
                    &committed,
                )?))
            })
            .await?
        {
            Lookup::Found(saved) => match saved.value {
                crate::node::channel::HistoryDeclineResult::Publication(wait) => {
                    Ok(DeclineResult::Publication(wait))
                }
                crate::node::channel::HistoryDeclineResult::Stored {
                    remembered,
                    current,
                } => Ok(DeclineResult::Stored {
                    remembered,
                    captured: authorization.1,
                    current,
                }),
                crate::node::channel::HistoryDeclineResult::AuthorizationChanged { current } => {
                    Ok(DeclineResult::AuthorizationChanged {
                        captured: authorization.1,
                        current,
                    })
                }
            },
            Lookup::Busy | Lookup::Missing => {
                Err(Error::Unreachable("history refusal was not persisted"))
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        room: Arc<Mutex<ChannelState>>,
        store: Arc<Store>,
        epoch: u64,
        peer: Digest32,
        fence: Arc<Fence>,
        deadline: Instant,
        authorization: Option<(Digest32, Digest32)>,
        work_committed: Arc<AtomicBool>,
    ) -> Self {
        Self {
            room,
            store,
            epoch,
            peer,
            fence,
            deadline,
            authorization,
            own_head_receipt: false,
            connection: None,
            work_committed,
            #[cfg(feature = "test-knobs")]
            proof_hold_elapsed: Arc::new(std::sync::Mutex::new(std::time::Duration::ZERO)),
        }
    }

    pub(super) fn on_connection(mut self, serial: u64) -> Self {
        self.connection = Some(serial);
        self
    }

    /// Record user-visible history work at the commit edge, independently of whether the
    /// surrounding exchange is later cancelled, superseded, retired or rejected.
    pub(super) fn note_work_committed(&self) {
        self.work_committed.store(true, Ordering::Release);
    }

    pub(super) fn commit_ledger(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.work_committed)
    }

    pub(super) fn for_own_head_receipt(&self) -> Self {
        let mut source = self.clone();
        source.own_head_receipt = true;
        source
    }

    fn current(&self) -> Result<()> {
        self.current_at(ReadBoundary::Observing)
    }

    fn current_at(&self, boundary: ReadBoundary) -> Result<()> {
        if self.fence.is_retired() {
            return Err(Error::Unreachable("history request cancelled"));
        }
        #[cfg(not(feature = "test-knobs"))]
        let deadline = self.deadline;
        #[cfg(feature = "test-knobs")]
        let deadline = self.deadline
            + *self
                .proof_hold_elapsed
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        if matches!(boundary, ReadBoundary::Observing) && Instant::now() >= deadline {
            return Err(Error::Unreachable("history request deadline elapsed"));
        }
        Ok(())
    }

    /// Reserve the returned allocation separately from transient index decoding.
    pub(super) async fn read<T, F>(&self, job: &Job, envelope: usize, read: F) -> Result<Lookup<T>>
    where
        T: Send + 'static,
        F: FnOnce(&mut ChannelState, &Store) -> Result<Option<T>> + Send + 'static,
    {
        self.read_charged(job, envelope, DIRECTORY_ENVELOPE, read)
            .await
    }

    /// A body envelope includes directory decoding and temporary ciphertext/plaintext copies.
    /// Retain only the returned allocation after decoding; keeping the now-unused copies'
    /// reservation would prevent a cohosted receiver from accepting the signed header.
    pub(super) async fn read_body<T, F>(
        &self,
        job: &Job,
        envelope: usize,
        retained: usize,
        read: F,
    ) -> Result<Lookup<T>>
    where
        T: Send + 'static,
        F: FnOnce(&mut ChannelState, &Store) -> Result<Option<T>> + Send + 'static,
    {
        let temporary = envelope
            .checked_sub(retained)
            .filter(|temporary| *temporary >= DIRECTORY_ENVELOPE)
            .ok_or(Error::SizeLimitExceeded("history body envelope"))?;
        self.read_charged(job, retained, temporary, read).await
    }

    /// Reuse a working envelope already owned by an assembled record. The owned guard must
    /// include directory decoding and every temporary allocation the callback performs; only
    /// its returned value receives a new charge. Moving the guard into the blocking closure
    /// keeps that existing reservation alive even when the async waiter is cancelled. The
    /// returned value retains the guard as well, including during later actor handoffs.
    pub(super) async fn read_precharged<T, G, F>(
        &self,
        job: &Job,
        envelope: usize,
        guard: Arc<G>,
        read: F,
    ) -> Result<Lookup<(Arc<G>, T)>>
    where
        T: Send + 'static,
        G: Send + Sync + 'static,
        F: FnOnce(&mut ChannelState, &Store, &G) -> Result<Option<T>> + Send + 'static,
    {
        self.read_charged(job, envelope, 0, move |room, store| {
            let value = read(room, store, &guard)?;
            Ok(value.map(|value| (guard, value)))
        })
        .await
    }

    /// Pre-admit the exact authority-read envelope before a body append can commit. This
    /// does no read and confers no authority; read_committed still checks the live room/grant.
    pub(super) async fn prepare_committed_read(&self, job: &Job) -> Result<Option<PreparedRead>> {
        self.current()?;
        self.reserve_read(job, 0, DIRECTORY_ENVELOPE).await
    }

    pub(super) async fn read_committed<T, F>(
        &self,
        admission: PreparedRead,
        read: F,
    ) -> Result<Lookup<T>>
    where
        T: Send + 'static,
        F: FnOnce(&mut ChannelState, &Store) -> Result<Option<T>> + Send + 'static,
    {
        self.read_reserved(admission, ReadBoundary::Committed, read)
            .await
    }

    async fn reserve_read(
        &self,
        job: &Job,
        envelope: usize,
        temporary: usize,
    ) -> Result<Option<PreparedRead>> {
        let work_envelope = envelope
            .checked_add(temporary)
            .ok_or(Error::SizeLimitExceeded("history read envelope"))?;
        let Some(work_job) = job.record_job(work_envelope).await else {
            return Ok(None);
        };
        let mut scratch = work_job.reserve_or_pressure(work_envelope)?;
        let charge = scratch
            .split_off(envelope)
            .ok_or(Error::Profile("history read reservation changed"))?;
        Ok(Some(PreparedRead { charge, scratch }))
    }

    async fn read_charged<T, F>(
        &self,
        job: &Job,
        envelope: usize,
        temporary: usize,
        read: F,
    ) -> Result<Lookup<T>>
    where
        T: Send + 'static,
        F: FnOnce(&mut ChannelState, &Store) -> Result<Option<T>> + Send + 'static,
    {
        self.current()?;
        let admission = match self.reserve_read(job, envelope, temporary).await {
            Ok(Some(admission)) => admission,
            Ok(None) => return Ok(Lookup::Busy),
            // A serving stream retains its wire Busy outcome; an owned client Flow retains
            // its exact local continuation behind the typed capacity dependency.
            Err(Error::HistoryCapacity(_)) if self.authorization.is_none() => {
                return Ok(Lookup::Busy);
            }
            Err(error) => return Err(error),
        };
        self.read_reserved(admission, ReadBoundary::Observing, read)
            .await
    }

    async fn read_reserved<T, F>(
        &self,
        admission: PreparedRead,
        boundary: ReadBoundary,
        read: F,
    ) -> Result<Lookup<T>>
    where
        T: Send + 'static,
        F: FnOnce(&mut ChannelState, &Store) -> Result<Option<T>> + Send + 'static,
    {
        self.current_at(boundary)?;
        let PreparedRead { charge, scratch } = admission;
        // A round deadline may end wire work, but it cannot make a queued local room step fail.
        // The mutex release is the causal wake for this bounded operation; wall-clock expiry is
        // neither evidence that the room is wedged nor permission to abandon a publication that
        // this request may already own. Cancellation remains exact through the attempt fence.
        let room = tokio::select! {
            biased;
            () = self.fence.retired() => return Err(Error::Unreachable("history request cancelled")),
            room = self.room.clone().lock_owned() => room,
        };
        self.current_at(boundary)?;
        let source = self.clone();
        // Once dispatched, the closure owns both charges and the room guard. Dropping the
        // async waiter detaches it; credit cannot be reused while the disk read still runs.
        let task = tokio::task::spawn_blocking(move || {
            let _notify = super::ObservationAfterUnlock(room.history_observation_signal());
            // Local declaration order makes the room guard drop before _notify, including
            // a callback error or unwind after its durable commit.
            let mut room = room;
            source.current_at(boundary)?;
            let departed_receipt = source.own_head_receipt
                && room.is_author(&source.peer)
                && room.has_left(&source.peer);
            if room.epoch() != source.epoch || (!room.is_member(&source.peer) && !departed_receipt)
            {
                return Err(Error::Unreachable("history room access changed"));
            }
            let value = read(&mut room, &source.store)?;
            // Do not turn a completed callback into cancellation after it may have committed.
            // The actor validates the returned Flow against its current port/fence and accounts
            // the shared commit edge before disposing a stale result.
            drop(scratch);
            Ok(match value {
                Some(value) => Lookup::Found(Held {
                    value,
                    _charge: charge,
                }),
                None => Lookup::Missing,
            })
        });
        // Once dispatched, await actual worker exit even after cancellation. The caller may
        // own an outbound slot in addition to the charges held by this closure; returning early
        // would free that slot while its blocking disk work still ran. No actor waits here.
        let result = task
            .await
            .map_err(|_| Error::Unreachable("history disk reader stopped"))?;
        // For the same reason, return the worker's exact outcome after join instead of replacing
        // it with a later fence/deadline observation.
        result
    }

    pub(super) async fn authorize(&self, job: &Job) -> Result<bool> {
        Ok(matches!(
            self.read_charged(job, 0, 0, |_, _| Ok(Some(()))).await?,
            Lookup::Found(_)
        ))
    }

    async fn range(
        &self,
        job: &Job,
        head: &SignedHead,
        start: u64,
        leaves: u64,
    ) -> Result<Lookup<Descriptor>> {
        // An old completed receipt may have discarded its proof nodes. Reconstruct only
        // missing canonical metadata from accepted indexed positions, never bodies. Each
        // completed child is durably memoized, so an existing wire deadline/cancellation
        // cannot force a later attempt to redo an arbitrarily large subtree from scratch.
        let task_capacity = 2 * MAX_TREE_DEPTH + 1;
        let value_capacity = MAX_TREE_DEPTH + 1;
        let cursor_bytes = task_capacity * std::mem::size_of::<RangeTask>()
            + value_capacity * std::mem::size_of::<Descriptor>()
            + crate::log::history::MAX_HEADER_BYTES;
        let _cursor_charge = match job.reserve_or_pressure(cursor_bytes) {
            Ok(charge) => charge,
            Err(Error::HistoryCapacity(_)) if self.authorization.is_none() => {
                return Ok(Lookup::Busy);
            }
            Err(error) => return Err(error),
        };
        let mut tasks = Vec::with_capacity(task_capacity);
        let mut values = Vec::with_capacity(value_capacity);
        tasks.push(RangeTask::Visit { start, leaves });
        while let Some(task) = tasks.last().copied() {
            self.current()?;
            let target = head.clone();
            let source = self.clone();
            let step = self
                .read(job, 64 * 1024, move |room, store| {
                    use crate::node::channel::entry_store::sparse::RangeMemo;
                    let input = room.history_read(store)?;
                    let binding = target.binding;
                    let (at, length) = match task {
                        RangeTask::Visit { start, leaves } => (start, leaves),
                        RangeTask::Join { start, left, right } => (
                            start,
                            left.leaves
                                .checked_add(right.leaves)
                                .ok_or(Error::SizeLimitExceeded("derived range length"))?,
                        ),
                    };
                    if let Some(descriptor) = input.history_range(binding, at, length)? {
                        return Ok(Some(RangeStep::Found(descriptor)));
                    }
                    if room.is_poisoned() || room.history_retirement_locked() {
                        return Err(Error::Profile("history range room is unavailable"));
                    }
                    if room.history_publication_busy(store)? {
                        return Ok(Some(RangeStep::Busy));
                    }
                    if binding.scope != LogScope::Public
                        || !input.history_head_accepted(&target.id(), binding)?
                    {
                        return Ok(None);
                    }
                    if input
                        .sparse_author(&binding.author, binding.scope)?
                        .is_some_and(|state| state.observed_conflict.is_some())
                    {
                        return Err(Error::MalformedBundle(
                            "history range author has conflicting heads",
                        ));
                    }
                    // Exactly one leaf/join primitive per guarded slice. WorkBudget is NEVER
                    // replenished under this guard; exhausted work returns Busy, not absence.
                    let mut work = WorkBudget::default();
                    let built = match task {
                        RangeTask::Visit { leaves, .. } if leaves > 1 => {
                            return Ok(Some(RangeStep::Split));
                        }
                        RangeTask::Visit { start, .. } => {
                            let Some((source_head, header)) =
                                input.history_validated_header(&binding.author, start)?
                            else {
                                return Ok(None);
                            };
                            if header.skeleton.seq != start
                                || !input.history_head_accepted(&source_head, binding)?
                            {
                                return Ok(None);
                            }
                            binding.matches_entry(&header)?;
                            leaf_descriptor(binding, &header, &input, &mut work)?
                        }
                        RangeTask::Join { left, right, .. } => {
                            join_descriptors(binding, left, right, &input, &mut work)?
                        }
                    };
                    let (descriptor, context) = match built {
                        HistoryStep::Complete(value) => value,
                        HistoryStep::MissingContext(_) => return Ok(None),
                        HistoryStep::Yielded | HistoryStep::Progress(_) => {
                            return Ok(Some(RangeStep::Busy))
                        }
                    };
                    if descriptor.leaves != length {
                        return Err(Error::MalformedAtRest("derived range length differs"));
                    }
                    let node = room.me();
                    let instance = room.history_instance(store)?;
                    let epoch = room.epoch();
                    let generation = super::authorization_generation(
                        store,
                        node,
                        binding.room,
                        instance,
                        epoch,
                    )?;
                    if source.authorization.is_some_and(|(expected, captured)| {
                        expected != node || captured != generation
                    }) {
                        return Err(Error::Profile("history range authorization changed"));
                    }
                    drop(input);
                    source.current()?;
                    room.history_write_tracked(store, &source.work_committed, |index| {
                        index.keep_derived_history_range(RangeMemo {
                            node,
                            instance,
                            epoch,
                            generation,
                            binding,
                            start: at,
                            descriptor,
                            context,
                        })
                    })?;
                    Ok(Some(RangeStep::Found(descriptor)))
                })
                .await?;
            let held = match step {
                Lookup::Found(held) => held,
                Lookup::Busy => return Ok(Lookup::Busy),
                Lookup::Missing => return Ok(Lookup::Missing),
            };
            match held.value {
                RangeStep::Busy => return Ok(Lookup::Busy),
                RangeStep::Split => {
                    let RangeTask::Visit { start, leaves } = task else {
                        return Err(Error::MalformedAtRest("range join cannot split"));
                    };
                    let left = split(leaves)?;
                    if tasks.len().saturating_add(2) > task_capacity {
                        return Err(Error::SizeLimitExceeded("history range task depth"));
                    }
                    tasks.pop();
                    // Join's scalar operands are installed after its two children finish.
                    tasks.push(RangeTask::Join {
                        start,
                        left: Descriptor::empty(head.binding),
                        right: Descriptor::empty(head.binding),
                    });
                    tasks.push(RangeTask::Visit {
                        start: start + left,
                        leaves: leaves - left,
                    });
                    tasks.push(RangeTask::Visit {
                        start,
                        leaves: left,
                    });
                }
                RangeStep::Found(descriptor) => {
                    tasks.pop();
                    if values.len() == value_capacity {
                        return Err(Error::SizeLimitExceeded("history range value depth"));
                    }
                    values.push(descriptor);
                    if tasks.is_empty() {
                        if values.len() != 1 {
                            return Err(Error::MalformedAtRest("history range extra operands"));
                        }
                        return Ok(Lookup::Found(Held {
                            value: descriptor,
                            _charge: held._charge,
                        }));
                    }
                }
            }
            // Once both child visits have returned, bind this exact canonical join.
            if let Some(RangeTask::Join { left, right, .. }) = tasks.last_mut() {
                if left.leaves == 0 && right.leaves == 0 && values.len() >= 2 {
                    let n = values.len();
                    *left = values[n - 2];
                    *right = values[n - 1];
                    values.truncate(n - 2);
                }
            }
            if tasks.len() > task_capacity || values.len() > value_capacity {
                return Err(Error::SizeLimitExceeded(
                    "history range reconstruction depth",
                ));
            }
            // No room guard, pinned read, context map or batch survives this yield. The
            // scalar cursor remains prepaid by THIS Source Job; no second owner is queued.
            self.current()?;
            tokio::task::yield_now().await;
        }
        Err(Error::MalformedAtRest(
            "history range reconstruction ended without root",
        ))
    }

    /// Proof construction uses indexed ranges or bounded, memoized authenticated header
    /// reconstruction for earlier receipts. It never scans or fetches content bodies. The
    /// response owns the output envelope and each disk reader separately owns its temporary
    /// envelope. Verification and authority still belong to the receiving admission path.
    pub(super) async fn proof(
        &self,
        job: &Job,
        head: &SignedHead,
        kind: ProofKind,
        from: u64,
        to: u64,
    ) -> Result<Lookup<Proof>> {
        self.current()?;
        let Some(charge) = job.reserve(1024 * 1024) else {
            return Ok(Lookup::Busy);
        };
        if to > head.root.leaves {
            return Err(Error::MalformedBundle("proof exceeds requested head"));
        }
        let proof = if kind == ProofKind::Control {
            return self.control_proof(job, head, from, to, charge).await;
        } else {
            let ranges = match kind {
                ProofKind::Inclusion => {
                    if from != to {
                        return Err(Error::MalformedBundle("inclusion position differs"));
                    }
                    inclusion_ranges(from, head.root.leaves)?
                }
                ProofKind::Consistency => consistency_ranges(from, to)?,
                ProofKind::Control => unreachable!(),
            };
            // A consistency answer always names this exact head, not an arbitrary earlier
            // size chosen by the server under the same HeadID.
            if kind == ProofKind::Consistency && to != head.root.leaves {
                return Err(Error::MalformedBundle(
                    "consistency target differs from head",
                ));
            }
            let mut descriptors = Vec::with_capacity(ranges.len());
            for range in ranges {
                self.current()?;
                match self.range(job, head, range.start, range.leaves).await? {
                    Lookup::Found(found) => descriptors.push(found.value),
                    Lookup::Busy => return Ok(Lookup::Busy),
                    Lookup::Missing => return Ok(Lookup::Missing),
                }
                // No room lock or store snapshot survives even one descriptor lookup.
                tokio::task::yield_now().await;
            }
            match kind {
                ProofKind::Inclusion => Proof::Inclusion(InclusionProof {
                    position: from,
                    size: head.root.leaves,
                    siblings: descriptors,
                }),
                ProofKind::Consistency => {
                    let prefix = if from == 0 {
                        Descriptor::empty(head.binding)
                    } else {
                        match self.range(job, head, 1, from).await? {
                            Lookup::Found(found) => found.value,
                            Lookup::Busy => return Ok(Lookup::Busy),
                            Lookup::Missing => return Ok(Lookup::Missing),
                        }
                    };
                    Proof::Consistency {
                        prefix,
                        proof: ConsistencyProof {
                            from,
                            to,
                            nodes: descriptors,
                        },
                    }
                }
                ProofKind::Control => unreachable!(),
            }
        };
        self.current()?;
        Ok(Lookup::Found(Held {
            value: proof,
            _charge: charge,
        }))
    }

    async fn control_proof(
        &self,
        job: &Job,
        head: &SignedHead,
        lo: u64,
        mut hi: u64,
        charge: BufferCharge,
    ) -> Result<Lookup<Proof>> {
        if lo == 0 || lo > hi || hi > head.root.leaves {
            return Err(Error::MalformedBundle("control interval differs from head"));
        }
        let tokens = 'interval: loop {
            let mut pending = vec![(1u64, head.root.leaves)];
            let mut tokens = Vec::new();
            let mut headers = 0;
            while let Some((start, leaves)) = pending.pop() {
                self.current()?;
                if pending.len() > MAX_TREE_DEPTH || tokens.len() >= MAX_PROOF_TOKENS {
                    return Err(Error::SizeLimitExceeded("served control proof"));
                }
                let descriptor = match self.range(job, head, start, leaves).await? {
                    Lookup::Found(found) => found.value,
                    Lookup::Busy => return Ok(Lookup::Busy),
                    Lookup::Missing => return Ok(Lookup::Missing),
                };
                if descriptor.leaves != leaves {
                    return Err(Error::MalformedAtRest("history range size differs"));
                }
                let end = start
                    .checked_add(leaves - 1)
                    .ok_or(Error::MalformedAtRest("history range overflow"))?;
                if end < lo || start > hi || descriptor.controls == 0 {
                    tokens.push(ControlToken::Collapse(descriptor));
                } else if leaves == 1 {
                    if headers == MAX_CONTROL_HEADERS {
                        // Branch tokens already emitted for the larger interval are not valid
                        // after narrowing it. Rebuild once from the final interval so every
                        // range outside it is represented canonically by one collapse token.
                        hi = start - 1;
                        self.current()?;
                        tokio::task::yield_now().await;
                        continue 'interval;
                    }
                    let author = head.binding.author;
                    let found = self
                        .read(job, 128 * 1024, move |room, store| {
                            room.history_header(store, &author, start)?
                                .map(|header| Entry::from_wire(&header.wire))
                                .transpose()
                        })
                        .await?;
                    match found {
                        Lookup::Found(found) => {
                            tokens.push(ControlToken::Leaf(Box::new(found.value)));
                            headers += 1;
                        }
                        Lookup::Busy => return Ok(Lookup::Busy),
                        Lookup::Missing => return Ok(Lookup::Missing),
                    }
                } else {
                    let left = split(leaves)?;
                    tokens.push(ControlToken::Branch);
                    pending.push((start + left, leaves - left));
                    pending.push((start, left));
                }
                tokio::task::yield_now().await;
            }
            break tokens;
        };
        self.current()?;
        Ok(Lookup::Found(Held {
            value: Proof::Control(ControlRangeProof {
                head_id: head.id(),
                lo,
                hi,
                tokens,
            }),
            _charge: charge,
        }))
    }
}

impl Source {
    /// One bounded, charged scalar inventory. Every page rechecks current room access;
    /// the compact index is read without touching content bodies or walking the archive.
    pub(super) async fn inventory(&self, job: &Job) -> Result<Lookup<InventoryPayload>> {
        let output_envelope = crate::log::history::MAX_CONTEXT_AUTHORS
            .checked_mul(std::mem::size_of::<super::HeadHint>())
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<super::AnnouncementSnapshot>()))
            .ok_or(Error::SizeLimitExceeded("inventory output envelope"))?;
        let charge = job.reserve_or_pressure(output_envelope)?;
        let mut hints = Vec::with_capacity(crate::log::history::MAX_CONTEXT_AUTHORS);
        let mut after = None;
        let mut complete = false;
        for _ in 0..=crate::log::history::MAX_CONTEXT_AUTHORS / 64 {
            self.current()?;
            let page = self
                .read(job, 64 * 1024, move |room, store| {
                    room.history_head_hints(store, after).map(Some)
                })
                .await?;
            let Lookup::Found(page) = page else {
                return Ok(Lookup::Busy);
            };
            if hints.len() + page.value.heads.len() > crate::log::history::MAX_CONTEXT_AUTHORS {
                return Err(Error::SizeLimitExceeded("inventory author bound"));
            }
            hints.extend(page.value.heads.iter().map(|hint| super::HeadHint {
                author: hint.author,
                size: hint.leaves,
                head: hint.head,
            }));
            match page.value.next {
                Some(next) if after.is_none_or(|previous| next > previous) => after = Some(next),
                None => {
                    complete = true;
                    break;
                }
                _ => return Err(Error::MalformedAtRest("inventory cursor did not advance")),
            }
        }
        if !complete {
            return Err(Error::SizeLimitExceeded("inventory index slice bound"));
        }
        // Ordinary gossip keeps its existing bounded pages. The two author facts used by
        // the announcement ledger and sidecar come from ONE final pinned index view.
        let peer = self.peer;
        let captured_authorization = self.authorization;
        let captured = self
            .read(job, 128 * 1024, move |room, store| {
                if let Some((node, expected)) = captured_authorization {
                    let current = super::authorization_generation(
                        store,
                        room.me(),
                        room.channel_id(),
                        room.history_instance(store)?,
                        room.epoch(),
                    )?;
                    if node != room.me() || expected != current {
                        return Err(Error::Profile("history authorization changed"));
                    }
                }
                Ok(Some((
                    room.me(),
                    room.history_inventory_snapshot(store, &peer)?,
                )))
            })
            .await?;
        let Lookup::Found(captured) = captured else {
            return Ok(Lookup::Busy);
        };
        let (node, snapshot) = captured.value;
        drop(captured);
        set_inventory_head(&mut hints, node, snapshot.own_head)?;
        set_inventory_head(&mut hints, peer, snapshot.peer.known_head)?;
        self.current()?;
        Ok(Lookup::Found(Held {
            value: InventoryPayload { hints, snapshot },
            _charge: charge,
        }))
    }

    /// One mandatory requester-specific scalar, independent of the ordinary author slices.
    /// It supplies a scheduling fact only; no inventory field applies a role receipt.
    pub(super) async fn offer_observation(
        &self,
        job: &Job,
        inbox: &Arc<super::HintInbox>,
        generation: u64,
        room_id: Digest32,
        observation: super::OwnObservation,
    ) -> Result<InventoryOffer> {
        let peer = self.peer;
        let captured_authorization = self.authorization;
        let connection = self
            .connection
            .ok_or(Error::Profile("inventory observation connection missing"))?;
        let inbox = Arc::clone(inbox);
        let offer_job = job.clone();
        let envelope = 128 * 1024
            + std::mem::size_of::<super::OwnProbeContext>()
            + std::mem::size_of::<super::OwnObservation>();
        let offered = self
            .read(job, envelope, move |room, store| {
                if room.channel_id() != room_id {
                    return Err(Error::MalformedBundle("inventory observation room binding"));
                }
                let instance = room.history_instance(store)?;
                let authorization = super::authorization_generation(
                    store,
                    room.me(),
                    room_id,
                    instance,
                    room.epoch(),
                )?;
                if captured_authorization
                    .is_some_and(|(node, expected)| node != room.me() || expected != authorization)
                {
                    return Err(Error::Profile("history authorization changed"));
                }
                if room.history_publication_busy(store)? {
                    return Ok(Some(InventoryOffer::Publication(
                        crate::node::channel::HistoryPublicationWait {
                            owner: room.history_publication_request(store)?,
                            wake: room.history_publication_wake(),
                        },
                    )));
                }
                let context = super::OwnProbeContext {
                    node: room.me(),
                    instance,
                    epoch: room.epoch(),
                    authorization,
                    connection,
                };
                let local = room
                    .history_head(store, &room.me())?
                    .map(|head| super::HeadHint {
                        author: head.binding.author,
                        head: head.id(),
                        size: head.root.leaves,
                    });
                let observation = match inbox.peer_observation(room_id, peer, generation, context) {
                    Some(retained)
                        if room.history_observation_dominates(store, retained, observation)? =>
                    {
                        retained
                    }
                    _ => observation,
                };
                let offer = match inbox.offer_peer_observation(
                    &offer_job,
                    generation,
                    room_id,
                    peer,
                    context,
                    local,
                    observation,
                ) {
                    Err(Error::Profile(super::hints::OWN_PROBE_CONNECTION_CHANGED)) => {
                        return Ok(Some(InventoryOffer::ConnectionChanged));
                    }
                    result => result?,
                };
                Ok(Some(InventoryOffer::Offered(offer)))
            })
            .await?;
        match offered {
            Lookup::Found(offered) => Ok(offered.value),
            Lookup::Busy | Lookup::Missing if self.authorization.is_none() => {
                Ok(InventoryOffer::Unavailable)
            }
            Lookup::Busy | Lookup::Missing => Err(Error::Profile(
                "owned inventory observation was not admitted",
            )),
        }
    }

    /// Filter at most 64 already decoded hints using exact accepted/settled local facts.
    /// A completed terminal control is not receipt of the content before it. Keep hints
    /// eligible until their selected newest window is visited and has no missing positions.
    /// A peer's BodyNotHeld is not a global absence verdict: a later hint may retry those
    /// positions from another peer without rewinding the main cursor or draining older history.
    /// The caller holds the original HAVE's decode charge and preserves this inbox generation.
    pub(super) async fn offer_inventory(
        &self,
        job: &Job,
        inbox: &Arc<super::HintInbox>,
        generation: u64,
        room_id: Digest32,
        hints: &[super::HeadHint],
    ) -> Result<InventoryOffer> {
        if hints.len() > 64 {
            return Err(Error::SizeLimitExceeded("inventory filter slice"));
        }
        // Input copy and returned vector coexist inside this small prepaid envelope.
        let input_charge =
            match job.reserve_or_pressure(64 * std::mem::size_of::<super::HeadHint>()) {
                Ok(charge) => charge,
                Err(Error::HistoryCapacity(_)) if self.authorization.is_none() => {
                    return Ok(InventoryOffer::Unavailable);
                }
                Err(error) => return Err(error),
            };
        let peer = self.peer;
        let captured_authorization = self.authorization;
        let connection = self
            .connection
            .ok_or(Error::Profile("inventory connection scope missing"))?;
        let slice = hints.to_vec();
        let committed = Arc::clone(&self.work_committed);
        let inbox = Arc::clone(inbox);
        let offer_job = job.clone();
        let output_envelope = 64
            * (std::mem::size_of::<super::HeadHint>()
                + std::mem::size_of::<(Digest32, Digest32)>()
                + std::mem::size_of::<Digest32>())
            + std::mem::size_of::<usize>()
            + std::mem::size_of::<super::OwnProbeContext>()
            + std::mem::size_of::<Option<super::HeadHint>>();
        let filtered = self
            .read(job, output_envelope, move |room, store| {
                let _input_charge = input_charge;
                if room.channel_id() != room_id {
                    return Err(Error::MalformedBundle("inventory room binding"));
                }
                let current_authorization = super::authorization_generation(
                    store,
                    room.me(),
                    room_id,
                    room.history_instance(store)?,
                    room.epoch(),
                )?;
                if captured_authorization.is_some_and(|(node, generation)| {
                    node != room.me() || generation != current_authorization
                }) {
                    return Err(Error::Profile("history authorization changed"));
                }
                let context = super::OwnProbeContext {
                    node: room.me(),
                    instance: room.history_instance(store)?,
                    epoch: room.epoch(),
                    authorization: current_authorization,
                    connection,
                };
                let local = room
                    .history_head(store, &room.me())?
                    .map(|head| super::HeadHint {
                        author: head.binding.author,
                        head: head.id(),
                        size: head.root.leaves,
                    });
                let publication_wake = room.history_publication_wake();
                let read = room.history_read(store)?;
                let mut missing = Vec::with_capacity(slice.len());
                let mut changed = Vec::new();
                for hint in slice {
                    if hint.author == room.me() {
                        // V3's mandatory sidecar is the sole own-author advertisement.
                        // Replaying its ordinary alias here would invalidate the same
                        // canonical facts twice, depending on author-slice scheduling.
                        continue;
                    }
                    if let Some((declined, authorization, peer_incarnation, author_incarnation)) =
                        read.history_declined_head(&peer, &hint.author)?
                    {
                        let current = room
                            .history_inventory_incarnation(&peer)
                            .zip(room.history_author_inventory_incarnation(&hint.author));
                        if declined == hint.head
                            && authorization == current_authorization
                            && current == Some((peer_incarnation, author_incarnation))
                        {
                            // The durable relationship is the source of truth. Do not mirror it
                            // in an uncharged process-global vector: an unchanged inventory is
                            // simply ineligible, including after reconnect and restart.
                            continue;
                        } else {
                            changed.push(hint.author);
                        }
                    }
                    let state =
                        read.sparse_author(&hint.author, crate::log::history::LogScope::Public)?;
                    // An inventory scalar is redundant only when its exact signed head is
                    // already in this author's accepted consistency chain, its selected
                    // current live window is complete and its exact control receipt is
                    // durable. Size alone never suppresses an unknown or same-size conflicting
                    // head. The live window may omit ordinary archive bodies; the separate
                    // bounded control closure proves those omitted positions contain no
                    // unapplied control and is what makes this state restart-complete.
                    let held = match (state, read.history_head(&hint.head)?) {
                        (Some(state), Some(advertised))
                            if advertised.binding.author == hint.author
                                && advertised.binding.scope
                                    == crate::log::history::LogScope::Public
                                && advertised.root.leaves == hint.size
                                && read
                                    .history_head_accepted(&hint.head, advertised.binding)? =>
                        {
                            match (state.committed, state.live) {
                                (Some(current_id), Some(window))
                                    if state.control_ready == Some(current_id)
                                        && window.head == current_id
                                        && window.complete() =>
                                {
                                    read.history_head(&current_id)?.is_some_and(|current| {
                                        current.binding == advertised.binding
                                            && window.through == current.root.leaves
                                    })
                                }
                                _ => false,
                            }
                        }
                        _ => false,
                    };
                    // One indexed successor lookup, not a scan of older missing bodies.
                    // Normal retention cleanup removes expired missing positions.
                    let retry_missing = if held && hint.size != 0 {
                        let floor = hint
                            .size
                            .saturating_sub(crate::log::history::MAX_PAGE_ENTRIES as u64 - 1)
                            .max(1);
                        let (positions, _) =
                            read.missing_page(Some((hint.author, floor - 1)), 1)?;
                        positions.first().is_some_and(|(author, seq)| {
                            *author == hint.author && *seq <= hint.size
                        })
                    } else {
                        false
                    };
                    if !held || retry_missing {
                        // Keep this hint as a bounded signed-head receipt probe. It is not
                        // itself acknowledgement and grants no source or authority.
                        missing.push(hint);
                    }
                }
                drop(read);
                changed.sort_unstable();
                changed.dedup();
                if !changed.is_empty() && room.history_publication_busy(store)? {
                    return Ok(Some(InventoryOffer::Publication(
                        crate::node::channel::HistoryPublicationWait {
                            owner: room.history_publication_request(store)?,
                            wake: publication_wake,
                        },
                    )));
                }
                let rearmed = changed.len();
                for author in changed {
                    room.forget_history_decline(store, peer, author, &committed)?;
                }
                // Filtering, current room/auth/head snapshot and metadata admission share
                // this SAME room guard. No delayed old callback can reset a newer record.
                // All index reads/transactions are gone before taking the short Inbox lock.
                let mut offer = match inbox.offer_peer_inventory(
                    &offer_job, generation, room_id, peer, &missing, context, local,
                ) {
                    Err(Error::Profile(super::hints::OWN_PROBE_CONNECTION_CHANGED)) => {
                        return Ok(Some(InventoryOffer::ConnectionChanged));
                    }
                    result => result?,
                };
                offer.rearmed = rearmed;
                Ok(Some(InventoryOffer::Offered(offer)))
            })
            .await?;
        match filtered {
            Lookup::Found(filtered) => Ok(filtered.value),
            Lookup::Busy | Lookup::Missing if self.authorization.is_none() => {
                Ok(InventoryOffer::Unavailable)
            }
            // The owned callback always returns Some and record_job always admits its fixed
            // envelope; real byte pressure was propagated above. Do not misreport a missing
            // callback as a completed bounded Inbox insertion.
            Lookup::Busy | Lookup::Missing => {
                Err(Error::Profile("owned inventory filter returned no result"))
            }
        }
    }
}

/// Replace only the exact captured author while preserving HAVE's strict order and cap.
/// An absent Head is absence, not a synthetic empty Head or a stale page's advertisement.
fn set_inventory_head(
    hints: &mut Vec<super::HeadHint>,
    author: Digest32,
    head: Option<super::ObservedHead>,
) -> Result<()> {
    match (
        hints.binary_search_by_key(&author, |hint| hint.author),
        head,
    ) {
        (Ok(at), Some(head)) => {
            hints[at] = super::HeadHint {
                author,
                size: head.size,
                head: head.head,
            };
        }
        (Ok(at), None) => {
            hints.remove(at);
        }
        (Err(at), Some(head)) => {
            if hints.len() >= crate::log::history::MAX_CONTEXT_AUTHORS {
                return Err(Error::SizeLimitExceeded("inventory captured author bound"));
            }
            hints.insert(
                at,
                super::HeadHint {
                    author,
                    size: head.size,
                    head: head.head,
                },
            );
        }
        (Err(_), None) => {}
    }
    Ok(())
}
