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
    consistency_ranges, inclusion_ranges, split, ConsistencyProof, ControlRangeProof, ControlToken,
    Descriptor, InclusionProof, SignedHead, MAX_CONTROL_HEADERS, MAX_PROOF_TOKENS, MAX_TREE_DEPTH,
};
use crate::node::channel::ChannelState;
use crate::node::history_budget::{BufferCharge, Job};
use crate::node::store::Store;
use crate::transport::stream_transport::Fence;

use super::{Proof, ProofKind, RequestId};

pub(super) enum DeclineResult {
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
fn request_text(request: &RequestId) -> String {
    use std::fmt::Write as _;
    let mut text = String::with_capacity(request.len() * 2);
    for byte in request {
        let _ = write!(text, "{byte:02x}");
    }
    text
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

/// Exact local announcement owner. Its token is never carried as peer authority.
pub(super) struct RoleAnnouncement {
    pub(super) owner: Arc<crate::node::channel::role_owed::RoleOwed>,
    pub(super) peer: Digest32,
    pub(super) token: Arc<()>,
    pub(super) head: super::HeadHint,
}

pub(super) struct CatalogAnnouncement {
    pub(super) owner: Arc<crate::node::channel::role_owed::RoleOwed>,
    pub(super) peer: Digest32,
    pub(super) token: Arc<()>,
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
    work_committed: Arc<AtomicBool>,
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
        if std::fs::write(&entered, identity).is_err() {
            return;
        }
        while std::path::Path::new(&path).exists() {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
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
        metadata: bool,
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
                    (authorization.0, authorization.1, metadata),
                    &committed,
                )?))
            })
            .await?
        {
            Lookup::Found(saved) => match saved.value {
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
            work_committed,
        }
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
        if matches!(boundary, ReadBoundary::Observing) && Instant::now() >= self.deadline {
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
        let mut room = tokio::select! {
            biased;
            () = self.fence.retired() => return Err(Error::Unreachable("history request cancelled")),
            room = self.room.clone().lock_owned() => room,
        };
        self.current_at(boundary)?;
        let source = self.clone();
        // Once dispatched, the closure owns both charges and the room guard. Dropping the
        // async waiter detaches it; credit cannot be reused while the disk read still runs.
        let task = tokio::task::spawn_blocking(move || {
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
        let mut cursor = crate::node::channel::ProofRangeRestore::new(head, start, leaves)?;
        loop {
            self.current()?;
            let ledger = self.commit_ledger();
            let peer = self.peer;
            // One bounded physical step: Directory scratch is separately reserved by read;
            // this envelope covers the two contexts/join/encoded context and scalar DFS.
            let step = self
                .read(
                    job,
                    crate::node::channel::ProofRangeRestore::WORK_BYTES,
                    move |room, store| {
                        let step = room.restore_proof_range(store, peer, &mut cursor, &ledger)?;
                        Ok(Some((cursor, step)))
                    },
                )
                .await?;
            let Lookup::Found(step) = step else {
                return Ok(match step {
                    Lookup::Busy => Lookup::Busy,
                    _ => Lookup::Missing,
                });
            };
            let (next, outcome) = step.value;
            cursor = next;
            match outcome {
                crate::node::channel::ProofRangeStep::Complete(value) => {
                    return Ok(Lookup::Found(Held {
                        value,
                        _charge: step._charge,
                    }));
                }
                crate::node::channel::ProofRangeStep::Missing => return Ok(Lookup::Missing),
                crate::node::channel::ProofRangeStep::Busy => return Ok(Lookup::Busy),
                crate::node::channel::ProofRangeStep::Progress => {}
            }
            // The worker, RoomMutex, snapshot and decode buffers have actually dropped.
            // Same request/Job remains owned; this is not a second admission or a timer retry.
            drop(step._charge);
            tokio::task::yield_now().await;
        }
    }

    /// Proof construction reads only indexed canonical ranges, never a content archive. The
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
    /// Settle the advertised authors after releasing the room lock. A newer
    /// transaction can add a conservative debt; one already removed is durable.
    pub(super) async fn flush_authors_before_ack(
        &self,
        room: Digest32,
        authors: Vec<Digest32>,
    ) -> Result<()> {
        let store = Arc::clone(&self.store);
        tokio::task::spawn_blocking(move || {
            for author in authors {
                for debt in store.received_debts_for_author(room, author)? {
                    store.flush_received_through(debt)?;
                }
            }
            Ok(())
        })
        .await
        .map_err(|_| Error::Unreachable("history flush worker stopped"))?
    }

    /// One bounded, charged scalar inventory. Every page rechecks current room access;
    /// the compact index is read without touching content bodies or walking the archive.
    pub(super) async fn inventory(
        &self,
        job: &Job,
    ) -> Result<
        Lookup<(
            Vec<super::HeadHint>,
            Option<RoleAnnouncement>,
            Option<([u8; 16], u64)>,
            Option<CatalogAnnouncement>,
            super::super::channel::availability::Token,
        )>,
    > {
        let charge = job.reserve_or_pressure(
            (crate::log::history::MAX_CONTEXT_AUTHORS + 2) * std::mem::size_of::<super::HeadHint>(),
        )?;
        let mut hints = Vec::with_capacity(crate::log::history::MAX_CONTEXT_AUTHORS);
        let mut after = None;
        for _ in 0..=crate::log::history::MAX_CONTEXT_AUTHORS / 64 {
            self.current()?;
            let page = self
                .read(job, 64 * 1024, move |room, store| {
                    room.history_head_hints(store, after)
                        .map(|page| Some((room.channel_id(), page)))
                })
                .await?;
            let Lookup::Found(page) = page else {
                return Ok(Lookup::Busy);
            };
            let (room_id, page) = page.value;
            if hints.len() + page.heads.len() > crate::log::history::MAX_CONTEXT_AUTHORS {
                return Err(Error::SizeLimitExceeded("inventory author bound"));
            }
            hints.extend(page.heads.iter().map(|hint| super::HeadHint {
                author: hint.author,
                size: hint.leaves,
                head: hint.head,
            }));
            match page.next {
                Some(next) if after.is_none_or(|previous| next > previous) => after = Some(next),
                None => {
                    let peer = self.peer;
                    let role = match self
                        .read(job, 128 * 1024, move |room, store| {
                            let owner = room.role_owed();
                            let role =
                                room.history_role_head(store, &peer)?
                                    .map(|head| super::HeadHint {
                                        author: peer,
                                        size: head.root.leaves,
                                        head: head.id(),
                                    });
                            let notice = if let Some(head) = role {
                                owner.observe(peer, head);
                                owner.snapshot(peer).map(|(token, head)| RoleAnnouncement {
                                    owner,
                                    peer,
                                    token,
                                    head,
                                })
                            } else {
                                owner.unavailable(peer);
                                None
                            };
                            Ok(Some(notice))
                        })
                        .await?
                    {
                        Lookup::Found(role) => role.value,
                        Lookup::Busy | Lookup::Missing => return Ok(Lookup::Busy),
                    };
                    let (key_catalog, catalog_announcement) = match self
                        .read(job, 128 * 1024, move |room, store| {
                            let instance = room.history_instance(store)?;
                            let tip = room.history_read(store)?.key_package_tip()?;
                            let owner = room.role_owed();
                            let notice = owner
                                .key_catalog_announcement(peer)
                                .map(|token| CatalogAnnouncement { owner, peer, token });
                            Ok(Some(((instance, tip), notice)))
                        })
                        .await?
                    {
                        Lookup::Found(hint) => (Some(hint.value.0), hint.value.1),
                        Lookup::Busy | Lookup::Missing => return Ok(Lookup::Busy),
                    };
                    let mut authors: Vec<_> = hints.iter().map(|hint| hint.author).collect();
                    if role.is_some() && !authors.contains(&peer) {
                        authors.push(peer);
                    }
                    self.flush_authors_before_ack(room_id, authors).await?;
                    let Lookup::Found(availability) = self
                        .read(job, 0, move |room, _| {
                            Ok(Some(room.availability_peer(peer, None)?.local()))
                        })
                        .await?
                    else {
                        return Ok(Lookup::Busy);
                    };
                    return Ok(Lookup::Found(Held {
                        value: (
                            hints,
                            role,
                            key_catalog,
                            catalog_announcement,
                            availability.value,
                        ),
                        _charge: charge,
                    }));
                }
                _ => return Err(Error::MalformedAtRest("inventory cursor did not advance")),
            }
        }
        Err(Error::SizeLimitExceeded("inventory index slice bound"))
    }

    pub(super) async fn observe_availability(
        &self,
        job: &Job,
        connection: u64,
        token: super::super::channel::availability::Token,
    ) -> Result<()> {
        let peer = self.peer;
        match self
            .read(job, 0, move |room, _| {
                room.availability_peer(peer, None)?
                    .observe(connection, token);
                Ok(Some(()))
            })
            .await?
        {
            Lookup::Found(_) => Ok(()),
            _ => Err(Error::Unreachable("availability room read busy")),
        }
    }

    /// A peer's role advertisement wakes an authenticated query; it is not a receipt.
    pub(super) async fn offer_role(
        &self,
        job: &Job,
        inbox: &super::HintInbox,
        generation: u64,
        room_id: Digest32,
        connection: u64,
        role: Option<super::HeadHint>,
    ) -> Result<super::hints::Offer> {
        let Some(role) = role else {
            return Ok(super::hints::Offer::default());
        };
        let author = role.author;
        let peer = self.peer;
        let epoch = self.epoch;
        let current = self
            .read(job, 128, move |room, store| {
                if room.channel_id() != room_id || room.me() != author {
                    return Err(Error::MalformedBundle("history role hint binding"));
                }
                let Some(incarnations) = room
                    .history_inventory_incarnation(&peer)
                    .zip(room.history_author_inventory_incarnation(&author))
                else {
                    return Ok(None);
                };
                let instance = room.history_instance(store)?;
                let authorization =
                    super::authorization_generation(store, author, room_id, instance, epoch)?;
                let scope = crate::node::ports::SupportDiscovery {
                    connection,
                    instance,
                    epoch,
                    authorization,
                };
                Ok(Some((
                    room.held_through(&peer).is_none_or(|held| held < role.size),
                    scope,
                    incarnations,
                )))
            })
            .await?;
        let (needed, scope, incarnations) = match current {
            Lookup::Found(held) => held.value,
            Lookup::Busy | Lookup::Missing => {
                return Err(Error::Unreachable("history role hint authority busy"));
            }
        };
        if !needed {
            return Ok(super::hints::Offer::default());
        }
        inbox.offer_role(generation, room_id, self.peer, scope, incarnations, role)
    }

    /// A catalog watermark is an unauthoritative scheduling hint for this exact peer.
    pub(super) async fn offer_key_catalog(
        &self,
        job: &Job,
        hint: Option<([u8; 16], u64)>,
        connection_serial: u64,
    ) -> Result<()> {
        let Some((instance, tip)) = hint else {
            return Ok(());
        };
        if instance == [0; 16] {
            return Err(Error::MalformedBundle("key catalog instance is zero"));
        }
        let peer = self.peer;
        match self
            .read(job, 128, move |room, _store| {
                room.role_owed()
                    .observe_key_catalog(peer, instance, tip, connection_serial);
                Ok(Some(()))
            })
            .await?
        {
            Lookup::Found(_) => Ok(()),
            Lookup::Busy | Lookup::Missing => {
                Err(Error::Unreachable("key catalog hint authority busy"))
            }
        }
    }

    /// Complete only the exact notice after the peer processed the inventory and while the
    /// originating room and trust incarnation are still current.
    pub(super) async fn acknowledge_role(&self, job: &Job, notice: RoleAnnouncement) -> Result<()> {
        let authorization = self.authorization;
        let epoch = self.epoch;
        match self
            .read(job, 128, move |room, store| {
                if !Arc::ptr_eq(&room.role_owed(), &notice.owner) {
                    return Ok(Some(()));
                }
                if let Some((node, expected)) = authorization {
                    let room_id = room.channel_id();
                    let current = super::authorization_generation(
                        store,
                        node,
                        room_id,
                        room.history_instance(store)?,
                        epoch,
                    )?;
                    if current != expected {
                        return Ok(Some(()));
                    }
                }
                notice.owner.ack(notice.peer, &notice.token);
                Ok(Some(()))
            })
            .await?
        {
            Lookup::Found(_) => Ok(()),
            Lookup::Busy | Lookup::Missing => Err(Error::Unreachable(
                "history role announcement confirmation busy",
            )),
        }
    }

    /// Retire only the catalog change whose matching inventory reached the peer.
    pub(super) async fn acknowledge_key_catalog(
        &self,
        job: &Job,
        notice: CatalogAnnouncement,
        connection_serial: u64,
    ) -> Result<()> {
        let authorization = self.authorization;
        let epoch = self.epoch;
        match self
            .read(job, 128, move |room, store| {
                if !Arc::ptr_eq(&room.role_owed(), &notice.owner) {
                    return Ok(Some(()));
                }
                if let Some((node, expected)) = authorization {
                    let current = super::authorization_generation(
                        store,
                        node,
                        room.channel_id(),
                        room.history_instance(store)?,
                        epoch,
                    )?;
                    if current != expected {
                        return Ok(Some(()));
                    }
                }
                notice.owner.ack_key_catalog_announcement(
                    notice.peer,
                    &notice.token,
                    connection_serial,
                );
                Ok(Some(()))
            })
            .await?
        {
            Lookup::Found(_) => Ok(()),
            Lookup::Busy | Lookup::Missing => Err(Error::Unreachable(
                "key catalog announcement confirmation busy",
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
        inbox: &super::HintInbox,
        generation: u64,
        room_id: Digest32,
        hints: &[super::HeadHint],
    ) -> Result<super::hints::Offer> {
        if hints.len() > 64 {
            return Err(Error::SizeLimitExceeded("inventory filter slice"));
        }
        // Input copy and returned vector coexist inside this small prepaid envelope.
        let Some(input_charge) = job.reserve(64 * std::mem::size_of::<super::HeadHint>()) else {
            return Ok(super::hints::Offer {
                added: 0,
                rearmed: 0,
                full: true,
            });
        };
        let peer = self.peer;
        let slice = hints.to_vec();
        let committed = Arc::clone(&self.work_committed);
        let output_envelope = 64
            * (std::mem::size_of::<super::HeadHint>()
                + std::mem::size_of::<(Digest32, Digest32)>()
                + std::mem::size_of::<Digest32>())
            + std::mem::size_of::<usize>();
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
                let read = room.history_read(store)?;
                let mut missing = Vec::with_capacity(slice.len());
                let mut changed = Vec::new();
                for hint in slice {
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
                    if hint.author == room.me() {
                        // Inventory is only an unauthoritative scalar hint. Even when its
                        // signed head is already accepted locally, it does not prove the peer
                        // completed every effect it owes through that position. Keep the hint
                        // until Query::Head asks the peer for the authenticated role-complete
                        // receipt. A previously recorded later receipt makes an older echo
                        // redundant; no scalar echo itself may advance held_through.
                        if room.held_through(&peer).is_none_or(|held| held < hint.size) {
                            missing.push(hint);
                        }
                        continue;
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
                    if !held
                        || retry_missing
                        || (hint.author == room.me()
                            && room.history_departure_matches(store, hint)?)
                    {
                        // Keep this hint as a bounded signed-head receipt probe. It is not
                        // itself acknowledgement and grants no source or authority.
                        missing.push(hint);
                    }
                }
                drop(read);
                changed.sort_unstable();
                changed.dedup();
                let rearmed = changed.len();
                for author in changed {
                    room.forget_history_decline(store, peer, author, &committed)?;
                }
                Ok(Some((missing, rearmed)))
            })
            .await?;
        match filtered {
            Lookup::Found(filtered) => {
                self.current()?;
                let (missing, rearmed) = filtered.value;
                let mut offer = inbox.offer(job, generation, room_id, self.peer, &missing)?;
                offer.rearmed = rearmed;
                Ok(offer)
            }
            Lookup::Busy | Lookup::Missing => Ok(super::hints::Offer {
                added: 0,
                rearmed: 0,
                full: true,
            }),
        }
    }
}
