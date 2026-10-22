//! Bounded disk reads used by one response. No pinned read or room lock crosses network I/O.

use std::sync::Arc;

use tokio::sync::Mutex;
use tokio::time::Instant;

use crate::error::{Error, Result};
use crate::hash::Digest32;
use crate::log::entry::Entry;
use crate::log::history::{
    consistency_ranges, inclusion_ranges, split, ConsistencyProof, ControlRangeProof, ControlToken,
    Descriptor, InclusionProof, SignedHead, TreeBinding, MAX_CONTROL_HEADERS, MAX_PROOF_TOKENS,
    MAX_TREE_DEPTH,
};
use crate::node::channel::ChannelState;
use crate::node::history_budget::{BufferCharge, Job};
use crate::node::store::{ReceivedDebt, Store};
use crate::transport::stream_transport::Fence;

use super::{Proof, ProofKind};

// Directory plaintext is capped at 1 MiB before copy/decrypt. This also covers its sealed
// bytes and bounded decoded author/presence maps. It is temporary, not part of Held's output.
const DIRECTORY_ENVELOPE: usize = 4 * 1024 * 1024;

/// The charge follows both the blocking read and the returned allocation. Cancelling an async
/// caller cannot release memory credit while an already running disk read still owns buffers.
pub(super) struct Held<T> {
    pub(super) value: T,
    _charge: BufferCharge,
}

pub(super) enum Lookup<T> {
    Found(Held<T>),
    Busy,
    Missing,
}

#[derive(Clone)]
pub(super) struct Source {
    room_id: Digest32,
    pub(super) room: Arc<Mutex<ChannelState>>,
    pub(super) store: Arc<Store>,
    pub(super) epoch: u64,
    pub(super) peer: Digest32,
    pub(super) fence: Arc<Fence>,
    pub(super) deadline: Instant,
    // Only a server clone bound to Control/Head(peer) may return a departed peer receipt.
    own_head_receipt: bool,
}

impl Source {
    /// The exact user-visible received-entry acknowledgement armed by the FX-30 crash journey.
    /// A two-field flow gate is not enough: only `<room> <peer> <entry>` can suppress inventory
    /// and bind the mutant to the head receipt for that entry.
    pub(super) fn received_ack_probe(&self) -> Option<(std::path::PathBuf, String)> {
        #[cfg(feature = "test-knobs")]
        {
            let gate = std::path::PathBuf::from(std::env::var_os(
                "VOX_TEST_HOLD_RECEIVED_FLOW_FLUSH_FILE",
            )?);
            let armed = std::fs::read_to_string(&gate).ok()?;
            let mut fields = armed.split_whitespace();
            let room = fields.next()?;
            let peer = fields.next()?;
            let entry = fields.next()?.to_owned();
            if fields.next().is_none()
                && room == crate::node::link::b32_encode(&self.room_id)
                && peer == crate::node::link::b32_encode(&self.peer)
            {
                return Some((gate, entry));
            }
        }
        None
    }

    pub(super) fn new(
        room_id: Digest32,
        room: Arc<Mutex<ChannelState>>,
        store: Arc<Store>,
        epoch: u64,
        peer: Digest32,
        fence: Arc<Fence>,
        deadline: Instant,
    ) -> Self {
        Self {
            room_id,
            room,
            store,
            epoch,
            peer,
            fence,
            deadline,
            own_head_receipt: false,
        }
    }

    pub(super) fn for_own_head_receipt(&self) -> Self {
        let mut source = self.clone();
        source.own_head_receipt = true;
        source
    }

    fn current(&self) -> Result<()> {
        if self.fence.is_retired() {
            return Err(Error::Unreachable("history request cancelled"));
        }
        if Instant::now() >= self.deadline {
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
        let work_envelope = envelope
            .checked_add(temporary)
            .ok_or(Error::SizeLimitExceeded("history read envelope"))?;
        let Some(work_job) = job.record_job(work_envelope) else {
            return Ok(Lookup::Busy);
        };
        let Some(charge) = work_job.reserve(envelope) else {
            return Ok(Lookup::Busy);
        };
        let Some(scratch) = work_job.reserve(temporary) else {
            return Ok(Lookup::Busy);
        };
        let mut room = tokio::select! {
            biased;
            () = self.fence.retired() => return Err(Error::Unreachable("history request cancelled")),
            result = tokio::time::timeout_at(self.deadline, self.room.clone().lock_owned()) => {
                result.map_err(|_| Error::Unreachable("history room lock deadline elapsed"))?
            }
        };
        self.current()?;
        let source = self.clone();
        // Once dispatched, the closure owns both charges and the room guard. Dropping the
        // async waiter detaches it; credit cannot be reused while the disk read still runs.
        let task = tokio::task::spawn_blocking(move || {
            source.current()?;
            let departed_receipt = source.own_head_receipt
                && room.is_author(&source.peer)
                && room.has_left(&source.peer);
            if room.epoch() != source.epoch || (!room.is_member(&source.peer) && !departed_receipt)
            {
                return Err(Error::Unreachable("history room access changed"));
            }
            let value = read(&mut room, &source.store)?;
            source.current()?;
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
        self.current()?;
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
        binding: TreeBinding,
        start: u64,
        leaves: u64,
    ) -> Result<Lookup<Descriptor>> {
        self.read(job, 64 * 1024, move |room, store| {
            room.history_tree_range(store, binding, start, leaves)
        })
        .await
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
                match self
                    .range(job, head.binding, range.start, range.leaves)
                    .await?
                {
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
                        match self.range(job, head.binding, 1, from).await? {
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
                let descriptor = match self.range(job, head.binding, start, leaves).await? {
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
    /// Flush the exact received transaction fenced by the room snapshot which is about to be
    /// acknowledged. The debt and advertised head are captured under the same room lock; neither
    /// a stale source nor a later flow in this room can substitute its bytes for that snapshot.
    pub(super) async fn flush_received_before_ack(
        &self,
        debt: Option<ReceivedDebt>,
        _boundary: Option<Digest32>,
    ) -> Result<()> {
        let Some(debt) = debt else {
            return Ok(());
        };
        let store = Arc::clone(&self.store);
        let room = self.room_id;
        let peer = self.peer;
        let _probe = self.received_ack_probe();
        tokio::task::spawn_blocking(move || {
            store
                .flush_received_through_with(
                    debt,
                    |_debt| {
                        #[cfg(feature = "test-knobs")]
                        {
                            if let Some((gate, expected)) = &_probe {
                                let exact = format!(
                                    "{} {}",
                                    crate::node::link::b32_encode(&room),
                                    crate::node::link::b32_encode(&peer)
                                );
                                let boundary = _boundary
                                    .map(|hash| crate::node::link::b32_encode(&hash))
                                    .unwrap_or_else(|| "-".to_owned());
                                if boundary == *expected {
                                    let reached = gate.with_extension("ack-reached");
                                    std::fs::write(
                                        &reached,
                                        format!("{exact} {} {boundary}\n", _debt.transaction()),
                                    )
                                    .map_err(|error| {
                                        Error::Storage {
                                            op: "mark received acknowledgement boundary",
                                            detail: error.to_string(),
                                        }
                                    })?;
                                    if std::env::var("VOX_TEST_FX30_MUTANT").as_deref()
                                        == Ok("received-ack-not-flushed")
                                    {
                                        // Isolated mutant: only this exact acknowledged transaction
                                        // skips its flush. Its fenced debt keeps every later writer
                                        // from rescuing it before the proof crashes the daemon.
                                        return Ok(false);
                                    }
                                }
                            }
                        }
                        Ok(true)
                    },
                    |debt| crate::node::store::hold_after_received_flow_flush(debt, room, peer),
                )
                .map(|_| ())
        })
        .await
        .map_err(|_| Error::Unreachable("history flush worker stopped"))?
    }

    /// One bounded, charged scalar inventory. Every page rechecks current room access;
    /// the compact index is read without touching content bodies or walking the archive.
    pub(super) async fn inventory(&self, job: &Job) -> Result<Lookup<Vec<super::HeadHint>>> {
        let Some(charge) = job.reserve(
            crate::log::history::MAX_CONTEXT_AUTHORS * std::mem::size_of::<super::HeadHint>(),
        ) else {
            return Ok(Lookup::Busy);
        };
        let mut hints = Vec::with_capacity(crate::log::history::MAX_CONTEXT_AUTHORS);
        let mut after = None;
        for _ in 0..=crate::log::history::MAX_CONTEXT_AUTHORS / 64 {
            self.current()?;
            let exact_head_probe = self.received_ack_probe().is_some();
            let page = self
                .read(job, 64 * 1024, move |room, store| {
                    let page = room.history_head_hints(store, after)?;
                    let debt = if page.next.is_none() && !exact_head_probe {
                        store.received_debt(&room.channel_id())?
                    } else {
                        None
                    };
                    Ok(Some((page, debt)))
                })
                .await?;
            let Lookup::Found(page) = page else {
                return Ok(Lookup::Busy);
            };
            let (page, debt) = page.value;
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
                    // The exact acknowledgement proof needs the entry-bound Head response, not
                    // an inventory hint that could settle the same debt first. Returning Busy is
                    // causal staging compiled out of packaged builds; it publishes no verdict.
                    if exact_head_probe {
                        return Ok(Lookup::Busy);
                    }
                    self.flush_received_before_ack(debt, None).await?;
                    return Ok(Lookup::Found(Held {
                        value: hints,
                        _charge: charge,
                    }));
                }
                _ => return Err(Error::MalformedAtRest("inventory cursor did not advance")),
            }
        }
        Err(Error::SizeLimitExceeded("inventory index slice bound"))
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
                full: true,
                mine_held: None,
            });
        };
        let slice = hints.to_vec();
        let filtered = self
            .read(
                job,
                64 * std::mem::size_of::<super::HeadHint>(),
                move |room, store| {
                    let _input_charge = input_charge;
                    if room.channel_id() != room_id {
                        return Err(Error::MalformedBundle("inventory room binding"));
                    }
                    let read = room.history_read(store)?;
                    let mut missing = Vec::with_capacity(slice.len());
                    let mut mine: Option<u64> = None;
                    let own_contiguous = room.own_verified_head();
                    for hint in slice {
                        if hint.author == room.me() {
                            // The peer names a head of this node's own feed that this node holds
                            // and accepted: its word that it holds the feed through there.
                            if let Some(adv) = read.history_head(&hint.head)? {
                                if adv.binding.author == hint.author
                                    && adv.binding.scope == crate::log::history::LogScope::Public
                                    && adv.root.leaves == hint.size
                                    && read.history_head_accepted(&hint.head, adv.binding)?
                                {
                                    mine = Some(mine.map_or(hint.size, |m| m.max(hint.size)));
                                    // The own feed is this node's durable fact (ADR-037 R5), and
                                    // R10 never visits the own live window, so the window test
                                    // below would keep every own-head echo as a probe forever:
                                    // a hinted round per peer per inventory that fetched
                                    // nothing. A known, accepted own head within the contiguous
                                    // own feed is held; only a longer own feed elsewhere stays a
                                    // probe, for the own-history conflict detector (R5).
                                    if hint.size <= own_contiguous {
                                        continue;
                                    }
                                }
                            }
                        }
                        let state = read
                            .sparse_author(&hint.author, crate::log::history::LogScope::Public)?;
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
                                    && read.history_head_accepted(
                                        &hint.head,
                                        advertised.binding,
                                    )? =>
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
                    Ok(Some((missing, mine)))
                },
            )
            .await?;
        match filtered {
            Lookup::Found(filtered) => {
                self.current()?;
                let (missing, mine) = filtered.value;
                let mut offer = inbox.offer(job, generation, room_id, self.peer, &missing)?;
                offer.mine_held = mine;
                Ok(offer)
            }
            Lookup::Busy | Lookup::Missing => Ok(super::hints::Offer {
                added: 0,
                full: true,
                mine_held: None,
            }),
        }
    }
}
