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
use crate::node::store::Store;
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
    pub(super) room: Arc<Mutex<ChannelState>>,
    pub(super) store: Arc<Store>,
    pub(super) epoch: u64,
    pub(super) peer: Digest32,
    pub(super) fence: Arc<Fence>,
    pub(super) deadline: Instant,
}

impl Source {
    pub(super) fn new(
        room: Arc<Mutex<ChannelState>>,
        store: Arc<Store>,
        epoch: u64,
        peer: Digest32,
        fence: Arc<Fence>,
        deadline: Instant,
    ) -> Self {
        Self {
            room,
            store,
            epoch,
            peer,
            fence,
            deadline,
        }
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
        let Some(charge) = job.reserve(envelope) else {
            return Ok(Lookup::Busy);
        };
        let Some(scratch) = job.reserve(temporary) else {
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
            if room.epoch() != source.epoch
                || !room.is_member(&source.peer)
                || room.has_left(&source.peer)
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
        let result = tokio::select! {
            biased;
            () = self.fence.retired() => return Err(Error::Unreachable("history request cancelled")),
            result = tokio::time::timeout_at(self.deadline, task) => {
                result.map_err(|_| Error::Unreachable("history disk read deadline elapsed"))?
                    .map_err(|_| Error::Unreachable("history disk reader stopped"))?
            }
        };
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
                    // The next control belongs to a separate locally requested quantum. The
                    // completed proof still reconstructs the whole exact head, with the suffix
                    // now outside its smaller covered interval rather than silently omitted.
                    hi = start - 1;
                    tokens.push(ControlToken::Collapse(descriptor));
                    self.current()?;
                    tokio::task::yield_now().await;
                    continue;
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
