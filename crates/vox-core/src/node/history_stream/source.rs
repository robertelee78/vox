//! Bounded disk reads used by one response. No pinned read or room lock crosses network I/O.

use std::future::Future;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use tokio::time::Instant;

use crate::error::{Error, Result};
use crate::hash::Digest32;
use crate::log::entry::Entry;
use crate::log::history::{
    consistency_ranges, inclusion_ranges, split, ConsistencyProof, ControlRangeProof, ControlToken,
    Descriptor, HeadTarget, InclusionProof, MAX_CONTROL_HEADERS, MAX_PROOF_TOKENS, MAX_TREE_DEPTH,
};
use crate::node::channel::{
    ChannelState, ResolvedTarget, RoomSnapshot, RoomSnapshotCell, ServedRoom,
};
use crate::node::history_budget::{BufferCharge, Job};
use crate::node::store::Store;
use crate::transport::stream_transport::Fence;

use super::{Proof, ProofKind, RequestId};

// Directory plaintext is capped at 1 MiB before copy/decrypt. This also covers its sealed
// bytes and bounded decoded author/presence maps. It is temporary, not part of Held's output.
const DIRECTORY_ENVELOPE: usize = 4 * 1024 * 1024;

/// The charge follows both the blocking read and the returned allocation. Cancelling an async
/// caller cannot release memory credit while an already running disk read still owns buffers.
pub(super) struct Held<T> {
    pub(super) value: T,
    _charge: BufferCharge,
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

pub(super) struct PublicationReadiness {
    pub(super) busy: bool,
    pub(super) owner: Option<RequestId>,
    pub(super) wake: std::pin::Pin<Box<dyn Future<Output = ()> + Send + Sync>>,
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
    pub(super) room: Arc<crate::node::channel::RoomLock>,
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
    // Set only on a server clone whose exact query is separately restricted to the peer's feed.
    own_recovery: bool,
    /// A Range bundle's server: it waits for the local admission it needs (bytes, the room's
    /// own saving, a publication) and then answers; it never answers Busy and has no deadline.
    /// One request is in flight per connection, so the wait costs only that connection.
    patient: bool,
    work_committed: Arc<AtomicBool>,
    retirement_request: Option<RequestId>,
    /// An answer to a peer reads the room's published snapshot, never the room itself.
    snapshot: Option<Arc<RoomSnapshotCell>>,
}

impl Source {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        room: Arc<crate::node::channel::RoomLock>,
        store: Arc<Store>,
        epoch: u64,
        peer: Digest32,
        fence: Arc<Fence>,
        deadline: Instant,
        authorization: Option<(Digest32, Digest32)>,
        work_committed: Arc<AtomicBool>,
        retirement_request: Option<RequestId>,
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
            own_recovery: false,
            patient: false,
            work_committed,
            retirement_request,
            snapshot: None,
        }
    }

    /// Answer a peer from the room's published snapshot (see [`RoomSnapshot`]): its reads of
    /// headers, proofs and bodies wait on neither the room's lock, the actor nor this node's own
    /// pending save. Served inventory still takes the store's writer
    /// ([`Self::flush_authors_before_ack`], a changed decline's forget).
    pub(super) fn serving(mut self, snapshot: Arc<RoomSnapshotCell>) -> Self {
        self.snapshot = Some(snapshot);
        self
    }

    /// What this source may serve a peer of `standing` (`channel::room_snapshot::standing`, the
    /// one rule the loop's teller uses too): a member anything; a returning author its own
    /// receipt and, on an own-recovery source, its own public tree; a departed author its own
    /// departure receipt only.
    fn serves(&self, standing: Option<crate::node::channel::Standing>) -> bool {
        use crate::node::channel::Standing;
        match standing {
            Some(Standing::Member) => true,
            Some(Standing::Returning) => self.own_head_receipt || self.own_recovery,
            Some(Standing::Departed) => self.own_head_receipt,
            None => false,
        }
    }

    /// The access a local step requires, read from the room itself: the room instance's epoch
    /// and, for a source working for a peer, that peer's standing ([`Self::serves`]) with no
    /// applied removal. The room's one local admission (`runtime::Flow::admit`, its peer this
    /// node) works for no peer: this node's own removal, and the readmission that ends it, are
    /// entries it admits, so its own standing never stops it.
    fn room_access(&self, room: &ChannelState) -> Result<()> {
        if room.epoch() != self.epoch {
            return Err(Error::Unreachable("history room access changed"));
        }
        if self
            .authorization
            .is_some_and(|(node, _)| node == self.peer)
        {
            return Ok(());
        }
        let allowed = self.serves(room.standing(&self.store, &self.peer)?);
        #[cfg(feature = "test-knobs")]
        let mutant =
            crate::node::computer::fx28_mutant("sync-departed-peer") && room.has_left(&self.peer);
        #[cfg(not(feature = "test-knobs"))]
        let mutant = false;
        if (!mutant && !allowed) || room.peer_removal_applied(&self.store, &self.peer)? {
            return Err(Error::Unreachable("history room access changed"));
        }
        Ok(())
    }

    /// The access a served read requires, decided on the room's published snapshot; the
    /// peer's applied removal is read in the store, as the room-locked check read it.
    fn snapshot_access(&self, snapshot: &RoomSnapshot) -> Result<()> {
        let peer = &self.peer;
        let allowed = self.serves(snapshot.standing(peer));
        #[cfg(feature = "test-knobs")]
        let mutant =
            crate::node::computer::fx28_mutant("sync-departed-peer") && snapshot.has_left(peer);
        #[cfg(not(feature = "test-knobs"))]
        let mutant = false;
        if snapshot.epoch() != self.epoch
            || (!mutant && !allowed)
            || snapshot.peer_removal_applied(&self.store, peer)?
        {
            return Err(Error::Unreachable("history room access changed"));
        }
        Ok(())
    }

    /// One served read: through the room's published snapshot when answering a peer, through
    /// the room for a client's own flow.
    pub(super) async fn serve_read<T, F>(
        &self,
        job: &Job,
        envelope: usize,
        read: F,
    ) -> Result<Lookup<T>>
    where
        T: Send + 'static,
        F: FnOnce(&mut dyn ServedRoom, &Store) -> Result<Option<T>> + Send + 'static,
    {
        self.serve_read_charged(job, envelope, DIRECTORY_ENVELOPE, read)
            .await
    }

    /// `VOX_MUTANT_SERVE_WAITS_ON_ROOM` (test-knobs): a served read goes back through the room's
    /// lock and stands aside for this node's own pending save as before this change, answering
    /// Busy past the old cap. `true` = answer Busy.
    async fn room_wait_mutant(&self) -> Result<bool> {
        #[cfg(feature = "test-knobs")]
        if std::env::var_os("VOX_MUTANT_SERVE_WAITS_ON_ROOM").is_some() {
            let cap = Instant::now() + std::time::Duration::from_millis(250);
            loop {
                let room = self.room.lock().await;
                if !room.post_pending() {
                    return Ok(false);
                }
                let wake = room.history_publication_wake();
                drop(room);
                tokio::select! {
                    () = tokio::time::sleep_until(cap) => {
                        eprintln!("vox: VOX_MUTANT_SERVE_WAITS_ON_ROOM answered busy");
                        return Ok(true);
                    }
                    () = wake => {}
                }
            }
        }
        Ok(false)
    }

    async fn serve_read_charged<T, F>(
        &self,
        job: &Job,
        envelope: usize,
        temporary: usize,
        read: F,
    ) -> Result<Lookup<T>>
    where
        T: Send + 'static,
        F: FnOnce(&mut dyn ServedRoom, &Store) -> Result<Option<T>> + Send + 'static,
    {
        let Some(cell) = self.snapshot.as_ref() else {
            return self
                .read_charged(
                    job,
                    envelope,
                    temporary,
                    ReadBoundary::Observing,
                    move |room, store| read(room, store),
                )
                .await;
        };
        self.current()?;
        if self.room_wait_mutant().await? {
            return Ok(Lookup::Busy);
        }
        let admission = match self.reserve_read(job, envelope, temporary).await {
            Ok(Some(admission)) => admission,
            Ok(None) | Err(Error::HistoryCapacity(_)) => return Ok(Lookup::Busy),
            Err(error) => return Err(error),
        };
        let snapshot = cell
            .current()
            .ok_or(Error::Unreachable("history room access changed"))?;
        let source = self.clone();
        // The blocking reader owns both charges; a dropped waiter cannot free them early.
        let read = tokio::task::spawn_blocking(move || {
            let PreparedRead { charge, scratch } = admission;
            source.current()?;
            source.snapshot_access(&snapshot)?;
            let value = snapshot.with(|view| read(view, &source.store))?;
            drop(scratch);
            Ok(match value {
                Some(value) => Lookup::Found(Held {
                    value,
                    _charge: charge,
                }),
                None => Lookup::Missing,
            })
        })
        .await;
        read.map_err(|_| Error::Unreachable("history disk reader stopped"))?
    }
    /// Record user-visible history work at the commit edge, independently of whether the
    /// surrounding exchange is later cancelled, superseded, retired or rejected.
    pub(super) fn note_work_committed(&self) {
        self.work_committed.store(true, Ordering::Release);
    }

    pub(super) fn commit_ledger(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.work_committed)
    }

    pub(super) fn retirement_request(&self) -> Result<RequestId> {
        self.retirement_request
            .ok_or(Error::Profile("history Begin has no Flow retirement owner"))
    }

    /// The node and generation this source's writes were authorized under, if a peer's.
    pub(super) fn authorization(&self) -> Option<(Digest32, Digest32)> {
        self.authorization
    }

    pub(super) fn for_own_head_receipt(&self) -> Self {
        let mut source = self.clone();
        source.own_head_receipt = true;
        source
    }
    pub(super) fn for_own_recovery(&self) -> Self {
        let mut source = self.clone();
        source.own_recovery = true;
        source
    }
    pub(super) fn patient(&self) -> Self {
        let mut source = self.clone();
        source.patient = true;
        source
    }
    pub(super) fn is_patient(&self) -> bool {
        self.patient
    }
    /// Persist only contexts already exposed by a proof/header of this requester's own
    /// authenticated head. The native owner commits before the proof leaves this node.
    pub(super) async fn authorize_recovery_contexts(
        &self,
        job: &Job,
        target: &ResolvedTarget,
        contexts: Vec<Digest32>,
    ) -> Result<bool> {
        if !self.own_recovery || target.target.binding.author != self.peer || contexts.is_empty() {
            return Ok(true);
        }
        let author = self.peer;
        let head = target.id;
        match self
            .write_owned(
                job,
                (128 * 1024, 128 * 1024, false),
                move |room, store| room.prepare_recovery_contexts(store, author, head, contexts),
                |pending, store, _| pending.commit(store),
                |room, _, ()| {
                    room.history_index_committed();
                    Ok(())
                },
            )
            .await?
        {
            Lookup::Found(_) => Ok(true),
            Lookup::Busy | Lookup::Missing => Ok(false),
        }
    }

    fn current(&self) -> Result<()> {
        self.current_at(ReadBoundary::Observing)
    }

    fn current_at(&self, boundary: ReadBoundary) -> Result<()> {
        if self.fence.is_retired() {
            return Err(Error::Unreachable("history request cancelled"));
        }
        if matches!(boundary, ReadBoundary::Observing)
            && !self.patient
            && Instant::now() >= self.deadline
        {
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
        self.read_charged(
            job,
            envelope,
            DIRECTORY_ENVELOPE,
            ReadBoundary::Observing,
            read,
        )
        .await
    }

    /// Settle retained local publication work without spending another wire deadline.
    /// Subscribe and sample under the same room guard; cancellation and access still apply.
    pub(super) async fn publication_readiness(
        &self,
        job: &Job,
    ) -> Result<Lookup<PublicationReadiness>> {
        self.read_charged(
            job,
            0,
            DIRECTORY_ENVELOPE,
            ReadBoundary::Committed,
            |room, store| {
                let wake = room.history_publication_wake();
                let busy = room.history_publication_busy(store)?;
                let owner = if busy {
                    room.history_publication_request(store)?
                } else {
                    None
                };
                Ok(Some(PublicationReadiness { busy, owner, wake }))
            },
        )
        .await
    }

    /// Recheck a retained sparse owner without allocating an unused wake subscription.
    pub(super) async fn publication_owner(&self, job: &Job) -> Result<Lookup<Option<RequestId>>> {
        self.read_charged(
            job,
            0,
            DIRECTORY_ENVELOPE,
            ReadBoundary::Committed,
            |room, store| Ok(Some(room.history_publication_request(store)?)),
        )
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
        F: FnOnce(&mut dyn ServedRoom, &Store) -> Result<Option<T>> + Send + 'static,
    {
        let temporary = envelope
            .checked_sub(retained)
            .filter(|temporary| *temporary >= DIRECTORY_ENVELOPE)
            .ok_or(Error::SizeLimitExceeded("history body envelope"))?;
        self.serve_read_charged(job, retained, temporary, read)
            .await
    }

    /// Reuse a working envelope already owned by an assembled record. The owned guard must
    /// include directory decoding and every temporary allocation the callback performs; only
    /// its returned value receives a new charge. Moving the guard into the blocking closure
    /// keeps that existing reservation alive even when the async waiter is cancelled. The
    /// returned value retains the guard as well, including during later actor handoffs.
    #[cfg(feature = "test-knobs")]
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
        self.read_charged(
            job,
            envelope,
            0,
            ReadBoundary::Observing,
            move |room, store| {
                let value = read(room, store, &guard)?;
                Ok(value.map(|value| (guard, value)))
            },
        )
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
        loop {
            let Some(work_job) = job.record_job(work_envelope).await else {
                return Ok(None);
            };
            let mut scratch = match work_job.reserve_or_pressure(work_envelope) {
                Ok(scratch) => scratch,
                Err(Error::HistoryCapacity(pressure)) if self.patient => {
                    self.released(*pressure).await?;
                    continue;
                }
                Err(error) => return Err(error),
            };
            let charge = scratch
                .split_off(envelope)
                .ok_or(Error::Profile("history read reservation changed"))?;
            return Ok(Some(PreparedRead { charge, scratch }));
        }
    }

    /// A patient server's wait for byte credit: the release edge, or this request's end.
    pub(super) async fn released(
        &self,
        pressure: crate::node::history_budget::BytePressure,
    ) -> Result<()> {
        let result = tokio::select! {
            biased;
            () = self.fence.retired() => Err(Error::Unreachable("history request cancelled")),
            () = pressure.released() => Ok(()),
        };
        result
    }

    /// Subscribe to the room's next published snapshot before a read whose answer may clear
    /// only when the room commits again (a recipient cut still refreshing, a publication in
    /// the middle of its transactions): every such commit publishes a new snapshot.
    pub(super) fn next_publication(&self) -> Option<tokio::sync::watch::Receiver<()>> {
        self.snapshot.as_ref().map(|cell| cell.next_publication())
    }

    /// A patient server's wait for the room's next published snapshot, or this request's end.
    pub(super) async fn published(
        &self,
        next: Option<tokio::sync::watch::Receiver<()>>,
    ) -> Result<()> {
        let mut next = next.ok_or(Error::Unreachable("history room access changed"))?;
        let result = tokio::select! {
            biased;
            () = self.fence.retired() => Err(Error::Unreachable("history request cancelled")),
            changed = next.changed() => {
                changed.map_err(|_| Error::Unreachable("history room access changed"))
            }
        };
        result
    }

    async fn read_charged<T, F>(
        &self,
        job: &Job,
        envelope: usize,
        temporary: usize,
        boundary: ReadBoundary,
        read: F,
    ) -> Result<Lookup<T>>
    where
        T: Send + 'static,
        F: FnOnce(&mut ChannelState, &Store) -> Result<Option<T>> + Send + 'static,
    {
        self.current_at(boundary)?;
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
        self.read_reserved(admission, boundary, read).await
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
            source.room_access(&room)?;
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

    /// Prepare under the room mutex, then retain only operation-owned inputs through writer
    /// acquisition and native commit. The physical worker also owns completion: cancellation of
    /// its async waiter cannot strand the reservation or publish an uncommitted mirror.
    pub(super) async fn write_owned<P, T, O, Prepare, Run, Install>(
        &self,
        job: &Job,
        allocation: (usize, usize, bool),
        prepare: Prepare,
        run: Run,
        install: Install,
    ) -> Result<Lookup<O>>
    where
        P: Send + 'static,
        T: Send + 'static,
        O: Send + 'static,
        Prepare: FnOnce(&mut ChannelState, &Store) -> Result<P> + Send + 'static,
        Run: FnOnce(P, &Store, &OwnedRoom<'_>) -> Result<T> + Send + 'static,
        Install: FnOnce(&mut ChannelState, &Store, T) -> Result<O> + Send + 'static,
    {
        self.current()?;
        let Some(admission) = self.reserve_read(job, allocation.0, allocation.1).await? else {
            return Ok(Lookup::Busy);
        };
        self.write_owned_reserved(admission, allocation.2, None, prepare, run, install)
            .await
    }

    pub(super) async fn begin_owned<P, T, O, Prepare, Run, Install>(
        &self,
        job: &Job,
        allocation: (usize, usize),
        request: RequestId,
        prepare: Prepare,
        run: Run,
        install: Install,
    ) -> Result<Lookup<O>>
    where
        P: Send + 'static,
        T: Send + 'static,
        O: Send + 'static,
        Prepare: FnOnce(&mut ChannelState, &Store) -> Result<P> + Send + 'static,
        Run: FnOnce(P, &Store, &OwnedRoom<'_>) -> Result<T> + Send + 'static,
        Install: FnOnce(&mut ChannelState, &Store, T) -> Result<O> + Send + 'static,
    {
        self.current()?;
        let Some(admission) = self.reserve_read(job, allocation.0, allocation.1).await? else {
            return Ok(Lookup::Busy);
        };
        self.write_owned_reserved(admission, false, Some(request), prepare, run, install)
            .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn write_owned_reserved<P, T, O, Prepare, Run, Install>(
        &self,
        admission: PreparedRead,
        publication: bool,
        begin: Option<RequestId>,
        prepare: Prepare,
        run: Run,
        install: Install,
    ) -> Result<Lookup<O>>
    where
        P: Send + 'static,
        T: Send + 'static,
        O: Send + 'static,
        Prepare: FnOnce(&mut ChannelState, &Store) -> Result<P> + Send + 'static,
        Run: FnOnce(P, &Store, &OwnedRoom<'_>) -> Result<T> + Send + 'static,
        Install: FnOnce(&mut ChannelState, &Store, T) -> Result<O> + Send + 'static,
    {
        let publication_flow = begin
            .map(|request| self.retirement_request().map(|root| (request, root)))
            .transpose()?;
        // Ruling correction 5. Everything this one local publication needs (its charge and
        // scratch, `admission`) is held already. What a member's own post needs, the room's one
        // pending write, is reserved only by the native worker that runs this step, under the
        // room lock it re-checks in, and is released when that step ends; it is never held
        // across a wait. An own post that holds the pending write, or waits for it
        // (`authored_save_waits`), goes first; this step waits on the room's release, with no
        // deadline.
        enum Step<A, O> {
            Wait(A),
            Done(Result<Lookup<O>>),
        }
        let owner = Arc::new(());
        let mut parts = Some((admission, prepare, run, install));
        loop {
            loop {
                let room = tokio::select! {
                    biased;
                    () = self.fence.retired() => return Err(Error::Unreachable("history request cancelled")),
                    room = self.room.clone().lock_owned() => room,
                };
                self.check_write_access(&room)?;
                // A step that finishes the room's unfinished publication does not stand aside
                // for a waiting save: that save waits for this publication to end in any case.
                if room.post_pending() || (!publication && room.authored_save_waits()) {
                    let wake = room.history_publication_wake();
                    drop(room);
                    tokio::select! {
                        biased;
                        () = self.fence.retired() => {
                            return Err(Error::Unreachable("history request cancelled"));
                        }
                        () = wake => {}
                    }
                    continue;
                }
                if !publication && room.history_publication_busy(&self.store)? {
                    if !self.patient {
                        // This operation has not inspected evidence: another native publication
                        // owns the room. Proof serving must not turn that wait into a durable
                        // EvidenceUnavailable refusal for an otherwise retained signed head. A
                        // patient (loop) answer waits for the publication's end instead, as for
                        // an own post above: answered, never refused Busy.
                        return Ok(Lookup::Busy);
                    }
                    let wake = room.history_publication_wake();
                    drop(room);
                    tokio::select! {
                        biased;
                        () = self.fence.retired() => {
                            return Err(Error::Unreachable("history request cancelled"));
                        }
                        () = wake => {}
                    }
                    continue;
                }
                break;
            }
            let inputs = parts
                .take()
                .ok_or(Error::Profile("history write lost its inputs"))?;
            let source = self.clone();
            let recovery_room = Arc::clone(&self.room);
            let recovery_store = Arc::clone(&self.store);
            let recovery_owner = Arc::clone(&owner);
            let owner = Arc::clone(&owner);
            let task = tokio::task::spawn_blocking(move || {
                let mut room = source.room.blocking_lock();
                if let Err(error) = source.check_write_access(&room) {
                    return Step::Done(Err(error));
                }
                let busy = match room.history_publication_busy(&source.store) {
                    Ok(busy) => !publication && busy,
                    Err(error) => return Step::Done(Err(error)),
                };
                if room.post_pending() || (!publication && room.authored_save_waits()) || busy {
                    return Step::Wait(inputs);
                }
                let (admission, prepare, run, install) = inputs;
                let room_instance = match room.history_instance(&source.store) {
                    Ok(instance) => instance,
                    Err(error) => return Step::Done(Err(error)),
                };
                let input_instance = room.generation();
                let input_channel = room.channel_id();
                let pending = match prepare(&mut room, &source.store) {
                    Ok(pending) => pending,
                    Err(error) => return Step::Done(Err(error)),
                };
                let mut pin = match room.reserve_pending_history_write(
                    &source.store,
                    Arc::clone(&owner),
                    publication,
                ) {
                    Ok(pin) => pin,
                    Err(error) => return Step::Done(Err(error)),
                };
                if let Some((request, root)) = publication_flow {
                    if let Err(error) =
                        room.register_history_publication_flow(&source.store, request, root)
                    {
                        room.release_pending_text(&owner, false);
                        return Step::Done(Err(error));
                    }
                }
                drop(room);
                let PreparedRead { charge, scratch } = admission;
                #[cfg(feature = "test-knobs")]
                if let Some(path) = std::env::var_os("VOX_TEST_HOLD_ROOM_WRITE")
                    .map(std::path::PathBuf::from)
                    .filter(|path| {
                        !publication
                            && std::fs::read(path)
                                .is_ok_and(|bytes| bytes.as_slice() == input_channel)
                    })
                {
                    let detail = format!(
                        "history receiver {}; publication={publication}",
                        std::any::type_name::<P>()
                    );
                    let _ = std::fs::write(path.with_extension("engaged"), &detail);
                    eprintln!("vox: holding {detail}");
                    while path.exists() {
                        std::thread::sleep(std::time::Duration::from_millis(10));
                    }
                    eprintln!("vox: released {detail}");
                }
                // Every physical callback and its room guard unwind before failure releases the
                // exact reservation. Dropping the async waiter never cancels this native owner.
                let completed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let input_source = source.clone();
                    let input_owner = Arc::clone(&owner);
                    let input_epoch = source.epoch;
                    let input_authorization = source.authorization;
                    let metadata_source = source.clone();
                    let metadata_owner = Arc::clone(&owner);
                    let metadata_instance = Arc::clone(&input_instance);
                    let input =
                        crate::node::channel::semantic_projection::SelectedReceiverInput::new(
                            move |slot| {
                                let room = input_source.room.blocking_lock();
                                room.classification_receiver_bytes(
                                    slot,
                                    &input_owner,
                                    input_epoch,
                                    &input_instance,
                                )
                            },
                            move |slot, iteration| {
                                let room = metadata_source.room.blocking_lock();
                                room.classification_receiver_metadata(
                                    slot,
                                    iteration,
                                    &metadata_owner,
                                    input_epoch,
                                    &metadata_instance,
                                )
                            },
                            move |batch| {
                                if let Some((node, generation)) = input_authorization {
                                    if super::authorization_generation_in(
                                        batch,
                                        node,
                                        input_channel,
                                        room_instance,
                                        input_epoch,
                                    )? != generation
                                    {
                                        return Err(Error::StreamRefused(
                                            super::AUTHORIZATION_CHANGED,
                                        ));
                                    }
                                }
                                Ok(())
                            },
                        );
                    let owned = OwnedRoom {
                        source: &source,
                        owner: &owner,
                        instance: room_instance,
                    };
                    // Ruling condition 2: a callback that committed nothing and whose install
                    // changed no public governance state (readiness, display, consent facts:
                    // `governance_public`, read around the install) publishes nothing.
                    // The store's transaction identity read around it tells (a commit elsewhere
                    // meanwhile only costs a needless publication, never a missed one). A failed
                    // callback publishes as before: a failed write may have poisoned the room,
                    // whose readers keep the pinned view (`publish_history_read`).
                    let before = source.store.transaction_identity();
                    let saved = input.scope(|| run(pending, &source.store, &owned));
                    let committed = source.store.transaction_identity() != before;
                    let mut room = source.room.blocking_lock();
                    let owns = room.owns_pending_history_write(&owner);
                    if owns && committed {
                        room.history_index_committed();
                    }
                    let shown = room.governance_public();
                    let result = saved.and_then(|value| {
                        if !owns {
                            return Err(Error::Unreachable("history publication owner changed"));
                        }
                        if room.epoch() != source.epoch
                            || room.history_instance(&source.store)? != room_instance
                        {
                            return Err(Error::Unreachable("history publication room changed"));
                        }
                        install(&mut room, &source.store, value)
                    });
                    let installed = room.governance_public() != shown;
                    room.release_pending_text(&owner, false);
                    // The release above still wakes the pending write's waiters.
                    let committed = committed || source.store.transaction_identity() != before;
                    let publication = if owns && (committed || installed || result.is_err()) {
                        let published = room
                            .publish_history_read(Arc::clone(&source.store))
                            .map(|_| ());
                        if published.is_err() {
                            pin.retain_saved_read();
                        }
                        published
                    } else {
                        Ok(())
                    };
                    let settled = if let Some((request, root)) = publication_flow {
                        room.settle_history_publication_flow(&source.store, request, root)
                    } else {
                        Ok(())
                    };
                    result.and_then(|value| publication.and(settled).map(|()| value))
                }));
                let result = match completed {
                    Ok(result) => result,
                    Err(_) => {
                        let error = Error::Profile("history save worker stopped");
                        let mut room = source.room.blocking_lock();
                        if room.owns_pending_history_write(&owner) {
                            room.history_index_committed();
                            room.fail_pending_history_write(&owner, &error);
                        }
                        room.release_pending_text(&owner, false);
                        let settled = if let Some((request, root)) = publication_flow {
                            room.settle_history_publication_flow(&source.store, request, root)
                        } else {
                            Ok(())
                        };
                        settled.and(Err(error))
                    }
                };
                drop(pin);
                drop(scratch);
                Step::Done(result.map(|value| {
                    Lookup::Found(Held {
                        value,
                        _charge: charge,
                    })
                }))
            });
            match task.await {
                Ok(Step::Wait(inputs)) => parts = Some(inputs),
                Ok(Step::Done(result)) => return result,
                Err(_) => {
                    // A native task that stopped outside its unwind guard may own the room's
                    // reservation. A joined cleanup, never an aborted waiter, settles it.
                    tokio::task::spawn_blocking(move || -> Result<()> {
                        let error = Error::Unreachable("history save completion stopped");
                        let mut room = recovery_room.blocking_lock();
                        if room.owns_pending_history_write(&recovery_owner) {
                            room.history_index_committed();
                            room.fail_pending_history_write(&recovery_owner, &error);
                        }
                        room.release_pending_text(&recovery_owner, false);
                        if let Some((request, root)) = publication_flow {
                            room.settle_history_publication_flow(&recovery_store, request, root)?;
                        }
                        Ok(())
                    })
                    .await
                    .map_err(|_| Error::Unreachable("history save cleanup stopped"))??;
                    return Err(Error::Unreachable("history save completion stopped"));
                }
            }
        }
    }

    /// The serving peer may still write here: the room's epoch, its membership (or the
    /// departed receipt or recovery standing it was admitted by) and no applied removal.
    fn check_write_access(&self, room: &ChannelState) -> Result<()> {
        self.current()?;
        self.room_access(room)?;
        Ok(())
    }

    pub(super) async fn write_admission<T, F>(
        &self,
        job: &Job,
        allocation: (usize, usize),
        operation: F,
    ) -> Result<Lookup<T>>
    where
        T: Send + 'static,
        F: FnOnce(&crate::node::channel::HistoryAdmission<'_>, &Store) -> Result<T>
            + Send
            + 'static,
    {
        let authorization = self.authorization;
        self.write_owned(
            job,
            (allocation.0, allocation.1, false),
            move |room, store| {
                if let Some((node, expected)) = authorization {
                    if super::authorization_generation(
                        store,
                        node,
                        room.channel_id(),
                        room.history_instance(store)?,
                        room.epoch(),
                    )? != expected
                    {
                        return Err(Error::Profile("history authorization changed"));
                    }
                }
                room.prepare_history_admission(store, authorization)
            },
            move |pending, store, _| pending.with(|room| operation(room, store)),
            |_, _, value| Ok(value),
        )
        .await
    }

    pub(super) async fn authorize(&self, job: &Job) -> Result<bool> {
        Ok(matches!(
            self.serve_read_charged(job, 0, 0, |_, _| Ok(Some(())))
                .await?,
            Lookup::Found(_)
        ))
    }

    /// The per-frame authorization of [`Self::authorize`], for a frame of an answer already
    /// assembled and about to be written: the room's snapshot cell it was served from still
    /// publishes (it is revoked when the room is poisoned, locked or closed), and the peer still
    /// has, in that snapshot, the access this answer was served under, its applied removal read
    /// in the store as before. No job: one removal read, while no shared admission is held.
    pub(super) async fn still_authorized(&self) -> Result<()> {
        let snapshot = self
            .snapshot
            .as_ref()
            .and_then(|cell| cell.current())
            .ok_or(Error::Unreachable("history room access changed"))?;
        let source = self.clone();
        tokio::task::spawn_blocking(move || source.snapshot_access(&snapshot))
            .await
            .map_err(|_| Error::Unreachable("history disk reader stopped"))?
    }

    /// Resolve the head a request names to one committed source head of the same room, scope and
    /// author whose authenticated material serves it (ADR-053 P). A head this node committed
    /// serves as itself, and so does the author's one kept unresolved head (MP-9 rule 6), by its
    /// exact id only: it is never compared with, or served as, a prefix of the committed head,
    /// and what is served under it is only what this node proved under it. Otherwise the source
    /// is this node's committed head of that author, at least as large, and the asked complete
    /// root must equal that source's prefix [1,n]: from the canonical prefix index, or rebuilt by
    /// the cooperative repair under this request's own job, lifetime and work slices. Nothing is
    /// committed, observed or written; a differing prefix, a smaller source or missing material
    /// is Missing, never a verdict on the asker.
    pub(super) async fn resolve(
        &self,
        job: &Job,
        target: HeadTarget,
        stage: &'static str,
    ) -> Result<Lookup<ResolvedTarget>> {
        self.current()?;
        let gate = prefix_gate_mutant(stage);
        // The P guards' forked provider (test-knobs; always false otherwise).
        let fork = crate::node::channel::bad_prefix("fork");
        let found = self
            .serve_read(job, 128 * 1024, move |room, store| {
                let read = room.history_read(store)?;
                let id = target.id();
                if read.history_head_committed(&id, target.binding)?
                    || (read.history_unresolved_head(&target.binding.author)? == Some(id)
                        && read.history_head(&id)?.is_some())
                {
                    return Ok(Some((
                        ResolvedTarget::pinned(target, id),
                        true,
                        target.root.leaves,
                    )));
                }
                if gate || target.root.leaves == 0 {
                    return Ok(None);
                }
                let Some(source) = read
                    .sparse_author(&target.binding.author, target.binding.scope)?
                    .and_then(|state| state.committed)
                else {
                    return Ok(None);
                };
                let head = read
                    .history_head(&source)?
                    .ok_or(Error::MalformedAtRest("committed history head missing"))?;
                if head.binding != target.binding || head.root.leaves < target.root.leaves {
                    return Ok(None);
                }
                let prefix = if head.root.leaves == target.root.leaves {
                    Some(head.root)
                } else {
                    read.history_range(target.binding, 1, target.root.leaves)?
                };
                let resolved = ResolvedTarget::pinned(target, source);
                Ok(match prefix {
                    Some(prefix) if prefix == target.root || fork => {
                        Some((resolved, true, head.root.leaves))
                    }
                    Some(_) => None,
                    None => Some((resolved, false, head.root.leaves)),
                })
            })
            .await?;
        let held = match found {
            Lookup::Found(held) => held,
            Lookup::Busy => return Ok(Lookup::Busy),
            Lookup::Missing => return Ok(Lookup::Missing),
        };
        let (resolved, settled, source_size) = held.value;
        let resolved = if settled {
            Lookup::Found(Held {
                value: resolved,
                _charge: held._charge,
            })
        } else {
            let job = held._charge.job();
            match self.range(&job, &resolved, 1, target.root.leaves).await? {
                // The repair returns Missing for a root differing from the asked one; recheck
                // the complete descriptor here before anything is served under this target.
                Lookup::Found(found) if found.value == target.root || fork => Lookup::Found(Held {
                    value: resolved,
                    _charge: found._charge,
                }),
                Lookup::Found(_) | Lookup::Missing => Lookup::Missing,
                Lookup::Busy => Lookup::Busy,
            }
        };
        #[cfg(feature = "test-knobs")]
        if let Lookup::Found(held) = &resolved {
            if held.value.source != held.value.id {
                // The act's evidence that this node served a head it never committed.
                eprintln!(
                    "vox: prefix resolved stage={stage} author={} size={} head={} from \
                     committed source size={source_size}",
                    crate::node::link::b32_encode(&target.binding.author),
                    target.root.leaves,
                    crate::node::link::b32_encode(&held.value.id),
                );
                if fork {
                    eprintln!(
                        "vox: bad prefix served mode=fork stage={stage} size={}",
                        target.root.leaves
                    );
                }
            }
        }
        #[cfg(not(feature = "test-knobs"))]
        let _ = source_size;
        Ok(resolved)
    }

    async fn range(
        &self,
        job: &Job,
        target: &ResolvedTarget,
        start: u64,
        leaves: u64,
    ) -> Result<Lookup<Descriptor>> {
        let mut cursor = crate::node::channel::ProofRangeRestore::new(target, start, leaves)?;
        // A client building its own proof reads the same published snapshot of its room.
        let cell = match &self.snapshot {
            Some(cell) => Arc::clone(cell),
            None => self.room.lock().await.room_snapshot(),
        };
        loop {
            self.current()?;
            if self.room_wait_mutant().await? {
                return Ok(Lookup::Busy);
            }
            // One bounded physical step: Directory scratch is separately reserved; this
            // envelope covers the two contexts/join/encoded context and scalar DFS.
            let Some(admission) = self
                .reserve_read(
                    job,
                    crate::node::channel::ProofRangeRestore::WORK_BYTES,
                    DIRECTORY_ENVELOPE,
                )
                .await?
            else {
                return Ok(Lookup::Busy);
            };
            // Subscribed before the read: a step that meets a publication in progress waits
            // for the room's next published snapshot (the publication's end commits).
            let published = cell.next_publication();
            let snapshot = cell
                .current()
                .ok_or(Error::Unreachable("history room access changed"))?;
            let source = self.clone();
            let (next, outcome, charge) = tokio::task::spawn_blocking(move || {
                let PreparedRead { charge, scratch } = admission;
                source.current()?;
                source.snapshot_access(&snapshot)?;
                let step = crate::node::channel::serve_proof_range(
                    &snapshot,
                    &source.store,
                    source.peer,
                    &mut cursor,
                )?;
                drop(scratch);
                Ok::<_, Error>((cursor, step, charge))
            })
            .await
            .map_err(|_| Error::Unreachable("history disk reader stopped"))??;
            cursor = next;
            match outcome {
                crate::node::channel::ProofRangeStep::Complete(value) => {
                    return Ok(Lookup::Found(Held {
                        value,
                        _charge: charge,
                    }));
                }
                crate::node::channel::ProofRangeStep::Missing => return Ok(Lookup::Missing),
                crate::node::channel::ProofRangeStep::Busy if self.patient => {
                    drop(charge);
                    self.published(Some(published)).await?;
                    continue;
                }
                crate::node::channel::ProofRangeStep::Busy => return Ok(Lookup::Busy),
                crate::node::channel::ProofRangeStep::Progress => {}
            }
            // The worker, snapshot read and decode buffers have actually dropped. Same
            // request/Job remains owned; this is not a second admission or a timer retry.
            drop(charge);
            tokio::task::yield_now().await;
        }
    }

    /// Proof construction reads only indexed canonical ranges, never a content archive. The
    /// response owns the output envelope and each disk reader separately owns its temporary
    /// envelope. Verification and authority still belong to the receiving admission path.
    pub(super) async fn proof(
        &self,
        job: &Job,
        target: &ResolvedTarget,
        kind: ProofKind,
        from: u64,
        to: u64,
    ) -> Result<Lookup<Proof>> {
        let head = &target.target;
        self.current()?;
        let charge = loop {
            match job.reserve_or_pressure(1024 * 1024) {
                Ok(charge) => break charge,
                Err(Error::HistoryCapacity(pressure)) if self.patient => {
                    self.released(*pressure).await?;
                }
                // Serving retains wire Busy; a client retains the exact byte-release wait.
                Err(Error::HistoryCapacity(_)) if self.authorization.is_none() => {
                    return Ok(Lookup::Busy);
                }
                Err(error) => return Err(error),
            }
        };
        if to > head.root.leaves {
            return Err(Error::MalformedBundle("proof exceeds requested head"));
        }
        let proof = if kind == ProofKind::Control {
            return self.control_proof(job, target, from, to, charge).await;
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
                match self.range(job, target, range.start, range.leaves).await? {
                    Lookup::Found(found) => descriptors.push(found.value),
                    Lookup::Busy => return Ok(Lookup::Busy),
                    Lookup::Missing => return Ok(Lookup::Missing),
                }
                // No room lock or store snapshot survives even one descriptor lookup.
                tokio::task::yield_now().await;
            }
            #[cfg(feature = "test-knobs")]
            {
                let only = match kind {
                    ProofKind::Inclusion => "corrupt-inclusion",
                    ProofKind::Consistency => "corrupt-consistency",
                    ProofKind::Control => "corrupt-control",
                };
                if target.source != target.id
                    && (crate::node::channel::bad_prefix("corrupt")
                        || crate::node::channel::bad_prefix(only))
                {
                    if let Some(first) = descriptors.first_mut() {
                        first.hash[0] ^= 1;
                        eprintln!(
                            "vox: bad prefix served mode=corrupt kind={kind:?} size={}",
                            head.root.leaves
                        );
                    }
                }
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
                        match self.range(job, target, 1, from).await? {
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
        target: &ResolvedTarget,
        lo: u64,
        mut hi: u64,
        charge: BufferCharge,
    ) -> Result<Lookup<Proof>> {
        let head = &target.target;
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
                let descriptor = match self.range(job, target, start, leaves).await? {
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
                        .serve_read(job, 128 * 1024, move |room, store| {
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
        #[cfg(feature = "test-knobs")]
        let tokens = {
            let mut tokens = tokens;
            if target.source != target.id
                && (crate::node::channel::bad_prefix("corrupt")
                    || crate::node::channel::bad_prefix("corrupt-control"))
            {
                if let Some(first) = tokens.iter_mut().find_map(|token| match token {
                    ControlToken::Collapse(descriptor) => Some(descriptor),
                    _ => None,
                }) {
                    first.hash[0] ^= 1;
                    eprintln!(
                        "vox: bad prefix served mode=corrupt kind=Control size={}",
                        head.root.leaves
                    );
                }
            }
            tokens
        };
        self.current()?;
        Ok(Lookup::Found(Held {
            value: Proof::Control(ControlRangeProof {
                head_id: target.id,
                lo,
                hi,
                tokens,
            }),
            _charge: charge,
        }))
    }
}

/// `VOX_MUTANT_PREFIX_GATE=header|proof|entry|inclusion|consistency|control`: that serving
/// stage answers only under a head this node committed itself, as before ADR-053 P (`entry` is
/// Entry and Page; `proof` is every proof kind). Says so once when the daemon first reads it.
#[cfg(feature = "test-knobs")]
fn prefix_gate_mutant(stage: &str) -> bool {
    static GATE: std::sync::LazyLock<Option<String>> = std::sync::LazyLock::new(|| {
        let gate = std::env::var("VOX_MUTANT_PREFIX_GATE").ok();
        if let Some(gate) = &gate {
            eprintln!(
                "vox: VOX_MUTANT_PREFIX_GATE={gate} engaged: that stage serves committed heads only"
            );
        }
        gate
    });
    GATE.as_deref().is_some_and(|gate| {
        gate == stage
            || (gate == "proof" && matches!(stage, "inclusion" | "consistency" | "control"))
    })
}

#[cfg(not(feature = "test-knobs"))]
const fn prefix_gate_mutant(_stage: &str) -> bool {
    false
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
}

/// The room again between two native transactions of one owned write, which still holds the
/// room's pending write: the mutex is taken for one bounded in-memory step and dropped before
/// the next native commit, as the write's own prepare and install are. Nothing is published
/// until the write's one install ends.
pub(super) struct OwnedRoom<'a> {
    source: &'a Source,
    owner: &'a Arc<()>,
    instance: [u8; 16],
}

impl OwnedRoom<'_> {
    /// The room, after a commit of this write: still this write's own, still the room it began
    /// in. An install of what committed needs no more. While it is held, the native write's
    /// receiver input is withheld (`SelectedReceiverInput::withhold`): a step under this lock
    /// runs as the write's own prepare and install do, outside that input, so nothing it calls
    /// can lock the room a second time on this thread.
    pub(super) fn lock(&self) -> Result<RoomHeld<'_>> {
        let withheld = crate::node::channel::semantic_projection::SelectedReceiverInput::withhold();
        let room = self.source.room.blocking_lock();
        if !room.owns_pending_history_write(self.owner) {
            return Err(Error::Unreachable("history publication owner changed"));
        }
        if room.epoch() != self.source.epoch
            || room.history_instance(&self.source.store)? != self.instance
        {
            return Err(Error::Unreachable("history publication room changed"));
        }
        room.history_index_committed();
        Ok(RoomHeld {
            room,
            _withheld: withheld,
        })
    }

    /// The room before a further write of this owned write: the same access every owned write
    /// checks before it prepares (`check_write_access`).
    pub(super) fn lock_for_write(&self) -> Result<RoomHeld<'_>> {
        let room = self.lock()?;
        self.source.check_write_access(&room)?;
        Ok(room)
    }
}

/// The room held by [`OwnedRoom`]; the lock is released before the receiver input comes back.
pub(super) struct RoomHeld<'a> {
    room: tokio::sync::MutexGuard<'a, ChannelState>,
    _withheld: crate::node::channel::semantic_projection::Withheld,
}

impl std::ops::Deref for RoomHeld<'_> {
    type Target = ChannelState;

    fn deref(&self) -> &ChannelState {
        &self.room
    }
}

impl std::ops::DerefMut for RoomHeld<'_> {
    fn deref_mut(&mut self) -> &mut ChannelState {
        &mut self.room
    }
}
