//! Receive one explicitly scheduled response quantum. A wire continuation never starts
//! another request; provisional bodies and verifier cursors survive only in bounded local slots.

use std::sync::{Arc, Mutex as StdMutex};

use crate::error::{Error, Result};
use crate::hash::Digest32;
use crate::node::channel::{
    entry_store::sparse::CursorBinding, ChannelState, HistoryAdmissionRoom,
};
use crate::node::history_demand::{self as demand, Active, Context};
use crate::node::store::{ReceivedFlow, Store};

use super::admission::{self, Advanced, Staged};
use super::source::{Lookup, OwnedRoom, Source};
use super::{ProofKind, Query, RequestId};

// Includes the actual maximum descriptor trace capacity, overlapping the verifier,
// generated contexts and Directory scratch under the existing 12-MiB record job.
const VERIFY_ENVELOPE: usize = 4 * 1024 * 1024 + crate::log::history::PROOF_RANGE_BYTES;
const RECORD_METADATA_WORK: usize = 64 * 1024;
const ENTRY_VALIDATION_WORK: usize = 512 * 1024;

fn fresh_worker_peak(job: &crate::node::history_budget::Job, bytes: usize) -> Result<usize> {
    bytes
        .checked_add(
            if job.lane() == crate::node::history_budget::Lane::Control {
                crate::node::history_budget::FLOW_STATE_BYTES
            } else {
                0
            },
        )
        .ok_or(Error::SizeLimitExceeded(
            "history record reconstruction envelope",
        ))
}

/// Owned activation supplied by the actor after explicit archive demand or current live/control
/// scheduling. Constructing a receiver never starts, resumes or replaces that activation.
#[derive(Clone)]
pub(crate) struct Staging {
    pub(crate) context: Arc<Context>,
    pub(crate) active: Arc<StdMutex<Active>>,
}

pub(crate) struct Receiver {
    source: Source,
    generation: Digest32,
    node: Digest32,
    received: ReceivedFlow,
    staging: Option<Staging>,
    historical: bool,
    key_body: Option<super::KeyBodyNeed>,
    own_head_observed: Arc<std::sync::atomic::AtomicBool>,
    /// The admission root's checked entry held in memory by the connection that fetched it:
    /// the admission frontier's record source instead of the node's staging record (C5).
    held: Option<super::pull::Ready>,
}

pub(crate) enum LocalProof {
    Verified(CursorBinding),
    Busy,
    Missing,
}

impl Receiver {
    // The receiver retains one exact room, peer, grant, staging slot and cancellation scope.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        room: Arc<crate::node::channel::RoomLock>,
        store: Arc<Store>,
        peer: Digest32,
        epoch: u64,
        generation: Digest32,
        node: Digest32,
        received: ReceivedFlow,
        staging: Option<Staging>,
        historical: bool,
        key_body: Option<super::KeyBodyNeed>,
        fence: Arc<crate::transport::stream_transport::Fence>,
        deadline: tokio::time::Instant,
        work_committed: Arc<std::sync::atomic::AtomicBool>,
        own_head_observed: Arc<std::sync::atomic::AtomicBool>,
        retirement_request: RequestId,
    ) -> Self {
        Self {
            source: Source::new(
                room,
                store,
                epoch,
                peer,
                fence,
                deadline,
                Some((node, generation)),
                work_committed,
                Some(retirement_request),
            ),
            generation,
            node,
            received,
            staging,
            historical,
            key_body,
            own_head_observed,
            held: None,
        }
    }

    /// Admit from the body held in memory, never from the staging record.
    pub(crate) fn with_held(mut self, held: super::pull::Ready) -> Self {
        self.held = Some(held);
        self
    }

    /// Build an exact control proof from this node's own canonical history and admit it through
    /// the same verifier path as a wire proof. A peer need not archive proof material for a head
    /// authored here, and its inability to serve that proof says nothing about the local head.
    pub(crate) async fn local_proof(
        &self,
        job: &crate::node::history_budget::Job,
        request: RequestId,
        query: Query,
    ) -> Result<LocalProof> {
        // Head, proof construction and verifier staging temporarily overlap. Admit that bounded
        // envelope on the existing large-control lane instead of repeatedly exhausting the
        // ordinary 8-MiB control slice before admission can persist the verifier.
        let Some(work_job) = job.record_job(12 * 1024 * 1024).await else {
            return Ok(LocalProof::Busy);
        };
        let Query::Proof {
            head,
            kind,
            from,
            to,
        } = query
        else {
            return Ok(LocalProof::Missing);
        };
        let local = self.node;
        let signed = self
            .read(
                &work_job,
                crate::log::history::MAX_HEADER_BYTES,
                move |room, store| {
                    let input = room.history_read(store)?;
                    Ok(input
                        .history_head(&head)?
                        .filter(|signed| signed.binding.author == local))
                },
            )
            .await?;
        let signed = match signed {
            Lookup::Found(signed) => signed,
            Lookup::Busy => return Ok(LocalProof::Busy),
            Lookup::Missing => return Ok(LocalProof::Missing),
        };
        let proof = match self
            .source
            .proof(
                &work_job,
                &crate::node::channel::ResolvedTarget::exact(&signed.value),
                kind,
                from,
                to,
            )
            .await?
        {
            Lookup::Found(proof) => proof,
            Lookup::Busy => return Ok(LocalProof::Busy),
            Lookup::Missing => return Ok(LocalProof::Missing),
        };
        let generation = self.generation;
        let committed = self.source.commit_ledger();
        let own_observed = Arc::clone(&self.own_head_observed);
        let staged = self
            .source
            .write_admission(
                &work_job,
                (VERIFY_ENVELOPE, 4 * 1024 * 1024),
                move |room, store| {
                    admission::stage(
                        room,
                        store,
                        (&committed, &own_observed),
                        request,
                        generation,
                        &query,
                        super::Object::Proof(proof.value),
                    )
                },
            )
            .await?;
        Ok(match staged {
            Lookup::Found(staged) => match staged.value {
                Staged::Verifier(binding) => {
                    self.source.note_work_committed();
                    LocalProof::Verified(binding)
                }
                Staged::Busy => LocalProof::Busy,
                _ => {
                    return Err(Error::MalformedAtRest(
                        "local control proof produced unrelated staging",
                    ));
                }
            },
            Lookup::Busy => LocalProof::Busy,
            Lookup::Missing => LocalProof::Missing,
        })
    }

    /// MP-9: apply a fork proof (found by comparing two signed heads, or a peer's kept proof)
    /// through the room, as a fork at a held position is applied. `None` is local busy.
    async fn record_fork(
        &self,
        job: &crate::node::history_budget::Job,
        existing: crate::log::entry::Entry,
        conflicting: crate::log::entry::Entry,
    ) -> Result<Option<bool>> {
        let recorded = self
            .source
            .write_owned(
                job,
                (64 * 1024, 0, false),
                |_, _| Ok(()),
                |(), _, _| Ok(()),
                move |room, store, ()| room.record_history_fork(store, existing, conflicting),
            )
            .await?;
        Ok(match recorded {
            Lookup::Found(recorded) => Some(recorded.value),
            Lookup::Busy | Lookup::Missing => None,
        })
    }

    /// One persisted verifier slice. This cannot send a request or follow a missing context.
    pub(super) async fn advance(
        &self,
        job: &crate::node::history_budget::Job,
        binding: CursorBinding,
    ) -> Result<Lookup<Advanced>> {
        if binding.generation != self.generation || binding.room == [0; 32] {
            return Err(Error::Profile("history verifier activation changed"));
        }
        let Some(work_job) = job.record_job(12 * 1024 * 1024).await else {
            return Ok(Lookup::Busy);
        };
        let commit_ledger = self.source.commit_ledger();
        let advanced = self
            .source
            .write_admission(
                &work_job,
                (VERIFY_ENVELOPE, 4 * 1024 * 1024),
                move |room, store| {
                    if room.channel_id() != binding.room {
                        return Err(Error::Profile("history verifier room changed"));
                    }
                    admission::advance(room, store, &commit_ledger, &binding)
                },
            )
            .await?;
        Ok(advanced)
    }
}

/// The complete record and its entire parse/seal/render working envelope travel together.
/// No actor handoff may retain the entry while dropping this reservation.
pub(crate) struct Record {
    pub(crate) entry: crate::log::entry::Entry,
    job: crate::node::history_budget::Job,
    _charge: crate::node::history_budget::BufferCharge,
    admission: Option<demand::AdmissionCharge>,
    staged: Option<(RequestId, Digest32, StagedAdmission)>,
    /// Its body came from the connection's private assembly, not from staging.
    memory: bool,
}

#[derive(Clone, Copy)]
enum StagedAdmission {
    Body,
    RoleHeader,
}
pub(crate) enum Assembly {
    Ready(Arc<Record>),
    Pending,
    Busy,
    BytePressure(crate::node::history_budget::BytePressure),
}

impl Receiver {
    /// Assemble exactly the already requested entry, at most256 persisted64-KiB pages.
    /// This is not a history fetch and cannot select another entry or begin another demand.
    pub(crate) async fn assemble(
        &self,
        job: &crate::node::history_budget::Job,
        completion: bool,
    ) -> Result<Assembly> {
        let Some(staging) = &self.staging else {
            return Ok(Assembly::Pending);
        };
        let staging = staging.clone();
        let job = job.clone();
        let fence = self.source.fence.clone();
        let deadline = self.source.deadline;
        let generation = self.generation;
        tokio::task::spawn_blocking(move || {
            current(&fence, deadline)?;
            let active = staging
                .active
                .lock()
                .map_err(|_| Error::Profile("history activation lock failed"))?;
            let Some(snapshot) = demand::inspect(&staging.context, &job)? else {
                return Ok(Assembly::Pending);
            };
            if !active.matches(snapshot.state()) || active.binding().grant != generation {
                return Err(Error::Profile("history activation changed"));
            }
            let Some(body) = &snapshot.state().body else {
                return Ok(Assembly::Pending);
            };
            if body.offset != body.length {
                return Ok(Assembly::Pending);
            }
            let record_envelope = 5
                * (body.length as usize + crate::log::history::MAX_HEADER_BYTES + 9)
                + VERIFY_ENVELOPE;
            let envelope = if completion {
                demand::AdmissionCharge::total(record_envelope)?
            } else {
                record_envelope
            };
            let Some(record_job) =
                tokio::runtime::Handle::current().block_on(job.record_job(envelope))
            else {
                return Ok(Assembly::Busy);
            };
            let peak = fresh_worker_peak(
                &record_job,
                demand::AdmissionCharge::reconstruction_peak(
                    envelope,
                    job.lane() == record_job.lane(),
                )?,
            )?;
            let pressure = record_job.byte_pressure(peak)?;
            let Some(mut charge) = record_job.reserve(envelope) else {
                return Ok(Assembly::BytePressure(pressure));
            };
            let admission = completion
                .then(|| demand::AdmissionCharge::split_from(&mut charge))
                .transpose()?;
            let mut entry = crate::log::entry::Entry::from_wire(&body.header)?;
            let mut payload = Vec::with_capacity(body.length as usize);
            for page in 1..=body
                .length
                .div_ceil(crate::log::history::MAX_CHUNK_BYTES as u64)
            {
                current(&fence, deadline)?;
                let held = demand::read_page(&staging.context, &active, page, &record_job)?;
                payload.extend_from_slice(held.as_slice());
            }
            entry.payload = Some(payload);
            entry.verify_payload_binding()?;
            if entry.entry_hash() != body.entry {
                return Err(Error::MalformedAtRest("staged entry hash changed"));
            }
            current(&fence, deadline)?;
            Ok(Assembly::Ready(Arc::new(Record {
                entry,
                job: record_job,
                _charge: charge,
                admission,
                staged: Some((active.request(), generation, StagedAdmission::Body)),
                memory: false,
            })))
        })
        .await
        .map_err(|_| Error::Unreachable("history record assembly stopped"))?
    }

    pub(super) async fn start_entry(
        &self,
        request: RequestId,
        head: Digest32,
        record: Arc<Record>,
        require_body: bool,
        context_ready: bool,
    ) -> Result<Lookup<(Arc<Record>, admission::EntryStart)>> {
        let generation = self.generation;
        let job = record.job.clone();
        let committed = self.source.commit_ledger();
        // The record already owns the complete verification/parse envelope.
        self.source
            .write_admission(&job, (64 * 1024, 0), move |room, store| {
                let outcome = admission::start_entry(
                    room,
                    store,
                    &committed,
                    request,
                    generation,
                    head,
                    &record.entry,
                    require_body,
                    context_ready,
                )?;
                Ok((record, outcome))
            })
            .await
    }

    pub(super) async fn advance_entry(
        &self,
        record: Arc<Record>,
        binding: CursorBinding,
    ) -> Result<Lookup<(Arc<Record>, admission::EntryAdvanced)>> {
        if binding.generation != self.generation {
            return Err(Error::Profile("history entry activation changed"));
        }
        let job = record.job.clone();
        let committed = self.source.commit_ledger();
        self.source
            .write_admission(&job, (ENTRY_VALIDATION_WORK, 0), move |room, store| {
                if record.entry.skeleton.author_id != binding.author
                    || record.entry.skeleton.seq != binding.from
                {
                    return Err(Error::Profile("history entry record changed"));
                }
                if room.channel_id() != binding.room {
                    return Err(Error::Profile("history entry room changed"));
                }
                let outcome = admission::advance_entry(room, store, &committed, binding)?;
                Ok((record, outcome))
            })
            .await
    }
}

fn current(
    fence: &crate::transport::stream_transport::Fence,
    deadline: tokio::time::Instant,
) -> Result<()> {
    if fence.is_retired() {
        return Err(Error::Unreachable("history request cancelled"));
    }
    if tokio::time::Instant::now() >= deadline {
        return Err(Error::Unreachable("history request deadline elapsed"));
    }
    Ok(())
}

impl Receiver {
    /// Load one exact authenticated provisional header. Reserving from its signed length also
    /// covers a later effect worker opening an already held body; no archive scan is involved.
    pub(super) async fn header_record(
        &self,
        job: &crate::node::history_budget::Job,
        head: Digest32,
        seq: u64,
        completion: bool,
        local_work: usize,
    ) -> Result<Assembly> {
        let Some(work_job) = job.record_job(12 * 1024 * 1024).await else {
            return Ok(Assembly::Busy);
        };
        let header = self
            .read(&work_job, RECORD_METADATA_WORK, move |room, store| {
                let input = room.history_read(store)?;
                if let Some(pending) = input.history_pending_header(&head, seq)? {
                    return Ok(Some(pending));
                }
                // A pending header is deleted when its position is published; under a head
                // in the accepted chain the published one is the same header.
                let Some(target) = input.history_head(&head)? else {
                    return Ok(None);
                };
                if !input.history_head_accepted(&head, target.binding)? {
                    return Ok(None);
                }
                input.history_position_header(&target.binding.author, seq)
            })
            .await?;
        let Lookup::Found(header) = header else {
            return Ok(match header {
                Lookup::Busy => Assembly::Busy,
                _ => Assembly::Pending,
            });
        };
        let record_envelope = 5
            * (header.value.skeleton.payload_len as usize
                + crate::log::history::MAX_HEADER_BYTES
                + 9)
            + VERIFY_ENVELOPE;
        let envelope = if completion {
            demand::AdmissionCharge::total(record_envelope)?
        } else {
            record_envelope
        };
        // The returned header retains the metadata worker which admitted it. Reuse that exact
        // worker for reconstruction while the header remains live. Asking the original Control
        // job for another foreground worker would retain one scarce owner while waiting for a
        // second owner from the same bounded pool.
        let record_job = header.job();
        let peak = fresh_worker_peak(
            &record_job,
            envelope
                .checked_add(local_work.max(RECORD_METADATA_WORK))
                .ok_or(Error::SizeLimitExceeded(
                    "history record reconstruction envelope",
                ))?,
        )?;
        let pressure = record_job.byte_pressure(peak)?;
        let Some(mut charge) = record_job.reserve(envelope) else {
            return Ok(Assembly::BytePressure(pressure));
        };
        let admission = completion
            .then(|| demand::AdmissionCharge::split_from(&mut charge))
            .transpose()?;
        let entry = header.value;
        Ok(Assembly::Ready(Arc::new(Record {
            entry,
            job: record_job,
            _charge: charge,
            admission,
            staged: None,
            memory: false,
        })))
    }

    /// The whole checked entry the admitting connection holds in memory for `head`/`seq`.
    async fn held_record(
        &self,
        job: &crate::node::history_budget::Job,
        head: Digest32,
        seq: u64,
    ) -> Result<Option<Assembly>> {
        let Some(entry) = self
            .held
            .as_ref()
            .filter(|held| held.head == head && held.entry.skeleton.seq == seq)
            .map(|held| &held.entry)
            .filter(|entry| entry.payload.is_some())
        else {
            return Ok(None);
        };
        let envelope = 5
            * (entry.skeleton.payload_len as usize + crate::log::history::MAX_HEADER_BYTES + 9)
            + VERIFY_ENVELOPE;
        let Some(record_job) = job.record_job(envelope).await else {
            return Ok(Some(Assembly::Busy));
        };
        let pressure = record_job.byte_pressure(fresh_worker_peak(&record_job, envelope)?)?;
        let Some(charge) = record_job.reserve(envelope) else {
            return Ok(Some(Assembly::BytePressure(pressure)));
        };
        Ok(Some(Assembly::Ready(Arc::new(Record {
            entry: (**entry).clone(),
            job: record_job,
            _charge: charge,
            admission: None,
            staged: None,
            memory: true,
        }))))
    }

    /// One entry's admission as ONE owned write of the room (`design/adopt/
    /// ruling-admission-order.md`, Amendment 1 §3). From Begin (`begin`), or from its own
    /// unfinished publication (`Publish`), one transaction publishes the source together with the
    /// governance facts over it (`PendingHistorySource::publish_in`). Then, the room's
    /// publication idle, the fold's bounded turn a governance change owes and one effect
    /// quantum, each prepared and installed under the room lock and saved off it, all under the
    /// one pending write this step reserved; the room is published once, at the write's end.
    pub(super) async fn admit_entry(
        &self,
        record: Arc<Record>,
        binding: CursorBinding,
        now: crate::time::Ms,
        begin: bool,
    ) -> Result<Lookup<(Arc<Record>, Admitted)>> {
        if binding.generation != self.generation {
            return Err(Error::Profile("history publication activation changed"));
        }
        // A proof can keep a remote departure's effect pending while the leaver probes a live
        // head; nothing else waits here.
        #[cfg(feature = "test-knobs")]
        let hold_effect = record.entry.skeleton.v2.as_ref().map(|header| header.kind)
            == Some(crate::log::history::SignedEntryKind::Governance)
            && match crate::governance::entry::GovEntry::body_bound_to(&record.entry) {
                Ok(crate::governance::entry::GovBody::Presence(presence)) => !presence.body.here,
                Ok(_) => false,
                Err(_) => true,
            }
            && self.departure_held(record.entry.skeleton.author_id).await?;
        #[cfg(not(feature = "test-knobs"))]
        let hold_effect = false;
        let kind = record.entry.skeleton.v2.as_ref().map(|header| header.kind);
        // The fold's turn runs inside this write: reserve its scratch as `Operation::Governance`.
        let scratch = if matches!(
            kind,
            Some(
                crate::log::history::SignedEntryKind::Governance
                    | crate::log::history::SignedEntryKind::StepPolicy
            )
        ) {
            4 * 1024 * 1024
        } else {
            0
        };
        let job = record.job.clone();
        let grant = self.grant();
        let effect = self.effect_inputs(now);
        if begin {
            let authorization = self.source.authorization();
            return self
                .source
                .begin_owned(
                    &job,
                    (64 * 1024, scratch),
                    binding.request,
                    move |room, store| {
                        grant.check(room, store)?;
                        if record.entry.skeleton.author_id != binding.author
                            || record.entry.skeleton.seq != binding.from
                        {
                            return Err(Error::Profile("history entry record changed"));
                        }
                        if room.channel_id() != binding.room {
                            return Err(Error::Profile("history entry room changed"));
                        }
                        let facts = room.prepare_history_admission(store, authorization)?;
                        let instance = room.history_instance(store)?;
                        let epoch = room.epoch();
                        let pending =
                            room.prepare_history_begin(store, &record.entry, binding.request)?;
                        Ok((record, facts, pending, instance, epoch))
                    },
                    move |(record, facts, pending, instance, epoch), store, owned| {
                        // The validation token, re-derived from its sealed cursor in this write.
                        let validated = match facts.with(|room| {
                            admission::advance_entry(room, store, &effect.committed, binding)
                        })? {
                            admission::EntryAdvanced::Validated(validated) => validated,
                            admission::EntryAdvanced::Busy => return Ok((record, Admitted::Busy)),
                            _ => {
                                return Err(Error::Profile(
                                    "completed history validation requires renewed evidence",
                                ))
                            }
                        };
                        let saved = effect.received.scope(|| {
                            pending.commit(
                                store,
                                &effect.committed,
                                binding.request,
                                &record.entry,
                                &validated,
                                binding,
                                now,
                                &effect.received,
                                |batch| grant.check_batch(batch, binding.room, instance, epoch),
                            )
                        });
                        let published = {
                            let mut room = owned.lock()?;
                            match room.finish_history_begin(saved)? {
                                crate::node::channel::HistorySourceStart::Busy => {
                                    return Ok((record, Admitted::Busy));
                                }
                                crate::node::channel::HistorySourceStart::Duplicate => {
                                    return Ok((record, Admitted::Duplicate));
                                }
                                crate::node::channel::HistorySourceStart::Started(published) => {
                                    room.install_history_source(&record.entry, &published)?;
                                    published
                                }
                            }
                        };
                        let admitted =
                            after_source(owned, store, &record, &published, hold_effect, &effect)?;
                        Ok((record, admitted))
                    },
                    |_, _, value| Ok(value),
                )
                .await;
        }
        let retirement_request = self.source.retirement_request()?;
        self.source
            .write_owned(
                &job,
                (64 * 1024, scratch, true),
                move |room, store| {
                    grant.check(room, store)?;
                    if binding.room != room.channel_id()
                        || binding.author != record.entry.skeleton.author_id
                        || binding.from != record.entry.skeleton.seq
                    {
                        return Err(Error::Profile("history publication record changed"));
                    }
                    let instance = room.history_instance(store)?;
                    let epoch = room.epoch();
                    let pending =
                        room.prepare_history_source(store, &record.entry, binding.request)?;
                    Ok((record, pending, instance, epoch))
                },
                move |(record, pending, instance, epoch), store, owned| {
                    let published = pending.publish(
                        store,
                        &effect.committed,
                        &record.entry,
                        binding,
                        now,
                        &effect.received,
                        |batch| grant.check_batch(batch, binding.room, instance, epoch),
                    )?;
                    {
                        let mut room = owned.lock()?;
                        room.install_history_source(&record.entry, &published)?;
                        if published.cleaned() {
                            room.settle_history_publication_flow(
                                store,
                                binding.request,
                                retirement_request,
                            )?;
                        }
                    }
                    let admitted =
                        after_source(owned, store, &record, &published, hold_effect, &effect)?;
                    Ok((record, admitted))
                },
                |_, _, value| Ok(value),
            )
            .await
    }

    /// The proof hold `VOX_TEST_DEPARTURE_HOLD_FILE`: `true` while the file exists and `author`
    /// is another member, so the departure's effect stays pending.
    #[cfg(feature = "test-knobs")]
    async fn departure_held(&self, author: Digest32) -> Result<bool> {
        if !std::env::var_os("VOX_TEST_DEPARTURE_HOLD_FILE")
            .is_some_and(|path| std::path::Path::new(&path).is_file())
        {
            return Ok(false);
        }
        let me = tokio::select! {
            biased;
            () = self.source.fence.retired() => return Err(Error::Unreachable("history request cancelled")),
            room = self.source.room.lock() => room.me(),
        };
        Ok(author != me)
    }

    fn effect_inputs(&self, now: crate::time::Ms) -> EffectInputs {
        EffectInputs {
            grant: self.grant(),
            received: self.received.clone(),
            committed: self.source.commit_ledger(),
            staging: self.staging.clone(),
            historical: self.historical,
            now,
        }
    }

    pub(super) async fn cleanup_source(
        &self,
        record: Arc<Record>,
        binding: CursorBinding,
    ) -> Result<Lookup<(Arc<Record>, bool)>> {
        if binding.generation != self.generation {
            return Err(Error::Profile("history cleanup activation changed"));
        }
        let job = record.job.clone();
        let committed = self.source.commit_ledger();
        let grant = self.grant();
        let retirement_request = self.source.retirement_request()?;
        self.source
            .write_owned(
                &job,
                (64 * 1024, 0, true),
                move |room, store| {
                    grant.check(room, store)?;
                    if binding.room != room.channel_id()
                        || binding.author != record.entry.skeleton.author_id
                        || binding.from != record.entry.skeleton.seq
                        || binding.through != record.entry.skeleton.seq
                        || binding.proof_kind != 3
                    {
                        return Err(Error::Profile("history cleanup record changed"));
                    }
                    let input = room.history_read(store)?;
                    let included = input
                        .history_inclusion_receipt(&binding.head, &binding.author, binding.from)?
                        .ok_or(Error::MalformedAtRest("history cleanup inclusion missing"))?;
                    if included.header().entry().header_wire() != record.entry.header_wire() {
                        return Err(Error::Profile("history cleanup head/entry changed"));
                    }
                    let source = input
                        .publication_busy()
                        .then_some(record.entry.entry_hash());
                    drop(input);
                    let pending =
                        room.prepare_history_publication(store, source, Some(binding.request))?;
                    Ok((record, pending))
                },
                move |(record, pending), store, _| {
                    Ok((
                        record,
                        pending.cleanup(store, &committed, Some(binding), None),
                    ))
                },
                move |room, store, (record, completed)| {
                    let finished = room.finish_history_publication(completed);
                    let settled = room.settle_history_publication_flow(
                        store,
                        binding.request,
                        retirement_request,
                    );
                    finished.and_then(|(done, _)| settled.map(|()| (record, done)))
                },
            )
            .await
    }

    /// One existing authority/effect slice, with the full signed-length record reservation.
    /// Only the final semantic Batch clears this exact provisional body from demand staging.
    pub(super) async fn advance_effect(
        &self,
        record: Arc<Record>,
        cursor: crate::node::channel::HistoryEffectCursor,
        now: crate::time::Ms,
    ) -> Result<
        Lookup<(
            Arc<Record>,
            (
                crate::node::channel::HistoryEffectCursor,
                crate::node::channel::HistoryEffectProgress,
            ),
        )>,
    > {
        let job = record.job.clone();
        // A proof can hold a remote departure's effect: the stored body is classified off actor
        // only while that hold is set.
        #[cfg(feature = "test-knobs")]
        if record
            .entry
            .skeleton
            .v2
            .as_ref()
            .is_some_and(|header| header.kind == crate::log::history::SignedEntryKind::Governance)
            && self.departure_held(record.entry.skeleton.author_id).await?
        {
            let classified = self
                .read_precharged(
                    &job,
                    64 * 1024,
                    Arc::clone(&record),
                    move |room, store, record| {
                        let input = room.history_read(store)?;
                        let hash = record.entry.entry_hash();
                        if input.publication_busy() {
                            return Ok(None);
                        }
                        if input.history_effect_finished(&hash)? {
                            return Ok(Some(false));
                        }
                        let entry = input.history_entry(&hash)?.ok_or(Error::MalformedAtRest(
                            "pending history body record missing",
                        ))?;
                        Ok(Some(
                            match crate::governance::entry::GovEntry::body_bound_to(&entry) {
                                Ok(crate::governance::entry::GovBody::Presence(presence)) => {
                                    !presence.body.here
                                }
                                Ok(_) => false,
                                Err(_) => true,
                            },
                        ))
                    },
                )
                .await?;
            match classified {
                Lookup::Found(held) if held.value.1 => return Ok(Lookup::Busy),
                Lookup::Found(_) => {}
                Lookup::Busy => return Ok(Lookup::Busy),
                Lookup::Missing => return Ok(Lookup::Missing),
            }
        }
        let staged = record.staged.is_some() || record.memory;
        let effect = self.effect_inputs(now);
        self.source
            .write_owned(
                &job,
                (64 * 1024, 0, false),
                |_, _| Ok(()),
                move |(), store, owned| {
                    let progress = effect_quantum(
                        owned,
                        store,
                        &record,
                        &effect,
                        |room, store| {
                            room.prepare_received_effect(
                                store,
                                cursor,
                                effect.now,
                                staged,
                                effect.historical,
                            )
                        },
                        None,
                    )?;
                    Ok((record, progress))
                },
                |_, _, value| Ok(value),
            )
            .await
    }

    /// A body for a previously source-complete header is validated before replacing storage.
    /// Existing effect completion is re-used; a pending authority fold stays pending.
    pub(super) async fn refill(
        &self,
        record: Arc<Record>,
        now: crate::time::Ms,
    ) -> Result<Lookup<(Arc<Record>, crate::node::channel::HistoryEffectProgress)>> {
        let job = record.job.clone();
        let key_body = self.key_body.filter(|need| {
            need.author == record.entry.skeleton.author_id
                && need.seq == record.entry.skeleton.seq
                && need.hash == record.entry.entry_hash()
        });
        let effect = self.effect_inputs(now);
        self.source
            .write_owned(
                &job,
                (64 * 1024, 0, false),
                |_, _| Ok(()),
                move |(), store, owned| {
                    let (_, progress) = effect_quantum(
                        owned,
                        store,
                        &record,
                        &effect,
                        |room, store| {
                            use crate::node::channel::governance::{
                                PayloadValidation, TypedSparseBody,
                            };
                            let key = room
                                .history_author_key(&record.entry.skeleton.author_id)
                                .ok_or(Error::MalformedAtRest("history refill author vanished"))?;
                            let body = match TypedSparseBody::verify(
                                &record.entry,
                                &key,
                                &mut crate::log::history::WorkBudget::default(),
                            )? {
                                PayloadValidation::Complete(body) => body,
                                _ => {
                                    return Err(Error::MalformedBundle(
                                        "history refill body is incomplete",
                                    ))
                                }
                            };
                            room.prepare_received_refill(
                                store,
                                &record.entry,
                                &body,
                                effect.now,
                                effect.historical,
                                key_body,
                            )
                        },
                        Some(&record.entry),
                    )?;
                    Ok((record, progress))
                },
                |_, _, value| Ok(value),
            )
            .await
    }
}

/// How far one entry's owned admission write reached (`Receiver::admit_entry`).
pub(super) enum Admitted {
    /// Another publication owns the room, or validation found it busy.
    Busy,
    /// The position already holds this entry: its body/effect continue.
    Duplicate,
    /// The publication's DAG facts (`switched == false`: nothing of it is history yet) or its
    /// cleanup continue in the next quantum.
    Source { switched: bool },
    /// Published, the room's publication idle, and one effect quantum ran.
    Effect(
        crate::node::channel::HistoryEffectCursor,
        crate::node::channel::HistoryEffectProgress,
    ),
    /// Published; the test departure hold keeps its effect pending.
    EffectHeld,
}

/// What an effect quantum needs from its receiver, owned by the native write running it.
struct EffectInputs {
    grant: Grant,
    received: ReceivedFlow,
    committed: Arc<std::sync::atomic::AtomicBool>,
    staging: Option<Staging>,
    historical: bool,
    now: crate::time::Ms,
}

/// What follows a publication transaction inside the same owned write: once the room's
/// publication is idle, the fold's bounded turn a governance change owes, as an unpublished
/// room's construction takes it (`actor/construction_save.rs` `fold_unpublished_governance`:
/// `advance_governance`, which also moves the room's governance display and its news), so the
/// effect reads the governance it changed; then one effect quantum.
fn after_source(
    owned: &OwnedRoom<'_>,
    store: &Store,
    record: &Record,
    published: &crate::node::channel::PublishedHistorySource,
    hold_effect: bool,
    effect: &EffectInputs,
) -> Result<Admitted> {
    if !published.cleaned() {
        return Ok(Admitted::Source {
            switched: published.switched(),
        });
    }
    if published.governance_changed() {
        let mut room = owned.lock_for_write()?;
        effect.grant.check(&room, store)?;
        match room.advance_governance(store, effect.now) {
            Err(error) if ChannelState::governance_refreshing(&error) => {}
            folded => {
                folded?;
            }
        }
    }
    if hold_effect {
        return Ok(Admitted::EffectHeld);
    }
    let staged = record.staged.is_some() || record.memory;
    let cursor = crate::node::channel::HistoryEffectCursor::new(record.entry.entry_hash());
    let (cursor, progress) = effect_quantum(
        owned,
        store,
        record,
        effect,
        |room, store| {
            room.prepare_received_effect(store, cursor, effect.now, staged, effect.historical)
        },
        None,
    )?;
    Ok(Admitted::Effect(cursor, progress))
}

/// One semantic effect (or refill) quantum and the legacy migration quantum it owes, inside an
/// owned write: each prepared and installed under the room lock, each saved off it. Every
/// native transaction rechecks the same flow grant.
fn effect_quantum(
    owned: &OwnedRoom<'_>,
    store: &Store,
    record: &Record,
    effect: &EffectInputs,
    prepare: impl FnOnce(
        &mut ChannelState,
        &Store,
    ) -> Result<crate::node::channel::pending_received::PendingReceived>,
    refill: Option<&crate::log::entry::Entry>,
) -> Result<(
    crate::node::channel::HistoryEffectCursor,
    crate::node::channel::HistoryEffectProgress,
)> {
    let grant = effect.grant;
    let (pending, (room, instance, epoch)) = {
        let mut room = owned.lock_for_write()?;
        grant.check(&room, store)?;
        let binding = (
            room.channel_id(),
            room.history_instance(store)?,
            room.epoch(),
        );
        (prepare(&mut room, store)?, binding)
    };
    let completed = pending.save(
        store,
        &effect.committed,
        &effect.received,
        refill,
        |batch| grant.check_batch(batch, room, instance, epoch),
        |batch, hash| complete_staged(batch, effect.staging.as_ref(), record, hash),
    );
    let migrate = completed.legacy_migration();
    let progress = owned.lock()?.finish_received(store, completed)?;
    if let Some(maintenance_now) = migrate {
        let pending = {
            let room = owned.lock()?;
            grant.check(&room, store)?;
            room.prepare_legacy_migration(store, maintenance_now)?
        };
        if let Some(pending) = pending {
            let completed = effect.received.scope(|| {
                pending.run_guarded(store, |batch| {
                    grant.check_batch(batch, room, instance, epoch)
                })
            });
            owned.lock()?.finish_legacy_migration(completed)?;
        }
    }
    Ok(progress)
}

fn complete_staged(
    batch: &mut crate::node::store::Batch<'_>,
    staging: Option<&Staging>,
    record: &Record,
    hash: Digest32,
) -> Result<()> {
    let Some((request, generation, admission)) = record.staged else {
        return Ok(());
    };
    let admission_charge = record
        .admission
        .as_ref()
        .ok_or(Error::Profile("history completion admission missing"))?;
    if hash != record.entry.entry_hash() {
        return Err(Error::MalformedAtRest("history completion entry changed"));
    }
    let staging = staging.ok_or(Error::Profile("history completion activation missing"))?;
    let active = staging
        .active
        .lock()
        .map_err(|_| Error::Profile("history activation lock failed"))?;
    if active.request() != request || active.binding().grant != generation {
        return Err(Error::Profile("history completion activation changed"));
    }
    match admission {
        StagedAdmission::Body => {
            demand::entry_admitted(batch, &staging.context, &active, hash, admission_charge)
        }
        StagedAdmission::RoleHeader => demand::role_header_admitted(
            batch,
            &staging.context,
            &active,
            record.entry.skeleton.seq,
            admission_charge,
        ),
    }
}

/// Small scheduling state only. Bodies and context maps never survive a local-step return.
#[derive(Clone, Copy)]
pub(crate) enum LocalStep {
    Verify(CursorBinding),
    Entry {
        request: RequestId,
        head: Digest32,
        seq: u64,
        body: bool,
        role_header: bool,
        phase: EntryPhase,
    },
    Control {
        head: Digest32,
        through: u64,
        effects: bool,
    },
}
#[derive(Clone, Copy)]
pub(crate) enum EntryPhase {
    Start,
    Preflight {
        parent: usize,
        next: usize,
    },
    Body,
    Validate(CursorBinding),
    /// Validation done: one owned write begins the publication and, as far as its quantum
    /// reaches, publishes the source and runs its fold turn and first effect quantum.
    Begin(CursorBinding),
    /// The same write resuming this request's publication whose DAG facts are unfinished.
    Publish(CursorBinding),
    Cleanup(CursorBinding),
    Refill,
    Effect(Option<crate::node::channel::HistoryEffectCursor>),
}
pub(crate) enum LocalNeed {
    /// Resume only through the existing operation's exact persisted body cursor.
    StagedBody,
    KeyBodyRetired,
    Wire(Query),
    Entry {
        head: Digest32,
        seq: u64,
    },
    Control {
        head: Digest32,
        through: u64,
        effects: bool,
    },
    Governance,
    /// Rule F2 E and rule F3: a wait on an author's fork or on a certified splitter's unmatched
    /// coordinate (`admission::ForkWait`), held by the frontier (`pull::Need::Fork`,
    /// `Need::Unmatched`).
    Fork(super::admission::ForkWait),
}
pub(crate) struct LocalResult {
    pub(crate) next: Option<LocalStep>,
    pub(crate) need: Option<LocalNeed>,
    /// Semantic dispatch completed; a header-only source need not have a visible body.
    pub(crate) published: Option<Digest32>,
    pub(crate) rendered: bool,
    pub(crate) governance: bool,
    pub(crate) busy: bool,
    pub(crate) byte_pressure: Option<crate::node::history_budget::BytePressure>,
    /// A control-effects step made its author's Session controls current here, which they were
    /// not: permission news for the room's tellers (`Flow::controls_ready`).
    pub(crate) controls_ready: bool,
}
impl LocalResult {
    fn next(step: LocalStep) -> Self {
        Self {
            next: Some(step),
            need: None,
            published: None,
            rendered: false,
            governance: false,
            busy: false,
            byte_pressure: None,
            controls_ready: false,
        }
    }
    fn done() -> Self {
        Self {
            next: None,
            need: None,
            published: None,
            rendered: false,
            governance: false,
            busy: false,
            byte_pressure: None,
            controls_ready: false,
        }
    }
    fn wait(step: LocalStep, need: LocalNeed) -> Self {
        Self {
            next: Some(step),
            need: Some(need),
            published: None,
            rendered: false,
            governance: false,
            busy: false,
            byte_pressure: None,
            controls_ready: false,
        }
    }
    fn busy(step: LocalStep) -> Self {
        Self {
            next: Some(step),
            need: None,
            published: None,
            rendered: false,
            governance: false,
            busy: true,
            byte_pressure: None,
            controls_ready: false,
        }
    }

    fn byte_pressure(step: LocalStep, pressure: crate::node::history_budget::BytePressure) -> Self {
        Self {
            byte_pressure: Some(pressure),
            ..Self::next(step)
        }
    }
}

impl Receiver {
    /// One local slice. The actor schedules its returned dependency explicitly; this function
    /// opens no stream, loops no verifier budget, and retains no full record on return.
    pub(crate) async fn local_step(
        &self,
        job: &crate::node::history_budget::Job,
        step: LocalStep,
        now: crate::time::Ms,
    ) -> Result<LocalResult> {
        use crate::node::channel::HistoryEffectProgress as Effect;
        match step {
            LocalStep::Verify(binding) => {
                let Lookup::Found(value) = self.advance(job, binding).await? else {
                    return Ok(LocalResult::busy(step));
                };
                return Ok(match value.value {
                    Advanced::Complete => LocalResult::done(),
                    Advanced::Progress => LocalResult::next(step),
                    Advanced::MissingContext(hash) => {
                        LocalResult::wait(step, LocalNeed::Wire(Query::Context(hash)))
                    }
                    Advanced::Need(query) => LocalResult::wait(step, LocalNeed::Wire(query)),
                    Advanced::Busy => LocalResult::busy(step),
                    Advanced::Fork(pair) => {
                        let (existing, conflicting) = *pair;
                        if self
                            .record_fork(job, existing, conflicting)
                            .await?
                            .is_none()
                        {
                            return Ok(LocalResult::busy(step));
                        }
                        // As at a held position: the fork is recorded, and this head's work
                        // ends refused.
                        return Err(Error::MalformedGovernance(
                            "author signed two histories under two signed heads",
                        ));
                    }
                });
            }
            LocalStep::Control {
                head,
                through,
                effects,
            } => {
                return self.control_step(job, step, head, through, effects).await;
            }
            LocalStep::Entry { .. } => {}
        }
        let LocalStep::Entry {
            request,
            head,
            seq,
            body,
            role_header,
            phase,
        } = step
        else {
            unreachable!()
        };
        let full = body
            && matches!(
                phase,
                EntryPhase::Body
                    | EntryPhase::Begin(_)
                    | EntryPhase::Publish(_)
                    | EntryPhase::Refill
                    | EntryPhase::Effect(_)
            );
        let completion = matches!(
            phase,
            EntryPhase::Begin(_)
                | EntryPhase::Publish(_)
                | EntryPhase::Refill
                | EntryPhase::Effect(_)
        ) && (body || role_header);
        let assembly = if full {
            match self.held_record(job, head, seq).await? {
                Some(assembly) => assembly,
                None => self.assemble(job, completion).await?,
            }
        } else {
            let local_work = if matches!(phase, EntryPhase::Validate(_)) {
                ENTRY_VALIDATION_WORK
            } else {
                RECORD_METADATA_WORK
            };
            self.header_record(job, head, seq, completion, local_work)
                .await?
        };
        let mut record = match assembly {
            Assembly::Ready(record) => record,
            Assembly::Busy => return Ok(LocalResult::busy(step)),
            Assembly::BytePressure(pressure) => {
                return Ok(LocalResult::byte_pressure(step, pressure));
            }
            Assembly::Pending => {
                return Ok(if full {
                    LocalResult::wait(step, LocalNeed::StagedBody)
                } else {
                    LocalResult::wait(step, LocalNeed::Wire(Query::Header { head, seq }))
                });
            }
        };
        if record.entry.skeleton.seq != seq {
            return Err(Error::Profile("history local step entry changed"));
        }
        if self.held.is_none() && ((body && !full) || role_header) {
            let staged = Some((
                request,
                self.generation,
                if role_header {
                    StagedAdmission::RoleHeader
                } else {
                    StagedAdmission::Body
                },
            ));
            Arc::get_mut(&mut record)
                .ok_or(Error::Profile("history header record is shared"))?
                .staged = staged;
        }
        let hash = record.entry.entry_hash();
        let record_author = record.entry.skeleton.author_id;
        let next = |phase| LocalStep::Entry {
            request,
            head,
            seq,
            body,
            role_header,
            phase,
        };
        let is_governance = record.entry.skeleton.v2.as_ref().map_or_else(
            || {
                record.entry.payload.as_deref().is_some_and(|payload| {
                    matches!(
                        crate::node::channel::classify_payload(payload),
                        Ok(crate::log::entry::EntryKind::Governance)
                    ) || crate::governance::step_policy::is_step_policy(payload)
                })
            },
            |v2| {
                matches!(
                    v2.kind,
                    crate::log::history::SignedEntryKind::Governance
                        | crate::log::history::SignedEntryKind::StepPolicy
                )
            },
        );
        let effect_result = |progress| -> LocalResult {
            match progress {
                Effect::Progress => LocalResult::next(step),
                Effect::AdmittedProgress { .. } => LocalResult::next(LocalStep::Entry {
                    request,
                    head,
                    seq,
                    body: false,
                    role_header: false,
                    phase,
                }),
                Effect::RefillPending { governance: true } => {
                    LocalResult::wait(step, LocalNeed::Governance)
                }
                Effect::RefillPending { governance: false } => LocalResult::next(step),
                Effect::BodyUnavailable => LocalResult::wait(step, LocalNeed::StagedBody),
                Effect::KeyBodyRetired => LocalResult::wait(step, LocalNeed::KeyBodyRetired),
                Effect::ControlPending { head, through } => LocalResult::wait(
                    step,
                    LocalNeed::Control {
                        head,
                        through,
                        effects: true,
                    },
                ),
                Effect::GovernancePending => LocalResult::wait(step, LocalNeed::Governance),
                Effect::CheckpointPending { author, seq } => {
                    // Existing Checkpoint payloads contain only seq/hash: their target is
                    // necessarily in this entry's own author feed, covered by this head.
                    if author != record_author {
                        return LocalResult::busy(step);
                    }
                    LocalResult::wait(step, LocalNeed::Entry { head, seq })
                }
                Effect::Complete { rendered } => LocalResult {
                    next: None,
                    need: None,
                    published: Some(hash),
                    rendered,
                    governance: is_governance,
                    busy: false,
                    byte_pressure: None,
                    controls_ready: false,
                },
            }
        };
        // An effect quantum's outcome, whichever write ran it: a continuation resumes at its
        // exact cursor in the Effect phase.
        let effect_step = |cursor, progress| -> LocalResult {
            if let Effect::RefillPending { governance } = progress {
                let refill = next(EntryPhase::Refill);
                return if governance {
                    LocalResult::wait(refill, LocalNeed::Governance)
                } else {
                    LocalResult::next(refill)
                };
            }
            let mut result = effect_result(progress);
            if let Some(LocalStep::Entry {
                body, role_header, ..
            }) = result.next
            {
                result.next = Some(LocalStep::Entry {
                    request,
                    head,
                    seq,
                    body,
                    role_header,
                    phase: EntryPhase::Effect(Some(cursor)),
                });
            }
            result
        };
        Ok(match phase {
            EntryPhase::Start | EntryPhase::Body => {
                let Lookup::Found(value) = self
                    .start_entry(
                        request,
                        head,
                        record,
                        body,
                        matches!(phase, EntryPhase::Body),
                    )
                    .await?
                else {
                    return Ok(LocalResult::busy(step));
                };
                match value.value.1 {
                    admission::EntryStart::Preflight => {
                        LocalResult::next(next(EntryPhase::Preflight { parent: 0, next: 0 }))
                    }
                    admission::EntryStart::BodyNeeded => {
                        // Admission can promote a header-only dependency when its signed
                        // recipient is this node. Carry that requirement into staging; merely
                        // changing the phase would otherwise reconstruct the same header again.
                        LocalResult::next(LocalStep::Entry {
                            request,
                            head,
                            seq,
                            body: true,
                            role_header: false,
                            phase: EntryPhase::Body,
                        })
                    }
                    admission::EntryStart::Cursor(binding) => {
                        LocalResult::next(next(EntryPhase::Validate(binding)))
                    }
                    admission::EntryStart::Need(query) => {
                        let resume = if matches!(query, Query::Entry { head: needed, seq: at, .. } if needed == head && at == seq)
                        {
                            // A mandatory typed-control body is now an explicit staged obligation;
                            // the caller cannot fetch it and then retry header-only admission.
                            LocalStep::Entry {
                                request,
                                head,
                                seq,
                                body: true,
                                role_header: false,
                                phase,
                            }
                        } else {
                            step
                        };
                        LocalResult::wait(resume, LocalNeed::Wire(query))
                    }
                    admission::EntryStart::Fork(wait) => {
                        LocalResult::wait(step, LocalNeed::Fork(wait))
                    }
                    admission::EntryStart::Busy => LocalResult::busy(step),
                }
            }
            EntryPhase::Preflight { parent, next: at } => {
                let job = record.job.clone();
                let value = self
                    .read_precharged(&job, 64 * 1024, record, move |room, store, record| {
                        admission::preflight(room, store, head, &record.entry, parent, at).map(Some)
                    })
                    .await?;
                let Lookup::Found(value) = value else {
                    return Ok(LocalResult::busy(step));
                };
                match value.value.1 {
                    admission::Preflight::Complete => LocalResult::next(next(EntryPhase::Body)),
                    admission::Preflight::Progress { parent, next: at } => {
                        LocalResult::next(next(EntryPhase::Preflight { parent, next: at }))
                    }
                    admission::Preflight::Need(query) => {
                        LocalResult::wait(step, LocalNeed::Wire(query))
                    }
                    admission::Preflight::Control {
                        head,
                        through,
                        effects,
                    } => LocalResult::wait(
                        step,
                        LocalNeed::Control {
                            head,
                            through,
                            effects,
                        },
                    ),
                    admission::Preflight::Fork(wait) => {
                        LocalResult::wait(step, LocalNeed::Fork(wait))
                    }
                    admission::Preflight::Busy => LocalResult::busy(step),
                }
            }
            EntryPhase::Validate(binding) => {
                let Lookup::Found(value) = self.advance_entry(record, binding).await? else {
                    return Ok(LocalResult::busy(step));
                };
                match value.value.1 {
                    admission::EntryAdvanced::Validated(_) => {
                        LocalResult::next(next(EntryPhase::Begin(binding)))
                    }
                    admission::EntryAdvanced::Progress => LocalResult::next(step),
                    admission::EntryAdvanced::Need(query) => {
                        LocalResult::wait(step, LocalNeed::Wire(query))
                    }
                    admission::EntryAdvanced::ControlPending { head, through } => {
                        LocalResult::wait(
                            step,
                            LocalNeed::Control {
                                head,
                                through,
                                effects: false,
                            },
                        )
                    }
                    admission::EntryAdvanced::ControlSource { head, seq } => {
                        LocalResult::wait(step, LocalNeed::Entry { head, seq })
                    }
                    admission::EntryAdvanced::Fork(wait) => {
                        LocalResult::wait(step, LocalNeed::Fork(wait))
                    }
                    admission::EntryAdvanced::Busy => LocalResult::busy(step),
                }
            }
            EntryPhase::Begin(binding) | EntryPhase::Publish(binding) => {
                let begin = matches!(phase, EntryPhase::Begin(_));
                let Lookup::Found(value) = self.admit_entry(record, binding, now, begin).await?
                else {
                    return Ok(LocalResult::busy(step));
                };
                match value.value.1 {
                    Admitted::Busy => LocalResult::busy(step),
                    Admitted::Duplicate => LocalResult::next(next(if body {
                        EntryPhase::Refill
                    } else {
                        EntryPhase::Effect(None)
                    })),
                    Admitted::Source { switched: false } => {
                        LocalResult::next(next(EntryPhase::Publish(binding)))
                    }
                    Admitted::Source { switched: true } => {
                        LocalResult::next(next(EntryPhase::Cleanup(binding)))
                    }
                    Admitted::EffectHeld => LocalResult::busy(next(EntryPhase::Effect(None))),
                    Admitted::Effect(cursor, progress) => effect_step(cursor, progress),
                }
            }
            EntryPhase::Cleanup(binding) => {
                let Lookup::Found(value) = self.cleanup_source(record, binding).await? else {
                    return Ok(LocalResult::busy(step));
                };
                LocalResult::next(next(if value.value.1 {
                    EntryPhase::Effect(None)
                } else {
                    phase
                }))
            }
            EntryPhase::Refill => {
                let Lookup::Found(value) = self.refill(record, now).await? else {
                    return Ok(LocalResult::busy(step));
                };
                match value.value.1 {
                    complete @ Effect::Complete { .. } => effect_result(complete),
                    Effect::Progress => LocalResult::next(next(EntryPhase::Effect(None))),
                    Effect::AdmittedProgress { rendered } => LocalResult::next(LocalStep::Entry {
                        request,
                        head,
                        seq,
                        body: false,
                        role_header: false,
                        phase: EntryPhase::Effect(Some(
                            crate::node::channel::HistoryEffectCursor::with_rendered(
                                hash, rendered,
                            ),
                        )),
                    }),
                    Effect::RefillPending { governance: true } => {
                        LocalResult::wait(step, LocalNeed::Governance)
                    }
                    Effect::RefillPending { governance: false } => LocalResult::next(step),
                    Effect::BodyUnavailable => LocalResult::wait(step, LocalNeed::StagedBody),
                    other => effect_result(other),
                }
            }
            EntryPhase::Effect(cursor) => {
                let cursor =
                    cursor.unwrap_or_else(|| crate::node::channel::HistoryEffectCursor::new(hash));
                let Lookup::Found(value) = self.advance_effect(record, cursor, now).await? else {
                    return Ok(LocalResult::busy(step));
                };
                let (cursor, progress) = value.value.1;
                effect_step(cursor, progress)
            }
        })
    }

    async fn control_step(
        &self,
        job: &crate::node::history_budget::Job,
        step: LocalStep,
        head: Digest32,
        through: u64,
        effects: bool,
    ) -> Result<LocalResult> {
        use crate::node::channel::entry_store::sparse::SourceProgress;
        let Some(work_job) = job.record_job(12 * 1024 * 1024).await else {
            return Ok(LocalResult::busy(step));
        };
        let committed = self.source.commit_ledger();
        let value = self
            .source
            .write_admission(
                &work_job,
                (VERIFY_ENVELOPE, 4 * 1024 * 1024),
                move |room, store| {
                    let input = room.history_read(store)?;
                    let named = input
                        .history_head(&head)?
                        .ok_or(Error::MalformedAtRest("control target head missing"))?;
                    // Control facts are kept per author (`control_prefix_complete`); an older
                    // committed head is replaced by the author's current one only so that a
                    // coverage need names the head this node and its peers hold now.
                    let head = match input
                        .sparse_author(&named.binding.author, named.binding.scope)?
                        .and_then(|state| state.committed)
                    {
                        Some(current)
                            if current != head
                                && input.history_head_committed(&head, named.binding)? =>
                        {
                            current
                        }
                        _ => head,
                    };
                    let target = input
                        .history_head(&head)?
                        .ok_or(Error::MalformedAtRest("control target head missing"))?;
                    if through == 0 || through > target.root.leaves {
                        return Err(Error::MalformedAtRest(
                            "control receipt bound exceeds target",
                        ));
                    }
                    let complete = if effects {
                        input.control_effects_complete(&head, through)?
                    } else {
                        input.control_sources_complete(&head, through)?
                    };
                    if complete {
                        return Ok((SourceProgress::Complete { through }, None, head, false));
                    }
                    let leaves = target.root.leaves;
                    drop(input);
                    let progress = room.history_write_tracked(store, &committed, |index| {
                        if effects {
                            index.advance_control_effects(&head, through)
                        } else {
                            index.advance_control_sources(&head, through)
                        }
                    })?;
                    // The author's effect prefix was below its committed size (not complete
                    // above, and `through` reaches that size) and this step brought it there:
                    // its Session controls became current (`history_control_ready`) here.
                    let ready = effects
                        && through >= leaves
                        && matches!(
                            progress,
                            SourceProgress::Complete { through: done }
                                | SourceProgress::Progress { through: done }
                                if done >= leaves
                        );
                    let needed = if let SourceProgress::PendingEffect { hash } = &progress {
                        let input = room.history_read(store)?;
                        input
                            .history_object(
                                crate::node::channel::entry_store::sparse::ObjectKind::Header,
                                hash,
                            )?
                            .map(|wire| {
                                crate::log::entry::Entry::from_wire(&wire)
                                    .map(|entry| entry.skeleton.seq)
                            })
                            .transpose()?
                    } else {
                        None
                    };
                    Ok((progress, needed, head, ready))
                },
            )
            .await?;
        let Lookup::Found(value) = value else {
            return Ok(LocalResult::busy(step));
        };
        let (progress, needed, head, controls_ready) = value.value;
        let mut result = match (progress, needed) {
            (
                SourceProgress::Complete { through: done }
                | SourceProgress::Progress { through: done },
                _,
            ) if done >= through => LocalResult::done(),
            (SourceProgress::Progress { .. } | SourceProgress::Complete { .. }, _) => {
                LocalResult::next(step)
            }
            (SourceProgress::MissingCoverage { after }, _) => LocalResult::wait(
                step,
                LocalNeed::Wire(Query::Proof {
                    head,
                    kind: ProofKind::Control,
                    from: after + 1,
                    to: through,
                }),
            ),
            (SourceProgress::MissingSource { seq }, _) => {
                LocalResult::wait(step, LocalNeed::Entry { head, seq })
            }
            (
                SourceProgress::ConflictingSource {
                    author,
                    seq,
                    expected,
                    actual,
                },
                _,
            ) => {
                tracing::warn!(
                    ?author,
                    seq,
                    ?expected,
                    ?actual,
                    "conflicting sparse control source"
                );
                return Err(Error::MalformedBundle(
                    "held sparse control source conflicts with authenticated head",
                ));
            }
            (SourceProgress::PendingEffect { .. }, Some(seq)) => {
                LocalResult::wait(step, LocalNeed::Entry { head, seq })
            }
            (SourceProgress::PendingEffect { .. }, None) => {
                return Err(Error::MalformedAtRest(
                    "pending history effect header missing",
                ));
            }
        };
        // The author's Session controls became current in this step: permission news, once.
        result.controls_ready = controls_ready;
        Ok(result)
    }
}

#[derive(Clone, Copy)]
struct Grant {
    node: Digest32,
    generation: Digest32,
}
impl Grant {
    fn check(&self, room: &ChannelState, store: &Store) -> Result<()> {
        let actual = super::authorization_generation(
            store,
            self.node,
            room.channel_id(),
            room.history_instance(store)?,
            room.epoch(),
        )?;
        if actual != self.generation {
            return Err(Error::StreamRefused(super::AUTHORIZATION_CHANGED));
        }
        Ok(())
    }
    fn check_batch(
        &self,
        batch: &crate::node::store::Batch<'_>,
        room: Digest32,
        instance: [u8; 16],
        epoch: u64,
    ) -> Result<()> {
        if super::authorization_generation_in(batch, self.node, room, instance, epoch)?
            != self.generation
        {
            return Err(Error::StreamRefused(super::AUTHORIZATION_CHANGED));
        }
        Ok(())
    }
}
impl Receiver {
    fn grant(&self) -> Grant {
        Grant {
            node: self.node,
            generation: self.generation,
        }
    }
    async fn read<T, F>(
        &self,
        job: &crate::node::history_budget::Job,
        envelope: usize,
        read: F,
    ) -> Result<Lookup<T>>
    where
        T: Send + 'static,
        F: FnOnce(&mut ChannelState, &Store) -> Result<Option<T>> + Send + 'static,
    {
        let grant = self.grant();
        let received = self.received.clone();
        self.source
            .read(job, envelope, move |room, store| {
                received.scope(|| {
                    grant.check(room, store)?;
                    read(room, store)
                })
            })
            .await
    }
    async fn read_precharged<T, F>(
        &self,
        job: &crate::node::history_budget::Job,
        envelope: usize,
        record: Arc<Record>,
        read: F,
    ) -> Result<Lookup<(Arc<Record>, T)>>
    where
        T: Send + 'static,
        F: FnOnce(&mut ChannelState, &Store, &Record) -> Result<Option<T>> + Send + 'static,
    {
        let grant = self.grant();
        let received = self.received.clone();
        self.source
            .read_precharged(job, envelope, record, move |room, store, record| {
                received.scope(|| {
                    grant.check(room, store)?;
                    read(room, store, record)
                })
            })
            .await
    }
}
