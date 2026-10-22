//! Receive one explicitly scheduled response quantum. A wire continuation never starts
//! another request; provisional bodies and verifier cursors survive only in bounded local slots.

use std::sync::{Arc, Mutex as StdMutex};
use tokio::sync::Mutex;

use crate::error::{Error, Result};
use crate::hash::Digest32;
use crate::node::channel::{entry_store::sparse::CursorBinding, ChannelState};
use crate::node::history_demand::{self as demand, Active, Context};
use crate::node::store::Store;
use crate::wire::WireError;

use super::admission::{self, Advanced, Staged};
use super::credit::Response;
use super::source::{Lookup, Source};
use super::transport::{Read, Transport};
use super::{Continuation, Frame, ProofKind, Query, RequestId, Status};

const VERIFY_ENVELOPE: usize = 4 * 1024 * 1024;
// One atomic metadata object, or one selected staged body, per receiver handoff.
const MAX_NEEDS: usize = 1;

/// Proof-only interruption point after a hostile nonrecipient body has been refused and the
/// archive cursor is durably parked on its authenticated header, but before semantic settlement.
/// The trigger is renamed with `.engaged`; removing that engaged marker releases the worker.
#[cfg(feature = "test-knobs")]
pub const TEST_HOLD_ROLE_SETTLEMENT_ENV: &str = "VOX_TEST_HOLD_ROLE_HEADER_SETTLEMENT_FILE";

/// Proof-only interruption after a body which its authenticated header says belongs to another
/// member is nevertheless durably appended by a mutant. The marker's exact 32 bytes are the entry
/// hash; removing it releases the worker.
#[cfg(feature = "test-knobs")]
pub const TEST_BODY_DURABLE_ENV: &str = "VOX_TEST_HISTORY_BODY_DURABLE_FILE";

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
    staging: Option<Staging>,
    historical: bool,
}

pub(crate) enum LocalProof {
    Verified(CursorBinding),
    Busy,
    Missing,
}

/// All results are bounded scheduling information, not permission to fetch another page.
pub(crate) struct Received {
    pub(crate) status: Status,
    pub(crate) continuation: Option<Continuation>,
    pub(crate) needs: Vec<Query>,
    pub(crate) verifiers: Vec<CursorBinding>,
    pub(crate) body_ready: Option<Digest32>,
    /// Exact authenticated header whose private body this node's role must not receive. Its
    /// inclusion and semantic settlement still have to complete before the archive can advance.
    pub(crate) role_ready: Option<(Digest32, u64, Digest32)>,
    pub(crate) body_progress: bool,
    pub(crate) inventory: Option<Inventory>,
    pub(crate) heads: Vec<super::HeadHint>,
    pub(crate) departure_receipt: Option<super::HeadHint>,
    /// The exchange fetched an object this node did not hold (a head, header, context or
    /// proof it saved): what makes a round not `empty` in `vox status --json` (ADR-038 FX-29).
    pub(crate) brought: bool,
}
impl Received {
    fn pending(status: Status) -> Self {
        Self {
            status,
            continuation: None,
            needs: Vec::new(),
            verifiers: Vec::new(),
            body_ready: None,
            role_ready: None,
            body_progress: false,
            inventory: None,
            heads: Vec::new(),
            departure_receipt: None,
            brought: false,
        }
    }
    fn need(&mut self, query: Query) -> Result<()> {
        if !self.needs.contains(&query) {
            if self.needs.len() == MAX_NEEDS {
                return Err(Error::SizeLimitExceeded("history missing evidence queue"));
            }
            self.needs.push(query);
        }
        Ok(())
    }
}

impl Receiver {
    // The receiver retains one exact room, peer, grant, staging slot and cancellation scope.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        room: Arc<Mutex<ChannelState>>,
        store: Arc<Store>,
        peer: Digest32,
        epoch: u64,
        generation: Digest32,
        node: Digest32,
        staging: Option<Staging>,
        historical: bool,
        fence: Arc<crate::transport::stream_transport::Fence>,
        deadline: tokio::time::Instant,
        work_committed: Arc<std::sync::atomic::AtomicBool>,
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
            ),
            generation,
            node,
            staging,
            historical,
        }
    }

    pub(super) async fn inventory(
        &self,
        job: &crate::node::history_budget::Job,
    ) -> Result<Lookup<Vec<super::HeadHint>>> {
        self.source.inventory(job).await
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
            .proof(&work_job, &signed.value, kind, from, to)
            .await?
        {
            Lookup::Found(proof) => proof,
            Lookup::Busy => return Ok(LocalProof::Busy),
            Lookup::Missing => return Ok(LocalProof::Missing),
        };
        let generation = self.generation;
        let committed = self.source.commit_ledger();
        let staged = self
            .read(&work_job, VERIFY_ENVELOPE, move |room, store| {
                admission::stage(
                    room,
                    store,
                    &committed,
                    request,
                    generation,
                    &query,
                    super::Object::Proof(proof.value),
                )
                .map(Some)
            })
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
                    ))
                }
            },
            Lookup::Busy => LocalProof::Busy,
            Lookup::Missing => LocalProof::Missing,
        })
    }

    /// The caller opens/handshakes the stream and owns its tracked cancellation fence.
    pub(super) async fn pull(
        &self,
        io: &mut Transport,
        request: RequestId,
        query: Query,
        handshake_bytes: usize,
    ) -> Result<Received> {
        let mut credit = Response::new(request, query.clone())?;
        credit.charge_handshake(handshake_bytes)?;
        let mut result = Received::pending(Status::ControlPending);
        #[cfg(feature = "test-knobs")]
        let mut unexpected_body = None;
        loop {
            let incoming = match io.read(credit.remaining_wire()).await? {
                Read::Frame(frame) => frame,
                Read::Busy => {
                    io.abort(WireError::SessionBusy);
                    result.status = Status::Busy;
                    return Ok(result);
                }
                Read::End => return Err(Error::Unreachable("history response ended before DONE")),
            };
            // The parsed proof vector dies before moving the still-charged raw frame into a
            // blocking worker. Its second decode never overlaps this first allocation.
            let action = {
                let frame = incoming.frame()?;
                if let Err(error) = credit.accept(&frame, incoming.wire_len()) {
                    // A hostile authenticated source can send the private bytes which its own
                    // signed header says belong to somebody else. Refuse those bytes, but do not
                    // discard the already authenticated header handoff. Its inclusion/effect
                    // work remains queued locally and the archive resumes below it only after
                    // that durable settlement. Any other malformed frame still fails the peer.
                    let refused_exact_role_body = matches!(
                        (&result.role_ready, &frame),
                        (
                            Some((_, _, expected)),
                            Frame::Chunk {
                                request: chunk_request,
                                entry,
                                offset: 0,
                                bytes,
                            }
                        ) if *chunk_request == request && entry == expected && !bytes.is_empty()
                    );
                    if refused_exact_role_body {
                        let Some((_, seq, _)) = result.role_ready else {
                            unreachable!()
                        };
                        let Query::Page {
                            head,
                            lo,
                            hi,
                            entries,
                            ..
                        } = &query
                        else {
                            return Err(error);
                        };
                        let continuation = Continuation {
                            query_kind: 4,
                            head: *head,
                            lo: *lo,
                            hi: *hi,
                            next_seq: seq,
                            entry: None,
                            offset: 0,
                            entries_remaining: *entries,
                        };
                        result.continuation = self
                            .checkpoint_response(
                                io.job(),
                                request,
                                &query,
                                Status::More,
                                Some(continuation),
                            )
                            .await?;
                        io.abort(WireError::ProtocolLimits);
                        self.hold_role_settlement().await?;
                        result.status = Status::ControlPending;
                        return Ok(result);
                    }
                    return Err(error);
                }
                match frame {
                    Frame::Meta { .. } => Action::Meta,
                    Frame::Have(hints) => Action::Inventory(hints),
                    Frame::Chunk {
                        entry,
                        offset,
                        bytes,
                        ..
                    } => Action::Chunk {
                        entry,
                        next: offset + bytes.len() as u64,
                    },
                    Frame::Done {
                        status,
                        continuation,
                        ..
                    } => Action::Done(status, continuation),
                    _ => return Err(Error::MalformedBundle("unexpected history response")),
                }
            };
            match action {
                Action::Inventory(hints) => {
                    let Some(charge) = io
                        .job()
                        .reserve(hints.capacity() * std::mem::size_of::<super::HeadHint>())
                    else {
                        io.abort(WireError::SessionBusy);
                        result.status = Status::Busy;
                        return Ok(result);
                    };
                    result.inventory = Some(Inventory {
                        hints,
                        _charge: charge,
                    });
                    drop(incoming);
                }
                Action::Meta => {
                    let generation = self.generation;
                    let selected = query.clone();
                    let committed = self.source.commit_ledger();
                    let Some(work_job) = io.job().record_job(12 * 1024 * 1024).await else {
                        io.abort(WireError::SessionBusy);
                        result.status = Status::Busy;
                        return Ok(result);
                    };
                    let staged = self
                        .read(&work_job, VERIFY_ENVELOPE, move |room, store| {
                            let Frame::Meta { object, .. } = incoming.frame()? else {
                                return Err(Error::MalformedBundle("metadata frame changed"));
                            };
                            admission::stage(
                                room, store, &committed, request, generation, &selected, object,
                            )
                            .map(Some)
                        })
                        .await?;
                    let Lookup::Found(staged) = staged else {
                        io.abort(WireError::SessionBusy);
                        result.status = Status::Busy;
                        return Ok(result);
                    };
                    match &staged.value {
                        Staged::Object { brought } => result.brought |= *brought,
                        Staged::Busy => {
                            io.abort(WireError::SessionBusy);
                            result.status = Status::Busy;
                            return Ok(result);
                        }
                        Staged::Head {
                            head,
                            tail,
                            author,
                            departure_receipt,
                            held,
                            brought,
                        } => {
                            if result.heads.len() >= MAX_NEEDS {
                                return Err(Error::SizeLimitExceeded("history head result bound"));
                            }
                            result.brought |= *brought;
                            result.heads.push(super::HeadHint {
                                author: *author,
                                head: *head,
                                size: *tail,
                            });
                            if *departure_receipt {
                                result.departure_receipt = Some(super::HeadHint {
                                    author: *author,
                                    head: *head,
                                    size: *tail,
                                });
                            } else if *held {
                                // Already in the author's accepted chain: its tail header,
                                // inclusion proof and promotion are done. Fetching and
                                // verifying them again every period wrote a cursor, a
                                // context per join and a receipt for nothing (ADR-038
                                // FX-29); the window below resumes from what is held.
                            } else if *tail == 0 {
                                // The canonical empty head has no position-zero header. Its
                                // ordinary empty consistency proof is the complete promotion
                                // path and makes the exact head available for peer echo.
                                result.need(Query::Proof {
                                    head: *head,
                                    kind: ProofKind::Consistency,
                                    from: 0,
                                    to: 0,
                                })?;
                            } else {
                                result.need(Query::Header {
                                    head: *head,
                                    seq: *tail,
                                })?;
                            }
                        }
                        Staged::Verifier(binding) => {
                            if result.verifiers.len() == MAX_NEEDS {
                                return Err(Error::SizeLimitExceeded("history verifier handoff"));
                            }
                            result.brought = true;
                            result.verifiers.push(*binding);
                        }
                        Staged::Header {
                            entry,
                            head,
                            body_allowed,
                            brought,
                        } => {
                            result.brought |= *brought;
                            let seq = entry.skeleton.seq;
                            result.need(Query::Proof {
                                head: *head,
                                kind: ProofKind::Inclusion,
                                from: seq,
                                to: seq,
                            })?;
                            if matches!(query, Query::Header { .. }) {
                                continue;
                            }
                            // The authenticated header says this private package belongs to a
                            // different member.  Do not create a body staging target or grant
                            // chunk credit.  An honest peer completes the role-visible entry
                            // header-only; an unexpected body frame is refused by credit.accept
                            // before Action::Chunk can persist a byte.
                            #[cfg(feature = "test-knobs")]
                            if !body_allowed {
                                unexpected_body = Some(entry.entry_hash());
                            }
                            if !body_allowed {
                                if result
                                    .role_ready
                                    .replace((*head, seq, entry.entry_hash()))
                                    .is_some()
                                {
                                    return Err(Error::SizeLimitExceeded(
                                        "history role-complete header handoff",
                                    ));
                                }
                                continue;
                            }
                            let Some(staging) = &self.staging else {
                                io.abort(WireError::SessionBusy);
                                return Err(Error::Profile(
                                    "history body has no authorized staging activation",
                                ));
                            };
                            let header = entry.header_wire();
                            let hash = entry.entry_hash();
                            let length = entry.skeleton.payload_len;
                            let staging = staging.clone();
                            let job = io.job().clone();
                            let head = *head;
                            let expected_offset = match query {
                                Query::Entry { offset, .. } => offset,
                                _ => 0,
                            };
                            let fence = self.source.fence.clone();
                            let deadline = self.source.deadline;
                            let offset = tokio::task::spawn_blocking(move || {
                                let _held_header = staged;
                                current(&fence, deadline)?;
                                let mut active = staging.active.lock().map_err(|_| {
                                    Error::Profile("history activation lock failed")
                                })?;
                                let state = demand::inspect(&staging.context, &job)?
                                    .ok_or(Error::Profile("history activation is absent"))?;
                                if !active.matches(state.state())
                                    || active.request() != request
                                    || state.state().bounds.head != head
                                {
                                    return Err(Error::Profile(
                                        "history activation binding changed",
                                    ));
                                }
                                if let Some(body) = &state.state().body {
                                    if body.entry != hash || body.offset != expected_offset {
                                        return Err(Error::Profile(
                                            "history response differs from persisted body",
                                        ));
                                    }
                                } else if expected_offset != 0 {
                                    return Err(Error::Profile(
                                        "history continuation has no persisted body",
                                    ));
                                }
                                drop(state);
                                demand::begin_body(
                                    &staging.context,
                                    &mut active,
                                    hash,
                                    seq,
                                    length,
                                    &header,
                                    &job,
                                )?;
                                current(&fence, deadline)?;
                                Ok(expected_offset)
                            })
                            .await
                            .map_err(|_| Error::Unreachable("history body staging stopped"))??;
                            credit.expect_body(hash, length, offset)?;
                            if length == offset {
                                result.body_ready = Some(hash);
                                result.continuation = self
                                    .checkpoint_response(
                                        io.job(),
                                        request,
                                        &query,
                                        Status::ControlPending,
                                        None,
                                    )
                                    .await?;
                                io.abort(WireError::SessionBusy);
                                return Ok(result);
                            }
                        }
                    }
                }
                Action::Chunk { entry, next } => {
                    let Some(staging) = &self.staging else {
                        return Err(Error::Profile("history chunk has no activation"));
                    };
                    let staging = staging.clone();
                    let job = io.job().clone();
                    let fence = self.source.fence.clone();
                    let deadline = self.source.deadline;
                    let (persisted, complete) = tokio::task::spawn_blocking(move || {
                        current(&fence, deadline)?;
                        let Frame::Chunk {
                            entry: exact,
                            offset,
                            bytes,
                            ..
                        } = incoming.frame()?
                        else {
                            return Err(Error::MalformedBundle("history chunk frame changed"));
                        };
                        let mut active = staging
                            .active
                            .lock()
                            .map_err(|_| Error::Profile("history activation lock failed"))?;
                        let persisted = demand::append(
                            &staging.context,
                            &mut active,
                            exact,
                            offset,
                            bytes,
                            &job,
                        )?;
                        let snapshot = demand::inspect(&staging.context, &job)?
                            .ok_or(Error::Profile("history body disappeared"))?;
                        let complete =
                            snapshot.state().body.as_ref().is_some_and(|body| {
                                body.entry == exact && body.offset == body.length
                            });
                        Ok((persisted, complete))
                    })
                    .await
                    .map_err(|_| Error::Unreachable("history chunk persistence stopped"))??;
                    if persisted != next {
                        return Err(Error::MalformedAtRest("history persisted offset differs"));
                    }
                    #[cfg(feature = "test-knobs")]
                    if complete && unexpected_body == Some(entry) {
                        self.hold_unexpected_body_durable(&entry).await?;
                    }
                    self.source.note_work_committed();
                    // Durable nonempty chunk progress remains progress even if later metadata
                    // or ACK allocation is Busy within this same bounded response.
                    result.body_progress = true;
                    // Current room access is checked again after durable storage and before ACK.
                    if !self.authorize(io.job()).await? {
                        io.abort(WireError::SessionBusy);
                        result.status = Status::Busy;
                        return Ok(result);
                    }
                    credit.acknowledge(request, entry, persisted)?;
                    let ack = Frame::Ack {
                        request,
                        entry,
                        next_offset: persisted,
                    };
                    let Some(encoded) = ack.encode(io.job())? else {
                        io.abort(WireError::SessionBusy);
                        result.status = Status::Busy;
                        return Ok(result);
                    };
                    credit.charge_overhead(encoded.as_slice().len() + 4)?;
                    io.write_encoded(&encoded).await?;
                    if complete {
                        result.body_ready = Some(entry);
                        result.continuation = self
                            .checkpoint_response(
                                io.job(),
                                request,
                                &query,
                                Status::ControlPending,
                                None,
                            )
                            .await?;
                        // The ACK must reach the source so it can release this completed Live
                        // grant. Gracefully finish the send direction; resetting it here can
                        // discard the buffered ACK. The actor still owns the provisional body's
                        // opaque inclusion/control/authority admission, and this stream accepts
                        // no additional entry.
                        io.finish()?;
                        result.status = Status::ControlPending;
                        return Ok(result);
                    }
                }
                Action::Done(status, continuation) => {
                    drop(incoming);
                    result.status = status;
                    result.continuation = self
                        .checkpoint_response(io.job(), request, &query, status, continuation)
                        .await?;
                    io.finish()?;
                    return Ok(result);
                }
            }
        }
    }

    async fn hold_role_settlement(&self) -> Result<()> {
        #[cfg(feature = "test-knobs")]
        {
            let Some(trigger) = std::env::var_os(TEST_HOLD_ROLE_SETTLEMENT_ENV)
                .filter(|path| !path.is_empty())
                .map(std::path::PathBuf::from)
                .filter(|path| path.is_file())
            else {
                return Ok(());
            };
            let mut engaged = trigger.as_os_str().to_os_string();
            engaged.push(".engaged");
            let engaged: std::path::PathBuf = engaged.into();
            std::fs::rename(&trigger, &engaged).map_err(|_| {
                Error::Profile("test role-settlement marker could not record engagement")
            })?;
            while engaged.is_file() {
                current(&self.source.fence, self.source.deadline)?;
                // Apparatus polling only: removing the marker is the causal release; elapsed
                // time never changes product state or makes the proof pass.
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        }
        Ok(())
    }

    #[cfg(feature = "test-knobs")]
    async fn hold_unexpected_body_durable(&self, entry: &Digest32) -> Result<()> {
        if let Some(path) = std::env::var_os(TEST_BODY_DURABLE_ENV)
            .filter(|path| !path.is_empty())
            .map(std::path::PathBuf::from)
        {
            std::fs::write(&path, entry)
                .map_err(|_| Error::Profile("test durable-body marker could not be written"))?;
            while path.is_file() {
                current(&self.source.fence, self.source.deadline)?;
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        }
        Ok(())
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
            .read(&work_job, VERIFY_ENVELOPE, move |room, store| {
                if room.channel_id() != binding.room {
                    return Err(Error::Profile("history verifier room changed"));
                }
                admission::advance(room, store, &commit_ledger, &binding).map(Some)
            })
            .await?;
        Ok(advanced)
    }
}

enum Action {
    Inventory(Vec<super::HeadHint>),
    Meta,
    Chunk { entry: Digest32, next: u64 },
    Done(Status, Option<Continuation>),
}

/// The complete record and its entire parse/seal/render working envelope travel together.
/// No actor handoff may retain the entry while dropping this reservation.
pub(crate) struct Record {
    pub(crate) entry: crate::log::entry::Entry,
    job: crate::node::history_budget::Job,
    _charge: crate::node::history_budget::BufferCharge,
    staged: Option<(RequestId, Digest32, StagedAdmission)>,
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
}

impl Receiver {
    /// Assemble exactly the already requested entry, at most256 persisted64-KiB pages.
    /// This is not a history fetch and cannot select another entry or begin another demand.
    pub(crate) async fn assemble(
        &self,
        job: &crate::node::history_budget::Job,
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
            let envelope = 5 * (body.length as usize + crate::log::history::MAX_HEADER_BYTES + 9)
                + VERIFY_ENVELOPE;
            let Some(record_job) =
                tokio::runtime::Handle::current().block_on(job.record_job(envelope))
            else {
                return Ok(Assembly::Busy);
            };
            let Some(charge) = record_job.reserve(envelope) else {
                return Ok(Assembly::Busy);
            };
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
                staged: Some((active.request(), generation, StagedAdmission::Body)),
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
        self.read_precharged(&job, 64 * 1024, record, move |room, store, record| {
            admission::start_entry(
                room,
                store,
                &committed,
                request,
                generation,
                head,
                &record.entry,
                require_body,
                context_ready,
            )
            .map(Some)
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
        self.read_precharged(&job, 512 * 1024, record, move |room, store, record| {
            if record.entry.skeleton.author_id != binding.author
                || record.entry.skeleton.seq != binding.from
            {
                return Err(Error::Profile("history entry record changed"));
            }
            if room.channel_id() != binding.room {
                return Err(Error::Profile("history entry room changed"));
            }
            admission::advance_entry(room, store, &committed, binding).map(Some)
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
    /// Persist the peer's hint only after rebinding it to the original local authorization.
    /// Metadata/control queries do not change an archive operation's page bounds or credit.
    async fn checkpoint_response(
        &self,
        job: &crate::node::history_budget::Job,
        request: RequestId,
        query: &Query,
        status: Status,
        hint: Option<Continuation>,
    ) -> Result<Option<Continuation>> {
        if !matches!(query, Query::Entry { .. } | Query::Page { .. }) {
            return Ok(hint);
        }
        let staging = self
            .staging
            .clone()
            .ok_or(Error::Profile("history response has no staging activation"))?;
        let fence = self.source.fence.clone();
        let deadline = self.source.deadline;
        let job = job.clone();
        tokio::task::spawn_blocking(move || {
            current(&fence, deadline)?;
            let mut active = staging
                .active
                .lock()
                .map_err(|_| Error::Profile("history activation lock failed"))?;
            let snapshot = demand::inspect(&staging.context, &job)?
                .ok_or(Error::Profile("history activation disappeared"))?;
            let state = snapshot.state();
            if !active.matches(state) || active.request() != request {
                return Err(Error::Profile("history response activation changed"));
            }
            let normalized = if let Some(body) = &state.body {
                if hint.as_ref().is_some_and(|cursor| {
                    cursor.head != state.bounds.head
                        || cursor.entry != Some(body.entry)
                        || cursor.next_seq != body.seq
                        || cursor.offset != body.offset
                }) {
                    return Err(Error::MalformedBundle(
                        "history body hint differs from storage",
                    ));
                }
                Some(Continuation {
                    query_kind: 3,
                    head: state.bounds.head,
                    lo: state.bounds.lo,
                    hi: state.bounds.hi,
                    next_seq: body.seq,
                    entry: Some(body.entry),
                    offset: body.offset,
                    entries_remaining: state.remaining,
                })
            } else if let Some(hint) = hint {
                if hint.head != state.bounds.head || hint.entry.is_some() || hint.offset != 0 {
                    return Err(Error::MalformedBundle("history hint differs from storage"));
                }
                Some(Continuation {
                    query_kind: 4,
                    head: state.bounds.head,
                    lo: state.bounds.lo,
                    hi: state.bounds.hi,
                    next_seq: hint.next_seq,
                    entry: None,
                    offset: 0,
                    entries_remaining: state.remaining,
                })
            } else {
                None
            };
            let progress = match status {
                Status::EvidenceUnavailable | Status::BodyNotHeld => demand::Progress::Unavailable,
                Status::More if normalized.is_some() => demand::Progress::More,
                Status::Complete if state.body.is_none() && !state.reclaiming() => {
                    demand::Progress::Complete
                }
                _ => demand::Progress::Pending,
            };
            drop(snapshot);
            demand::checkpoint(
                &staging.context,
                &mut active,
                progress,
                normalized.as_ref(),
                &job,
            )?;
            current(&fence, deadline)?;
            Ok(normalized)
        })
        .await
        .map_err(|_| Error::Unreachable("history checkpoint worker stopped"))?
    }

    /// Load one exact authenticated provisional header. Reserving from its signed length also
    /// covers a later effect worker opening an already held body; no archive scan is involved.
    pub(super) async fn header_record(
        &self,
        job: &crate::node::history_budget::Job,
        head: Digest32,
        seq: u64,
    ) -> Result<Assembly> {
        let Some(work_job) = job.record_job(12 * 1024 * 1024).await else {
            return Ok(Assembly::Busy);
        };
        let header = self
            .read(&work_job, 64 * 1024, move |room, store| {
                let input = room.history_read(store)?;
                input.history_pending_header(&head, seq)
            })
            .await?;
        let Lookup::Found(header) = header else {
            return Ok(match header {
                Lookup::Busy => Assembly::Busy,
                _ => Assembly::Pending,
            });
        };
        let envelope = 5
            * (header.value.skeleton.payload_len as usize
                + crate::log::history::MAX_HEADER_BYTES
                + 9)
            + VERIFY_ENVELOPE;
        // Release the metadata job before attempting a large body job. The small header itself
        // stays charged until its replacement reservation has been acquired.
        let Some(record_job) = job.record_job(envelope).await else {
            return Ok(Assembly::Busy);
        };
        let Some(charge) = record_job.reserve(envelope) else {
            return Ok(Assembly::Busy);
        };
        let entry = header.value;
        Ok(Assembly::Ready(Arc::new(Record {
            entry,
            job: record_job,
            _charge: charge,
            staged: None,
        })))
    }

    /// One preparation quantum. It never loops through an archive or through a fresh budget.
    pub(super) async fn advance_source(
        &self,
        record: Arc<Record>,
    ) -> Result<Lookup<(Arc<Record>, bool)>> {
        let job = record.job.clone();
        let committed = self.source.commit_ledger();
        self.read_precharged(&job, 64 * 1024, record, move |room, store, _| {
            let advanced = room.advance_history_source(store, &committed)?;
            Ok(Some(advanced))
        })
        .await
    }

    pub(super) async fn commit_source(
        &self,
        record: Arc<Record>,
        binding: CursorBinding,
        now: crate::time::Ms,
    ) -> Result<Lookup<(Arc<Record>, ())>> {
        if binding.generation != self.generation {
            return Err(Error::Profile("history publication activation changed"));
        }
        let job = record.job.clone();
        let grant = self.grant();
        let committed = self.source.commit_ledger();
        self.read_precharged(&job, 64 * 1024, record, move |room, store, record| {
            if binding.room != room.channel_id()
                || binding.author != record.entry.skeleton.author_id
                || binding.from != record.entry.skeleton.seq
            {
                return Err(Error::Profile("history publication record changed"));
            }
            let room_id = room.channel_id();
            let instance = room.history_instance(store)?;
            let epoch = room.epoch();
            room.commit_history_source(store, &committed, &record.entry, now, |batch| {
                grant.check_batch(batch, room_id, instance, epoch)
            })?;
            // Publication is now Switched, not Idle. Keep the exact verifier until the
            // bounded cleanup phase finishes; sparse metadata cannot mutate these roots yet.
            Ok(Some(()))
        })
        .await
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
        self.read_precharged(&job, 64 * 1024, record, move |room, store, record| {
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
                .ok_or(Error::Profile("history cleanup inclusion missing"))?;
            if included.header().entry().header_wire() != record.entry.header_wire() {
                return Err(Error::Profile("history cleanup head/entry changed"));
            }
            drop(input);
            let done = room.cleanup_history_source(store, &committed)?;
            if done {
                // The same room lock spans cleanup's transition to Idle and this exact
                // cursor retirement. A crash between them leaves only a resumable cursor;
                // the accepted source is already durable and is never rolled back here.
                room.history_write_tracked(store, &committed, |index| {
                    index.finish_history_verifier_cursor(binding)
                })?;
            }
            Ok(Some(done))
        })
        .await
    }

    /// One existing authority/effect slice, with the full signed-length record reservation.
    /// Only the final semantic Batch clears this exact provisional body from demand staging.
    pub(super) async fn advance_effect(
        &self,
        record: Arc<Record>,
        mut cursor: crate::node::channel::HistoryEffectCursor,
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
        let staging = self.staging.clone();
        let grant = self.grant();
        let historical = self.historical;
        let committed = self.source.commit_ledger();
        self.read_precharged(&job, 64 * 1024, record, move |room, store, record| {
            let room_id = room.channel_id();
            let instance = room.history_instance(store)?;
            let epoch = room.epoch();
            let body_expected = record.staged.is_some();
            let outcome = room.advance_history_effect(
                store,
                &committed,
                &mut cursor,
                now,
                body_expected,
                historical,
                |batch| grant.check_batch(batch, room_id, instance, epoch),
                |batch, hash| complete_staged(batch, staging.as_ref(), record, hash),
            )?;
            Ok(Some((cursor, outcome)))
        })
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
        let staging = self.staging.clone();
        let grant = self.grant();
        let historical = self.historical;
        let committed = self.source.commit_ledger();
        self.read_precharged(&job, 64 * 1024, record, move |room, store, record| {
            use crate::node::channel::governance::{PayloadValidation, TypedSparseBody};
            let key = room
                .history_author_key(&record.entry.skeleton.author_id)
                .ok_or(Error::MalformedBundle("history refill author vanished"))?;
            let body = match TypedSparseBody::verify(
                &record.entry,
                &key,
                &mut crate::log::history::WorkBudget::default(),
            )? {
                PayloadValidation::Complete(body) => body,
                _ => return Err(Error::MalformedBundle("history refill body is incomplete")),
            };
            let room_id = room.channel_id();
            let instance = room.history_instance(store)?;
            let epoch = room.epoch();
            let progress = room.refill_history_body(
                store,
                &committed,
                &record.entry,
                &body,
                now,
                historical,
                |batch| grant.check_batch(batch, room_id, instance, epoch),
                |batch, hash| complete_staged(batch, staging.as_ref(), record, hash),
            )?;
            Ok(Some(progress))
        })
        .await
    }
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
            demand::entry_admitted(batch, &staging.context, &active, hash, &record.job)
        }
        StagedAdmission::RoleHeader => demand::role_header_admitted(
            batch,
            &staging.context,
            &active,
            record.entry.skeleton.seq,
            &record.job,
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
    Preflight { parent: usize, next: usize },
    Body,
    Validate(CursorBinding),
    Begin(CursorBinding),
    Prepare(CursorBinding),
    Commit(CursorBinding),
    Cleanup(CursorBinding),
    Refill,
    Effect(Option<crate::node::channel::HistoryEffectCursor>),
}
pub(crate) enum LocalNeed {
    /// Resume only through the existing operation's exact persisted body cursor.
    StagedBody,
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
}
pub(crate) struct LocalResult {
    pub(crate) next: Option<LocalStep>,
    pub(crate) need: Option<LocalNeed>,
    /// Semantic dispatch completed; a header-only source need not have a visible body.
    pub(crate) published: Option<Digest32>,
    pub(crate) rendered: bool,
    pub(crate) governance: bool,
    pub(crate) busy: bool,
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
        use crate::node::channel::{HistoryEffectProgress as Effect, HistorySourceStart as Start};
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
                    | EntryPhase::Commit(_)
                    | EntryPhase::Refill
                    | EntryPhase::Effect(_)
            );
        let assembly = if full {
            self.assemble(job).await?
        } else {
            self.header_record(job, head, seq).await?
        };
        let mut record = match assembly {
            Assembly::Ready(record) => record,
            Assembly::Busy => return Ok(LocalResult::busy(step)),
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
        if (body && !full) || role_header {
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
        let is_governance = record
            .entry
            .skeleton
            .v2
            .as_ref()
            .is_some_and(|v2| v2.kind == crate::log::history::SignedEntryKind::Governance);
        let effect_result = |progress| -> LocalResult {
            match progress {
                Effect::Progress => LocalResult::next(step),
                Effect::RefillPending { governance: true } => {
                    LocalResult::wait(step, LocalNeed::Governance)
                }
                Effect::RefillPending { governance: false } => LocalResult::next(step),
                Effect::BodyUnavailable => LocalResult::wait(step, LocalNeed::StagedBody),
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
                Effect::Busy => LocalResult::busy(step),
                Effect::Complete { rendered } => LocalResult {
                    next: None,
                    need: None,
                    published: Some(hash),
                    rendered,
                    governance: is_governance,
                    busy: false,
                },
            }
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
                    admission::EntryAdvanced::Busy => LocalResult::busy(step),
                }
            }
            EntryPhase::Begin(binding) => {
                let job = record.job.clone();
                let committed = self.source.commit_ledger();
                let value = self
                    .read_precharged(&job, 64 * 1024, record, move |room, store, record| {
                        let admission::EntryAdvanced::Validated(validated) =
                            admission::advance_entry(room, store, &committed, binding)?
                        else {
                            return Err(Error::Profile(
                                "completed history validation requires renewed evidence",
                            ));
                        };
                        let started = room.begin_history_source(
                            store,
                            &committed,
                            request,
                            &record.entry,
                            &validated,
                            now,
                        )?;
                        if matches!(started, Start::Duplicate) {
                            room.history_write_tracked(store, &committed, |index| {
                                index.finish_history_verifier_cursor(binding)
                            })?;
                        }
                        Ok(Some(started))
                    })
                    .await?;
                let Lookup::Found(value) = value else {
                    return Ok(LocalResult::busy(step));
                };
                match value.value.1 {
                    Start::Started => LocalResult::next(next(EntryPhase::Prepare(binding))),
                    Start::Duplicate => LocalResult::next(next(if body {
                        EntryPhase::Refill
                    } else {
                        EntryPhase::Effect(None)
                    })),
                    Start::Busy => LocalResult::busy(step),
                }
            }
            EntryPhase::Prepare(binding) => {
                let Lookup::Found(value) = self.advance_source(record).await? else {
                    return Ok(LocalResult::busy(step));
                };
                LocalResult::next(next(if value.value.1 {
                    EntryPhase::Commit(binding)
                } else {
                    phase
                }))
            }
            EntryPhase::Commit(binding) => {
                let Lookup::Found(_) = self.commit_source(record, binding, now).await? else {
                    return Ok(LocalResult::busy(step));
                };
                LocalResult::next(next(EntryPhase::Cleanup(binding)))
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
                if let Effect::RefillPending { governance } = progress {
                    let refill = next(EntryPhase::Refill);
                    return Ok(if governance {
                        LocalResult::wait(refill, LocalNeed::Governance)
                    } else {
                        LocalResult::next(refill)
                    });
                }
                let mut result = effect_result(progress);
                if result.next.is_some() {
                    result.next = Some(next(EntryPhase::Effect(Some(cursor))));
                }
                result
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
            .read(&work_job, VERIFY_ENVELOPE, move |room, store| {
                let input = room.history_read(store)?;
                if room.history_publication_busy(store)? {
                    return Ok(None);
                }
                let target = input
                    .history_head(&head)?
                    .ok_or(Error::MalformedAtRest("control target head missing"))?;
                if through == 0 || through > target.root.leaves {
                    return Err(Error::Profile("control receipt bound exceeds target"));
                }
                let complete = if effects {
                    input.control_effects_complete(&head, through)?
                } else {
                    input.control_sources_complete(&head, through)?
                };
                if complete {
                    // Effects may finish while this signed head is still only observed. The
                    // effect walker then cannot publish its exact-head receipt yet. Once the
                    // same head commits, do one writer turn even though its prefix is already
                    // complete so `advance_control_effects` can atomically promote it to
                    // `control_ready`; otherwise every later inventory re-offers it forever.
                    let state =
                        input.sparse_author(&target.binding.author, target.binding.scope)?;
                    let receipt_ready = !effects
                        || through < target.root.leaves
                        || state.is_some_and(|state| state.control_ready == Some(head));
                    if receipt_ready {
                        return Ok(Some((SourceProgress::Complete { through }, None)));
                    }
                }
                drop(input);
                let progress = room.history_write_tracked(store, &committed, |index| {
                    if effects {
                        index.advance_control_effects(&head, through)
                    } else {
                        index.advance_control_sources(&head, through)
                    }
                })?;
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
                Ok(Some((progress, needed)))
            })
            .await?;
        let Lookup::Found(value) = value else {
            return Ok(LocalResult::busy(step));
        };
        Ok(match value.value {
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
                ))
            }
        })
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
            return Err(Error::Profile("history authorization changed"));
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
            return Err(Error::Profile(
                "history authorization changed before publication",
            ));
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
        self.source
            .read(job, envelope, move |room, store| {
                grant.check(room, store)?;
                read(room, store)
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
        self.source
            .read_precharged(job, envelope, record, move |room, store, record| {
                grant.check(room, store)?;
                read(room, store, record)
            })
            .await
    }
    async fn authorize(&self, job: &crate::node::history_budget::Job) -> Result<bool> {
        Ok(matches!(
            self.read(job, 0, |_, _| Ok(Some(()))).await?,
            Lookup::Found(_)
        ))
    }
}

/// Charged scalar hints only. They never advance a feed or authorize a body request.
pub(crate) struct Inventory {
    pub(crate) hints: Vec<super::HeadHint>,
    _charge: crate::node::history_budget::BufferCharge,
}
