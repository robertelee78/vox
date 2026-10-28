//! Bounded durable staging for explicit archive and current live/control (ADR-036 H-4/H-7).
//!
//! The disk record never authorizes traffic. Only an explicit start/resume produces an Active
//! handle, and every mutation checks its durable fencing serial. Callers recheck current room,
//! trust and audience authority before use. Partial pages are sealed provisional bytes, never
//! canonical LogDb entries. Obtain a shared Job outside actor locks before calling this module.
//! Archive has one fixed slot per node, including paused work. Live and control each have one
//! separate fixed slot so neither a paused archive nor a large live body blocks essential control.
//! Those slots add no workers or memory pool; their actual buffers use the shared foreground jobs.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::history_budget::{BufferCharge, Job};
use super::history_stream::{Continuation, Purpose, RequestId};
use super::profile::Profile;
use super::store::{Batch, Snapshot as StoreSnapshot, Store};
use crate::atrest::sek::Sek;
use crate::atrest::store::{open_segment, seal_segment, SegmentKind};
use crate::error::{Error, Result};
use crate::hash::{sha256, Digest32};
use crate::log::feed::MAX_SEQ;
use crate::log::history::{MAX_CHUNK_BYTES, MAX_HEADER_BYTES, MAX_PAGE_ENTRIES, MAX_PAYLOAD_BYTES};

const KIND: SegmentKind = SegmentKind::HistoryDemand;
const HEADER: u64 = 0;
const STATE_BYTES: usize = 64 * 1024;
const STATE_WORK: usize = 8 * STATE_BYTES;
const PAGE_BYTES: usize = MAX_CHUNK_BYTES;
const PAGE_COUNT: u64 = (MAX_PAYLOAD_BYTES / PAGE_BYTES) as u64;
// version, node scope, request, entry hash, page number; all are inside the AEAD body.
const PAGE_PREFIX: usize = 1 + 32 + 16 + 32 + 8;
const PAGE_WORK: usize = 4 * (PAGE_BYTES + PAGE_PREFIX + 64);
// Respect both the 64-row and 1-MiB slice bounds even if removed value bytes count as work.
const RECLAIM_ROWS: u64 = ((1024 * 1024 - STATE_BYTES) / (PAGE_BYTES + PAGE_PREFIX + 64)) as u64;

/// One owned, unlocked worker context. It may not outlive its tracked node task: lock and
/// authority withdrawal cancel it and await that bounded worker before reporting completion.
/// The actor checks current authority/activation before dispatch and again before sending ACK.
pub struct Context {
    node: Digest32,
    scope: Digest32,
    slot: Slot,
    store: Arc<Store>,
    key: Sek,
    cancellation: Cancellation,
    // Declared after the key: release the lock-completion barrier only after secrets drop.
    _secret_work: Arc<tokio::sync::OwnedRwLockReadGuard<()>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Slot {
    Archive,
    OwnRecovery,
    Live,
    Control,
}

/// The actor retains this handle to fence a worker even when a blocking disk call cannot abort.
#[derive(Clone)]
pub struct Cancellation(Arc<AtomicBool>);

impl Cancellation {
    pub fn cancel(&self) {
        self.0.store(true, Ordering::Release);
    }
    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

impl Context {
    /// Explicit archive commands only. A retained record cannot create or resume this context.
    pub fn unlocked(
        profile: &Profile,
        secret_work: Arc<tokio::sync::OwnedRwLockReadGuard<()>>,
    ) -> Result<Self> {
        Self::with_slot(profile, Slot::Archive, secret_work)
    }
    /// Current-purpose work only; a network handler cannot use this to start archive demand.
    pub fn current_unlocked(
        profile: &Profile,
        purpose: Purpose,
        secret_work: Arc<tokio::sync::OwnedRwLockReadGuard<()>>,
    ) -> Result<Self> {
        let slot = match purpose {
            Purpose::Live => Slot::Live,
            Purpose::Control => Slot::Control,
            Purpose::History => return Err(invalid("archive requires explicit local demand")),
        };
        Self::with_slot(profile, slot, secret_work)
    }
    /// Local durable own-feed recovery only; no public command or network request mints it.
    pub(crate) fn own_recovery_unlocked(
        profile: &Profile,
        room: Digest32,
        secret_work: Arc<tokio::sync::OwnedRwLockReadGuard<()>>,
    ) -> Result<Self> {
        let mut context = Self::with_slot(profile, Slot::OwnRecovery, secret_work)?;
        context.scope = own_recovery_scope(context.node, room);
        Ok(context)
    }
    fn with_slot(
        profile: &Profile,
        slot: Slot,
        secret_work: Arc<tokio::sync::OwnedRwLockReadGuard<()>>,
    ) -> Result<Self> {
        let key = crate::atrest::seal::sek(profile.signer()?, b"vox/history-demand-sek/v1")?;
        let node = profile.fingerprint();
        Ok(Self {
            node,
            scope: node_scope(node, slot),
            slot,
            store: profile.store_handle(),
            key,
            cancellation: Cancellation(Arc::new(AtomicBool::new(false))),
            _secret_work: secret_work,
        })
    }
    pub fn cancellation(&self) -> Cancellation {
        self.cancellation.clone()
    }
    fn fingerprint(&self) -> Digest32 {
        self.node
    }
    fn store(&self) -> &Store {
        &self.store
    }
    fn check(&self) -> Result<()> {
        if self.cancellation.is_cancelled() {
            Err(invalid(CANCELLED))
        } else {
            Ok(())
        }
    }
}

/// Exact current authority, supplied and rechecked by the room owner, not by a peer cursor.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub room: Digest32,
    /// Saved room incarnation captured by the explicit local selection.
    pub instance: [u8; 16],
    pub epoch: u64,
    /// Public scope or the digest of the exact private audience.
    pub audience: Digest32,
    /// Digest of the current authorization/grant incarnation, including the room instance.
    pub grant: Digest32,
}

/// Immutable local authorization for one logical page; continuation never resets its count.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bounds {
    pub head: Digest32,
    pub lo: u64,
    pub hi: u64,
    pub entries: usize,
}

impl Bounds {
    fn validate(self) -> Result<()> {
        if self.lo == 0
            || self.lo > self.hi
            || self.hi > MAX_SEQ
            || self.entries == 0
            || self.entries > MAX_PAGE_ENTRIES
        {
            return Err(invalid("history demand bounds"));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Progress {
    Paused,
    Pending,
    More,
    Unavailable,
    Complete,
    Cancelled,
}

impl Progress {
    fn terminal(self) -> bool {
        matches!(self, Self::Complete | Self::Cancelled)
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Body {
    pub entry: Digest32,
    pub seq: u64,
    pub length: u64,
    pub offset: u64,
    /// Exact already-authenticated header, needed to finish the same entry after explicit resume.
    pub header: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Cursor {
    pub query_kind: u8,
    pub next_seq: u64,
    pub entry: Option<Digest32>,
    pub offset: u64,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Cleanup {
    next: u64,
    last: u64,
}

/// A private operation uses the same archive slot and immutable original interval.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PrivatePlan {
    pub donor: Digest32,
    pub grant: Digest32,
    pub inventory_done: bool,
    pub positions: Vec<super::sessionstream::Locator>,
}
impl PrivatePlan {
    fn validate(&self, bounds: Bounds) -> Result<()> {
        if bounds.hi - bounds.lo >= super::sessionstream::PAGE_RECORDS as u64
            || self.positions.len() > super::sessionstream::PAGE_RECORDS
            || (!self.inventory_done && !self.positions.is_empty())
            || self
                .positions
                .iter()
                .any(|p| p.id < bounds.lo || p.id > bounds.hi)
            || self.positions.windows(2).any(|p| p[0].id >= p[1].id)
        {
            return Err(bad());
        }
        Ok(())
    }
}

/// One explicitly selected legacy prefix. The provisional spool owns its exact tail and
/// publication cursor; this record only preserves the original local authorization.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LegacyPlan {
    pub author: Digest32,
    pub from: u64,
    pub through: u64,
    pub expected_base: u64,
}
impl LegacyPlan {
    fn validate(&self, bounds: Bounds) -> Result<()> {
        if self.from != bounds.lo
            || self.through != bounds.hi
            || self.expected_base.checked_add(1) != Some(self.from)
            || bounds.entries > 64
        {
            return Err(bad());
        }
        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct State {
    // Reconstructed from the authenticated envelope, never supplied by serialized state.
    #[serde(skip)]
    scope: Digest32,
    pub request: RequestId,
    pub binding: Binding,
    pub bounds: Bounds,
    pub remaining: usize,
    pub body: Option<Body>,
    pub cursor: Option<Cursor>,
    #[serde(default)]
    pub(crate) private: Option<PrivatePlan>,
    #[serde(default)]
    pub(crate) legacy: Option<LegacyPlan>,
    progress: Progress,
    serial: u64,
    cleanup: Option<Cleanup>,
}

impl State {
    pub(crate) fn stored_progress(&self) -> Progress {
        self.progress
    }
    /// A retained operation is always paused without a live handle from explicit local demand.
    pub fn progress(&self, active: Option<&Active>) -> Progress {
        if self.progress.terminal() || active.is_some_and(|a| a.matches(self)) {
            self.progress
        } else {
            Progress::Paused
        }
    }

    pub fn reclaiming(&self) -> bool {
        self.cleanup.is_some()
    }

    fn validate(&self) -> Result<()> {
        self.bounds.validate()?;
        if let Some(private) = &self.private {
            private.validate(self.bounds)?;
            if self.body.is_some() || self.cursor.is_some() || self.legacy.is_some() {
                return Err(bad());
            }
        }
        if let Some(legacy) = &self.legacy {
            legacy.validate(self.bounds)?;
            if self.body.is_some()
                || self.cursor.is_some()
                || (self.progress == Progress::Complete && self.remaining != 0)
            {
                return Err(bad());
            }
        }
        let maximum_remaining = self.legacy.map_or(Ok(self.bounds.entries), |legacy| {
            usize::try_from(legacy.through - legacy.expected_base).map_err(|_| bad())
        })?;
        if self.serial == 0 || self.remaining > maximum_remaining {
            return Err(bad());
        }
        if let Some(body) = &self.body {
            if body.seq < self.bounds.lo
                || body.seq > self.bounds.hi
                || body.length > MAX_PAYLOAD_BYTES as u64
                || body.offset > body.length
                || body.header.is_empty()
                || body.header.len() > MAX_HEADER_BYTES
                || self.cleanup.is_some()
                || self.progress.terminal()
            {
                return Err(bad());
            }
        }
        if let Some(cursor) = self.cursor {
            if cursor.query_kind > 4
                || cursor.next_seq < self.bounds.lo
                || cursor.next_seq > self.bounds.hi
                || cursor.offset > MAX_PAYLOAD_BYTES as u64
                || (cursor.offset != 0 && cursor.entry.is_none())
            {
                return Err(bad());
            }
        }
        if let Some(cleanup) = self.cleanup {
            if cleanup.next == 0 || cleanup.next > cleanup.last || cleanup.last > PAGE_COUNT {
                return Err(bad());
            }
        }
        Ok(())
    }
}

/// The allocation reservation follows the retained header across worker/actor handoff.
pub struct Snapshot {
    state: State,
    _charge: BufferCharge,
}

impl Snapshot {
    pub fn state(&self) -> &State {
        &self.state
    }
}

/// Never serialized or reconstructed during restart. A commit failure invalidates this handle.
pub struct Active {
    node: Digest32,
    scope: Digest32,
    request: RequestId,
    serial: u64,
    valid: bool,
    binding: Binding,
    cancellation: Cancellation,
}

impl Active {
    pub fn request(&self) -> RequestId {
        self.request
    }
    pub fn binding(&self) -> Binding {
        self.binding
    }
    pub fn matches(&self, state: &State) -> bool {
        self.valid
            && !self.cancellation.is_cancelled()
            && self.scope == state.scope
            && self.request == state.request
            && self.serial == state.serial
            && self.binding == state.binding
            && !state.progress.terminal()
    }
}

/// One decrypted storage page. Its charge remains held until the plaintext is wiped.
pub struct Page {
    bytes: Zeroizing<Vec<u8>>,
    _charge: BufferCharge,
}

impl Page {
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[PAGE_PREFIX..]
    }
}

/// The actor replaced, paused or stopped this request; a worker still holding its context stops
/// at its next store step. A local decision, never a fault of the room or of the peer.
pub(crate) const CANCELLED: &str = "history worker was cancelled";

fn invalid(message: &'static str) -> Error {
    Error::Profile(message)
}
fn bad() -> Error {
    Error::MalformedAtRest("history demand state")
}
fn charge(job: &Job, bytes: usize) -> Result<BufferCharge> {
    job.reserve_or_pressure(bytes)
}

/// The exact demand-state working envelope prepaid with a staged record. Semantic application
/// borrows this proof after it has begun; it never performs another fallible byte reservation.
pub(crate) struct AdmissionCharge {
    _charge: BufferCharge,
}

/// Exact durable terminal state returned to the one accepted local Cancel owner.
pub(crate) enum LocalCancelOutcome {
    NewlyCancelled(Box<CommittedCancel>),
    AlreadyCancelled(Box<CommittedCancel>),
    AlreadyComplete,
}

/// Capability to reclaim only the exact request whose Cancelled fence is already durable.
pub(crate) struct CommittedCancel {
    node: Digest32,
    scope: Digest32,
    request: RequestId,
    binding: Binding,
}

pub(crate) enum CommittedReclaim {
    More,
    Complete,
    Superseded,
}

impl AdmissionCharge {
    pub(crate) fn reserve(job: &Job) -> Result<Self> {
        charge(job, STATE_WORK).map(|charge| Self { _charge: charge })
    }
    /// Peak while reconstructing a staged body: one page's temporary state/page buffers and,
    /// when it shares the record's lane, the original demand Snapshot are simultaneously live.
    pub(crate) fn reconstruction_peak(record: usize, shared_snapshot: bool) -> Result<usize> {
        record
            .checked_add(STATE_WORK + PAGE_WORK)
            .and_then(|bytes| bytes.checked_add(if shared_snapshot { STATE_WORK } else { 0 }))
            .ok_or(Error::SizeLimitExceeded("history reconstruction envelope"))
    }

    pub(crate) fn total(record: usize) -> Result<usize> {
        record
            .checked_add(STATE_WORK)
            .ok_or(Error::SizeLimitExceeded("history completion envelope"))
    }

    pub(crate) fn split_from(combined: &mut BufferCharge) -> Result<Self> {
        let charge = combined
            .split_off(STATE_WORK)
            .ok_or(Error::SizeLimitExceeded("history completion envelope"))?;
        Ok(Self { _charge: charge })
    }
}

/// Complete bounded preparation for one accepted Resume. The private branch can retain both
/// its original and refreshed Snapshot; public/legacy preparation does not reserve that credit.
/// Activation and an immediate pause are sequential and borrow the same mutation credit.
pub(crate) struct ResumeAdmission {
    _scratch: BufferCharge,
    inspect: Option<AdmissionCharge>,
    mutation: AdmissionCharge,
    followup: Option<AdmissionCharge>,
}

impl ResumeAdmission {
    pub(crate) fn reserve(job: &Job, scratch: usize, private: bool) -> Result<Self> {
        let peak = STATE_WORK
            .checked_mul(if private { 3 } else { 2 })
            .and_then(|state| scratch.checked_add(state))
            .ok_or(Error::SizeLimitExceeded(
                "history resume preparation envelope",
            ))?;
        let mut combined = charge(job, peak)?;
        let inspect = AdmissionCharge::split_from(&mut combined)?;
        let mutation = AdmissionCharge::split_from(&mut combined)?;
        let followup = private
            .then(|| AdmissionCharge::split_from(&mut combined))
            .transpose()?;
        Ok(Self {
            _scratch: combined,
            inspect: Some(inspect),
            mutation,
            followup,
        })
    }

    pub(crate) fn inspect(&mut self, context: &Context) -> Result<Option<Snapshot>> {
        let credit = self
            .inspect
            .take()
            .ok_or_else(|| invalid("history resume inspection credit"))?;
        inspect_precharged(context, credit)
    }

    pub(crate) fn mutation(&self) -> &AdmissionCharge {
        &self.mutation
    }

    pub(crate) fn take_followup(&mut self) -> Result<AdmissionCharge> {
        self.followup
            .take()
            .ok_or_else(|| invalid("history resume follow-up credit"))
    }

    pub(crate) fn is_private(&self) -> bool {
        self.followup.is_some()
    }
}

/// Complete memory admission for one local Status or Cancel. The actor obtains this before it
/// accepts the action; the worker then consumes these exact credits without another reservation.
pub(crate) struct LocalAdmission {
    inspect: AdmissionCharge,
    mutation: Option<AdmissionCharge>,
}

impl LocalAdmission {
    pub(crate) fn status(job: &Job) -> Result<Self> {
        Ok(Self {
            inspect: AdmissionCharge::reserve(job)?,
            mutation: None,
        })
    }

    pub(crate) fn cancel(job: &Job) -> Result<Self> {
        let peak = STATE_WORK
            .checked_mul(2)
            .ok_or(Error::SizeLimitExceeded("local history operation envelope"))?;
        let mut combined = charge(job, peak)?;
        let inspect = AdmissionCharge::split_from(&mut combined)?;
        Ok(Self {
            inspect,
            mutation: Some(AdmissionCharge { _charge: combined }),
        })
    }

    pub(crate) fn inspect(
        self,
        context: &Context,
    ) -> Result<(Option<Snapshot>, Option<AdmissionCharge>)> {
        let snapshot = inspect_precharged(context, self.inspect)?;
        Ok((snapshot, self.mutation))
    }
}

fn key(context: &Context) -> Result<&Sek> {
    context.check()?;
    Ok(&context.key)
}
fn scope(context: &Context) -> Digest32 {
    context.scope
}
fn node_scope(node: Digest32, slot: Slot) -> Digest32 {
    let mut bytes = b"vox/history-demand-scope/v1".to_vec();
    bytes.extend_from_slice(&node);
    bytes.push(match slot {
        Slot::Archive => 0,
        Slot::Live => 1,
        Slot::Control => 2,
        Slot::OwnRecovery => 3,
    });
    sha256(&bytes)
}

fn own_recovery_scope(node: Digest32, room: Digest32) -> Digest32 {
    let mut bytes = b"vox/history-demand-own-recovery-scope/v1".to_vec();
    bytes.extend_from_slice(&node);
    bytes.extend_from_slice(&room);
    sha256(&bytes)
}

/// Room retirement deletes derived staging in the same lifecycle transaction.
pub(crate) fn purge_own_recovery_in(
    batch: &mut Batch<'_>,
    node: Digest32,
    room: Digest32,
) -> Result<()> {
    batch.purge_channel(&own_recovery_scope(node, room))?;
    Ok(())
}

type RetainedLegacyOwner = (Digest32, RequestId, [u8; 16], Digest32);

/// The exact paused legacy owner retained in the one archive slot, if there is one.
/// Reopen uses this bounded header read before touching provisional room roots. It does not
/// create an active handle or authorize network work; an explicit Resume is still required.
pub(crate) fn retained_legacy_owner(profile: &Profile) -> Result<Option<RetainedLegacyOwner>> {
    let key = crate::atrest::seal::sek(profile.signer()?, b"vox/history-demand-sek/v1")?;
    let scope = node_scope(profile.fingerprint(), Slot::Archive);
    let Some(segment) =
        profile
            .store()
            .snapshot()?
            .get_segment_bounded(&scope, KIND, HEADER, STATE_BYTES)?
    else {
        return Ok(None);
    };
    let state = match decode(&key, &scope, &segment) {
        Ok(state) => state,
        Err(
            Error::MalformedAtRest(_) | Error::AtRestUnlockFailed | Error::SizeLimitExceeded(_),
        ) => {
            return Ok(None);
        }
        Err(error) => return Err(error),
    };
    let Some(plan) = state.legacy else {
        return Ok(None);
    };
    Ok(
        (!state.progress.terminal() && state.cleanup.is_none()).then_some((
            state.binding.room,
            state.request,
            state.binding.instance,
            plan.author,
        )),
    )
}
fn decode(
    key: &Sek,
    scope: &Digest32,
    segment: &crate::atrest::store::SealedSegment,
) -> Result<State> {
    if segment.ciphertext.len() > STATE_BYTES + 16 {
        return Err(bad());
    }
    let bytes = open_segment(key, KIND, HEADER, segment)?;
    let (version, bound, mut state): (u8, Digest32, State) =
        serde_json::from_slice(&bytes).map_err(|_| bad())?;
    if version != 1 || bound != *scope {
        return Err(bad());
    }
    state.scope = *scope;
    state.validate()?;
    Ok(state)
}
fn load(batch: &Batch<'_>, key: &Sek, scope: &Digest32) -> Result<Option<State>> {
    batch
        .get_segment_bounded(scope, KIND, HEADER, STATE_BYTES)?
        .map(|s| decode(key, scope, &s))
        .transpose()
}
fn put(batch: &mut Batch<'_>, key: &Sek, scope: &Digest32, state: &State) -> Result<()> {
    state.validate()?;
    let bytes = Zeroizing::new(serde_json::to_vec(&(1u8, scope, state)).map_err(|_| bad())?);
    if bytes.len() > STATE_BYTES {
        return Err(bad());
    }
    batch.put_segment(
        scope,
        KIND,
        HEADER,
        &seal_segment(key, KIND, HEADER, &bytes)?,
    )
}
fn live(
    batch: &Batch<'_>,
    key: &Sek,
    scope: &Digest32,
    context: &Context,
    active: &Active,
) -> Result<State> {
    let state = load(batch, key, scope)?.ok_or_else(|| invalid("no history demand"))?;
    if active.node != context.fingerprint() || !active.matches(&state) {
        return Err(invalid("history demand is paused, cancelled or replaced"));
    }
    authorize_in(batch, context, state.binding)?;
    Ok(state)
}
fn authorize_in(batch: &Batch<'_>, context: &Context, binding: Binding) -> Result<()> {
    let current = super::history_stream::authorization_generation_in(
        batch,
        context.node,
        binding.room,
        binding.instance,
        binding.epoch,
    )?;
    if current != binding.grant {
        return Err(invalid("history demand authorization changed"));
    }
    Ok(())
}
fn commit_context(batch: Batch<'_>, context: &Context) -> Result<()> {
    context.check()?;
    batch.commit()?;
    context.check()
}
fn commit(batch: Batch<'_>, active: &mut Active, context: &Context) -> Result<()> {
    let result = commit_context(batch, context);
    if result.is_err() {
        active.valid = false;
    }
    result
}
fn next_serial(serial: u64) -> Result<u64> {
    serial
        .checked_add(1)
        .ok_or_else(|| invalid("history demand serial exhausted"))
}

/// Local status/cache inspection only; does not create an Active handle or request peer work.
pub fn inspect(context: &Context, job: &Job) -> Result<Option<Snapshot>> {
    inspect_precharged(context, AdmissionCharge::reserve(job)?)
}

pub(crate) fn inspect_precharged(
    context: &Context,
    admission: AdmissionCharge,
) -> Result<Option<Snapshot>> {
    let charge = admission._charge;
    let key = key(context)?;
    let scope = scope(context);
    context
        .store()
        .snapshot()?
        .get_segment_bounded(&scope, KIND, HEADER, STATE_BYTES)?
        .map(|segment| {
            Ok(Snapshot {
                state: decode(key, &scope, &segment)?,
                _charge: charge,
            })
        })
        .transpose()
}

/// Start only after an explicit local request and current authorization. No abandoned namespaces.
pub fn start(
    context: &Context,
    request: RequestId,
    binding: Binding,
    bounds: Bounds,
    job: &Job,
) -> Result<Active> {
    start_plan(context, request, binding, bounds, None, None, job)
}

pub(crate) fn start_private(
    context: &Context,
    request: RequestId,
    binding: Binding,
    bounds: Bounds,
    plan: PrivatePlan,
    job: &Job,
) -> Result<Active> {
    bounds.validate()?;
    plan.validate(bounds)?;
    start_plan(context, request, binding, bounds, Some(plan), None, job)
}

pub(crate) fn start_legacy(
    context: &Context,
    request: RequestId,
    binding: Binding,
    bounds: Bounds,
    plan: LegacyPlan,
    job: &Job,
) -> Result<Active> {
    bounds.validate()?;
    plan.validate(bounds)?;
    if context.slot != Slot::Archive {
        return Err(invalid("legacy recovery requires explicit archive demand"));
    }
    start_plan(context, request, binding, bounds, None, Some(plan), job)
}
fn start_plan(
    context: &Context,
    request: RequestId,
    binding: Binding,
    bounds: Bounds,
    private: Option<PrivatePlan>,
    legacy: Option<LegacyPlan>,
    job: &Job,
) -> Result<Active> {
    let _charge = charge(job, STATE_WORK)?;
    bounds.validate()?;
    let key = key(context)?;
    let scope = scope(context);
    let mut batch = context.store().batch()?;
    authorize_in(&batch, context, binding)?;
    let serial = match load(&batch, key, &scope)? {
        Some(previous) => {
            if !previous.progress.terminal() || previous.cleanup.is_some() {
                return Err(invalid(
                    "history demand already exists; resume it or cancel and reclaim it",
                ));
            }
            if previous.request == request {
                return Err(invalid("history request ID must be fresh"));
            }
            next_serial(previous.serial)?
        }
        None => 1,
    };
    let state = State {
        scope,
        request,
        binding,
        bounds,
        remaining: legacy.map_or(Ok(bounds.entries), |plan| {
            usize::try_from(plan.through - plan.expected_base).map_err(|_| bad())
        })?,
        body: None,
        cursor: None,
        private,
        legacy,
        progress: Progress::Pending,
        serial,
        cleanup: None,
    };
    put(&mut batch, key, &scope, &state)?;
    commit_context(batch, context)?;
    Ok(Active {
        node: context.fingerprint(),
        scope,
        request,
        serial,
        valid: true,
        binding,
        cancellation: context.cancellation(),
    })
}

/// The caller prepaid this mutation and supplies freshly rechecked authority. Bounds and
/// remaining count come only from disk. Precommit authorization/cancellation checks remain;
/// postcommit observer cancellation cannot replace a successful activation with failure.
pub(crate) fn resume_precharged(
    context: &Context,
    request: RequestId,
    binding: Binding,
    _admission: &AdmissionCharge,
) -> Result<Active> {
    let key = key(context)?;
    let scope = scope(context);
    let mut batch = context.store().batch()?;
    authorize_in(&batch, context, binding)?;
    let mut state = load(&batch, key, &scope)?.ok_or_else(|| invalid("no history demand"))?;
    if state.request != request || state.binding != binding || state.progress.terminal() {
        return Err(invalid(
            "history demand authority changed or operation ended",
        ));
    }
    if state.cleanup.is_some() {
        return Err(invalid("history staging reclamation is pending"));
    }
    state.serial = next_serial(state.serial)?;
    state.progress = Progress::Pending;
    put(&mut batch, key, &scope, &state)?;
    // A successful activation is a durable fact even if observer cancellation arrives just
    // after commit. Dispatch still requires the actor's fresh authority/lifecycle checks.
    context.check()?;
    batch.commit()?;
    Ok(Active {
        node: context.fingerprint(),
        scope,
        request,
        serial: state.serial,
        valid: true,
        binding,
        cancellation: context.cancellation(),
    })
}

/// Identity only: retaining this token does not retain the old Context, its key, or its
/// secret-work lease. The caller may capture it only from the exact returned Flow it owns.
#[derive(Clone, Copy)]
pub(crate) struct RetiredPublicToken {
    node: Digest32,
    scope: Digest32,
    request: RequestId,
    serial: u64,
    binding: Binding,
    pub(crate) wire_bytes: u64,
    pub(crate) counted_body: Option<Digest32>,
}
impl RetiredPublicToken {
    pub(crate) fn matches_state(&self, context: &Context, state: &State, binding: Binding) -> bool {
        self.node == context.fingerprint()
            && self.scope == scope(context)
            && self.request == state.request
            && self.serial == state.serial
            && self.binding == binding
            && state.binding == binding
            && state.private.is_none()
            && state.legacy.is_none()
            && binding.audience == [0; 32]
    }
}
impl Active {
    pub(crate) fn retired_public_token(&self) -> RetiredPublicToken {
        RetiredPublicToken {
            node: self.node,
            scope: self.scope,
            request: self.request,
            serial: self.serial,
            binding: self.binding,
            wire_bytes: 0,
            counted_body: None,
        }
    }
}

/// Result of observing a retired automatic quantum at the activation boundary.
pub(crate) enum InterruptedActivation {
    /// The exact interrupted Pending quantum has been reactivated.
    Resumed(Active),
    /// A different durable outcome won; it must be shown without starting another quantum.
    Finished {
        progress: Progress,
        remaining: usize,
        offset: u64,
        reclaiming: bool,
    },
}

/// Reacquire only the interrupted public Pending quantum. Unlike an explicit Resume, this
/// cannot turn a committed More or Paused state into another user's unrequested quantum.
/// Caller owns the exact retired Flow and must fence its room/request lifecycle separately.
pub(crate) fn resume_interrupted_pending_precharged(
    context: &Context,
    request: RequestId,
    binding: Binding,
    retired: &RetiredPublicToken,
    _admission: &AdmissionCharge,
) -> Result<InterruptedActivation> {
    let key = key(context)?;
    let scope = scope(context);
    let mut batch = context.store().batch()?;
    authorize_in(&batch, context, binding)?;
    let mut state = load(&batch, key, &scope)?.ok_or_else(|| invalid("no history demand"))?;
    if state.request != request
        || state.binding != binding
        || retired.node != context.fingerprint()
        || retired.scope != scope
        || retired.request != request
        || retired.binding != binding
        || retired.serial != state.serial
        || state.private.is_some()
        || state.legacy.is_some()
        || binding.audience != [0; 32]
    {
        return Err(invalid("interrupted history owner changed"));
    }
    context.check()?;
    if state.progress != Progress::Pending || state.cleanup.is_some() {
        return Ok(InterruptedActivation::Finished {
            progress: state.progress,
            remaining: state.remaining,
            offset: state.body.as_ref().map_or_else(
                || state.cursor.map_or(0, |cursor| cursor.offset),
                |body| body.offset,
            ),
            reclaiming: state.reclaiming(),
        });
    }
    state.serial = next_serial(state.serial)?;
    put(&mut batch, key, &scope, &state)?;
    context.check()?;
    batch.commit()?;
    Ok(InterruptedActivation::Resumed(Active {
        node: context.fingerprint(),
        scope,
        request,
        serial: state.serial,
        valid: true,
        binding,
        cancellation: context.cancellation(),
    }))
}

/// Reconstruct deletion ownership after a crash, never a live admission capability.
pub(crate) fn own_recovery_cleanup(context: &Context, state: &State) -> Result<Active> {
    if context.slot != Slot::OwnRecovery || state.scope != context.scope {
        return Err(invalid("own recovery cleanup binding"));
    }
    Ok(Active {
        node: context.node,
        scope: context.scope,
        request: state.request,
        serial: state.serial,
        valid: false,
        binding: state.binding,
        cancellation: context.cancellation(),
    })
}

/// Automatic recovery rechecks current authority in this Batch while preserving its original
/// signed interval and body cursor. A trust nonce change is not permission to replace the page.
pub(crate) fn resume_own_recovery(
    context: &Context,
    request: RequestId,
    binding: Binding,
    job: &Job,
) -> Result<Active> {
    if context.slot != Slot::OwnRecovery {
        return Err(invalid("own recovery context required"));
    }
    let _charge = charge(job, STATE_WORK)?;
    let key = key(context)?;
    let scope = scope(context);
    let mut batch = context.store().batch()?;
    authorize_in(&batch, context, binding)?;
    let mut state = load(&batch, key, &scope)?.ok_or_else(|| invalid("no own recovery"))?;
    if state.request != request
        || state.binding.room != binding.room
        || state.binding.instance != binding.instance
        || state.binding.epoch != binding.epoch
        || state.binding.audience != binding.audience
        || state.progress.terminal()
        || state.cleanup.is_some()
    {
        return Err(invalid("own recovery lifetime changed"));
    }
    state.binding = binding;
    state.serial = next_serial(state.serial)?;
    state.progress = Progress::Pending;
    put(&mut batch, key, &scope, &state)?;
    context.check()?;
    batch.commit()?;
    Ok(Active {
        node: context.node,
        scope,
        request,
        serial: state.serial,
        valid: true,
        binding,
        cancellation: context.cancellation(),
    })
}

/// Record one authenticated exact-request header before provisional body bytes. Repetition
/// consumes no count. Full inclusion/control/governance may still be pending; no entry or effect
/// is admitted until entry_admitted runs in the final verified canonical-publication transaction.
#[allow(clippy::too_many_arguments)] // One exact authenticated header/body binding.
pub fn begin_body(
    context: &Context,
    active: &mut Active,
    entry: Digest32,
    seq: u64,
    length: u64,
    header: &[u8],
    job: &Job,
) -> Result<()> {
    let _charge = charge(job, STATE_WORK)?;
    if length > MAX_PAYLOAD_BYTES as u64 || header.is_empty() || header.len() > MAX_HEADER_BYTES {
        return Err(invalid("history body/header bounds"));
    }
    let key = key(context)?;
    let scope = scope(context);
    let mut batch = context.store().batch()?;
    let mut state = live(&batch, key, &scope, context, active)?;
    if let Some(body) = &state.body {
        return if body.entry == entry
            && body.seq == seq
            && body.length == length
            && body.header == header
        {
            Ok(())
        } else {
            Err(invalid("another history body is unfinished"))
        };
    }
    if state.cleanup.is_some()
        || state.remaining == 0
        || seq < state.bounds.lo
        || seq > state.bounds.hi
    {
        return Err(invalid(
            "history header exceeds original demand or reclamation is pending",
        ));
    }
    state.remaining -= 1;
    state.body = Some(Body {
        entry,
        seq,
        length,
        offset: 0,
        header: header.to_vec(),
    });
    state.cursor = None;
    put(&mut batch, key, &scope, &state)?;
    commit(batch, active, context)
}

fn page_prefix(scope: &Digest32, request: &RequestId, entry: &Digest32, page: u64) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(PAGE_PREFIX);
    bytes.push(1);
    bytes.extend_from_slice(scope);
    bytes.extend_from_slice(request);
    bytes.extend_from_slice(entry);
    bytes.extend_from_slice(&page.to_be_bytes());
    bytes
}
fn open_page(
    key: &Sek,
    scope: &Digest32,
    request: &RequestId,
    entry: &Digest32,
    page: u64,
    segment: &crate::atrest::store::SealedSegment,
    expected: usize,
) -> Result<Zeroizing<Vec<u8>>> {
    if page == 0 || page > PAGE_COUNT || segment.ciphertext.len() > PAGE_PREFIX + PAGE_BYTES + 16 {
        return Err(bad());
    }
    let bytes = open_segment(key, KIND, page, segment)?;
    if bytes.len() != PAGE_PREFIX + expected
        || bytes[..PAGE_PREFIX] != page_prefix(scope, request, entry, page)
    {
        return Err(bad());
    }
    Ok(bytes)
}
fn held_in_page(offset: u64, page: u64) -> usize {
    offset
        .saturating_sub((page - 1) * PAGE_BYTES as u64)
        .min(PAGE_BYTES as u64) as usize
}

/// Commit at most two coalesced storage pages plus the exact offset before returning ACK credit.
/// A duplicate chunk is idempotent only when every byte matches; its end was already persisted.
/// Return the persisted offset and completion from this same checked state, without a second read.
pub fn append(
    context: &Context,
    active: &mut Active,
    entry: Digest32,
    offset: u64,
    bytes: &[u8],
    job: &Job,
) -> Result<(u64, bool)> {
    let _charge = charge(job, STATE_WORK + 2 * PAGE_WORK)?;
    if bytes.is_empty() || bytes.len() > MAX_CHUNK_BYTES {
        return Err(invalid("history chunk bounds"));
    }
    let end = offset
        .checked_add(bytes.len() as u64)
        .ok_or_else(|| invalid("history chunk offset"))?;
    let key = key(context)?;
    let scope = scope(context);
    let mut batch = context.store().batch()?;
    let mut state = live(&batch, key, &scope, context, active)?;
    let body = state
        .body
        .as_mut()
        .ok_or_else(|| invalid("history body header is missing"))?;
    if body.entry != entry
        || end > body.length
        || offset > body.offset
        || (offset < body.offset && end > body.offset)
    {
        return Err(invalid("history chunk request/hash/offset mismatch"));
    }
    let duplicate = offset < body.offset;
    let mut consumed = 0;
    while consumed < bytes.len() {
        let at = offset + consumed as u64;
        let page = at / PAGE_BYTES as u64 + 1;
        let within = (at % PAGE_BYTES as u64) as usize;
        let count = (bytes.len() - consumed).min(PAGE_BYTES - within);
        let held = held_in_page(body.offset, page);
        let mut data =
            match batch.get_segment_bounded(&scope, KIND, page, PAGE_PREFIX + PAGE_BYTES)? {
                Some(segment) => {
                    open_page(key, &scope, &state.request, &entry, page, &segment, held)?
                }
                None if held == 0 => {
                    Zeroizing::new(page_prefix(&scope, &state.request, &entry, page))
                }
                None => return Err(bad()),
            };
        if duplicate {
            if data.get(PAGE_PREFIX + within..PAGE_PREFIX + within + count)
                != Some(&bytes[consumed..consumed + count])
            {
                return Err(invalid("duplicate history chunk has different bytes"));
            }
        } else {
            if data.len() != PAGE_PREFIX + within {
                return Err(bad());
            }
            data.extend_from_slice(&bytes[consumed..consumed + count]);
            let segment = seal_segment(key, KIND, page, &data)?;
            batch.put_segment(&scope, KIND, page, &segment)?;
        }
        consumed += count;
    }
    if duplicate {
        context.check()?;
        return Ok((end, body.offset == body.length));
    }
    body.offset = end;
    let complete = body.offset == body.length;
    state.cursor = None;
    put(&mut batch, key, &scope, &state)?;
    commit(batch, active, context)?;
    Ok((end, complete))
}

fn read_bound(
    snapshot: &StoreSnapshot,
    key: &Sek,
    scope: &Digest32,
    context: &Context,
    active: &Active,
) -> Result<State> {
    let segment = snapshot
        .get_segment_bounded(scope, KIND, HEADER, STATE_BYTES)?
        .ok_or_else(|| invalid("no history demand"))?;
    let state = decode(key, scope, &segment)?;
    if active.node != context.fingerprint() || !active.matches(&state) {
        return Err(invalid("history demand is paused, cancelled or replaced"));
    }
    Ok(state)
}

/// Read a single bounded page into a charged buffer. Assembly requires a separate full-body charge.
pub fn read_page(context: &Context, active: &Active, page: u64, job: &Job) -> Result<Page> {
    let charge = charge(job, STATE_WORK + PAGE_WORK)?;
    if page == 0 || page > PAGE_COUNT {
        return Err(invalid("history staging page"));
    }
    let key = key(context)?;
    let scope = scope(context);
    let snapshot = context.store().snapshot()?;
    let state = read_bound(&snapshot, key, &scope, context, active)?;
    let body = state
        .body
        .as_ref()
        .ok_or_else(|| invalid("no history body"))?;
    let held = held_in_page(body.offset, page);
    if held == 0 {
        return Err(invalid("history page is not persisted"));
    }
    let segment = snapshot
        .get_segment_bounded(&scope, KIND, page, PAGE_PREFIX + PAGE_BYTES)?
        .ok_or_else(bad)?;
    let bytes = open_page(
        key,
        &scope,
        &state.request,
        &body.entry,
        page,
        &segment,
        held,
    )?;
    context.check()?;
    Ok(Page {
        bytes,
        _charge: charge,
    })
}

fn schedule_cleanup(state: &mut State) {
    let pages = state
        .body
        .take()
        .map_or(0, |body| body.offset.div_ceil(PAGE_BYTES as u64));
    if pages != 0 {
        state.cleanup = Some(Cleanup {
            next: 1,
            last: pages,
        });
    }
    state.cursor = None;
}

/// Call only after complete hash/signature/governance admission, in that SAME accepted-entry Batch.
/// This adds one row, so the caller must reserve one row in its <=64-row publication slice.
/// Commit failure must poison the enclosing admission; no ACK/progress is claimed on that failure.
pub(crate) fn entry_admitted(
    batch: &mut Batch<'_>,
    context: &Context,
    active: &Active,
    entry: Digest32,
    _admission: &AdmissionCharge,
) -> Result<()> {
    let key = key(context)?;
    let scope = scope(context);
    let mut state = live(batch, key, &scope, context, active)?;
    if !state
        .body
        .as_ref()
        .is_some_and(|b| b.entry == entry && b.offset == b.length)
    {
        return Err(invalid("history entry is incomplete or changed"));
    }
    let admitted_seq = state.body.as_ref().ok_or_else(bad)?.seq;
    schedule_cleanup(&mut state);
    // The admitted body and its cursor disappear together. Preserve the next exact
    // position in the same transaction, so retirement or a restart cannot replay
    // the original upper bound after publication.
    if context.slot == Slot::Archive
        && state.private.is_none()
        && state.legacy.is_none()
        && state.binding.audience == [0; 32]
        && state.remaining > 0
    {
        if let Some(next_seq) = admitted_seq
            .checked_sub(1)
            .filter(|next| *next >= state.bounds.lo)
        {
            state.cursor = Some(Cursor {
                query_kind: 4,
                next_seq,
                entry: None,
                offset: 0,
            });
        } else {
            // The authenticated lower bound was admitted; unused entry credit is
            // not evidence that another entry exists outside this interval.
            state.remaining = 0;
        }
    }
    put(batch, key, &scope, &state)
}

/// Commit one bodyless, authenticated entry that is complete for this node's recipient role.
/// The caller invokes this only from the exact entry's semantic-effect transaction, after its
/// inclusion proof and typed dispatch have succeeded. Unlike body staging, this both advances
/// the archive count and moves the cursor below the role-only header atomically.
pub(crate) fn role_header_admitted(
    batch: &mut Batch<'_>,
    context: &Context,
    active: &Active,
    seq: u64,
    _admission: &AdmissionCharge,
) -> Result<()> {
    let key = key(context)?;
    let scope = scope(context);
    let mut state = load(batch, key, &scope)?.ok_or_else(|| invalid("no history demand"))?;
    // The same settled semantic effect can be handed back after the callback that completed
    // this request: bounded contiguous feed restoration continues independently and asks the
    // effect step to finish once more. Match the exact activation and authorize it before the
    // terminal idempotence check; `Active::matches` intentionally rejects terminal work.
    if active.node != context.fingerprint()
        || !active.valid
        || active.cancellation.is_cancelled()
        || active.scope != state.scope
        || active.request != state.request
        || active.serial != state.serial
        || active.binding != state.binding
    {
        return Err(invalid("history demand is paused, cancelled or replaced"));
    }
    authorize_in(batch, context, state.binding)?;
    if seq < state.bounds.lo || seq > state.bounds.hi {
        return Err(invalid("role-complete history header exceeds demand"));
    }
    let next = seq.checked_sub(1).filter(|next| *next >= state.bounds.lo);
    let already_admitted = state.body.is_none()
        && state.cleanup.is_none()
        && ((state.progress == Progress::Complete && state.remaining == 0)
            || state.cursor.is_some_and(|cursor| {
                cursor.query_kind == 4
                    && next == Some(cursor.next_seq)
                    && cursor.entry.is_none()
                    && cursor.offset == 0
            }));
    if already_admitted {
        return Ok(());
    }
    if !active.matches(&state) {
        return Err(invalid("history demand is paused, cancelled or replaced"));
    }
    if state.body.is_some()
        || state.cleanup.is_some()
        || state.remaining == 0
        || seq < state.bounds.lo
        || seq > state.bounds.hi
        || state.progress != Progress::More
        || !state.cursor.is_some_and(|cursor| {
            cursor.query_kind == 4
                && cursor.next_seq == seq
                && cursor.entry.is_none()
                && cursor.offset == 0
        })
    {
        return Err(invalid("role-complete history header changed"));
    }
    state.remaining -= 1;
    if state.remaining == 0 {
        state.cursor = None;
        state.progress = Progress::Complete;
    } else if let Some(next) = next {
        let cursor = state
            .cursor
            .as_mut()
            .ok_or_else(|| invalid("role-complete history cursor vanished"))?;
        cursor.next_seq = next;
    } else {
        return Err(invalid("role-complete lower bound left remaining entries"));
    }
    put(batch, key, &scope, &state)
}

/// Persist a locally normalized cursor within the original authorization and actual credit.
/// An Entry quantum's [seq,seq] wire bounds must first be rebound to the original local page;
/// never treat the peer's narrower quantum, new query kind or count as fresh authorization.
pub fn checkpoint(
    context: &Context,
    active: &mut Active,
    progress: Progress,
    cursor: Option<&Continuation>,
    job: &Job,
) -> Result<()> {
    let charge = AdmissionCharge::reserve(job)?;
    checkpoint_precharged(context, active, progress, cursor, &charge)
}

pub(crate) fn checkpoint_precharged(
    context: &Context,
    active: &mut Active,
    progress: Progress,
    cursor: Option<&Continuation>,
    _charge: &AdmissionCharge,
) -> Result<()> {
    if matches!(progress, Progress::Cancelled | Progress::Paused) {
        return Err(invalid("use explicit history cancel/pause"));
    }
    if progress == Progress::More && cursor.is_none() {
        return Err(invalid("history More requires a bounded continuation"));
    }
    let key = key(context)?;
    let scope = scope(context);
    let mut batch = context.store().batch()?;
    let mut state = live(&batch, key, &scope, context, active)?;
    if progress == Progress::Complete
        && (state.body.is_some()
            || state.cleanup.is_some()
            || cursor.is_some()
            || state.remaining != 0)
    {
        return Err(invalid("history demand still has unfinished work"));
    }
    let next_cursor = if let Some(cursor) = cursor {
        if cursor.head != state.bounds.head
            || cursor.lo != state.bounds.lo
            || cursor.hi != state.bounds.hi
            || cursor.next_seq < state.bounds.lo
            || cursor.next_seq > state.bounds.hi
            || cursor.entries_remaining != state.remaining
            || cursor.query_kind > 4
            || match &state.body {
                Some(body) => {
                    cursor.entry != Some(body.entry)
                        || cursor.offset != body.offset
                        || cursor.next_seq != body.seq
                }
                None => cursor.entry.is_some() || cursor.offset != 0,
            }
        {
            return Err(invalid("history continuation exceeds persisted demand"));
        }
        Some(Cursor {
            query_kind: cursor.query_kind,
            next_seq: cursor.next_seq,
            entry: cursor.entry,
            offset: cursor.offset,
        })
    } else {
        None
    };
    if state.progress == progress && state.cursor == next_cursor {
        // Exact Active, current authority and all cursor/credit invariants were checked in
        // this serialized batch. An identical checkpoint has no durable work to commit.
        let result = context.check();
        if result.is_err() {
            active.valid = false;
        }
        return result;
    }
    state.cursor = next_cursor;
    state.progress = progress;
    put(&mut batch, key, &scope, &state)?;
    commit(batch, active, context)?;
    if progress.terminal() {
        active.valid = false;
    }
    Ok(())
}

/// Effects are committed before this acknowledgement. Repeated body admission is idempotent;
/// a crash before this commit retries the same exact positions rather than skipping them.
#[allow(clippy::too_many_arguments)]
pub(crate) fn checkpoint_private(
    context: &Context,
    active: &mut Active,
    expected: &PrivatePlan,
    next: PrivatePlan,
    remaining: usize,
    progress: Progress,
    job: &Job,
) -> Result<()> {
    let _charge = charge(job, STATE_WORK)?;
    let key = key(context)?;
    let scope = scope(context);
    let mut batch = context.store().batch()?;
    let mut state = live(&batch, key, &scope, context, active)?;
    next.validate(state.bounds)?;
    if state.private.as_ref() != Some(expected)
        || next.donor != expected.donor
        || next.grant != expected.grant
        || remaining > state.remaining
        || !matches!(
            progress,
            Progress::More | Progress::Complete | Progress::Unavailable
        )
        || (progress == Progress::Complete && (!next.inventory_done || !next.positions.is_empty()))
    {
        return Err(invalid("private history checkpoint binding"));
    }
    state.private = Some(next);
    state.remaining = remaining;
    state.progress = progress;
    put(&mut batch, key, &scope, &state)?;
    commit(batch, active, context)?;
    if progress.terminal() {
        active.valid = false;
    }
    Ok(())
}

/// A legacy worker acknowledges only already-durable accepted prefix progress. Unsigned
/// staging and building never decrease remaining; signed publication does. Each explicit
/// quantum has its separate fixed bounds.entries cap, without resetting the original count.
pub(crate) fn checkpoint_legacy(
    context: &Context,
    active: &mut Active,
    expected: &LegacyPlan,
    remaining: usize,
    progress: Progress,
    job: &Job,
) -> Result<()> {
    let _charge = charge(job, STATE_WORK)?;
    let key = key(context)?;
    let scope = scope(context);
    let mut batch = context.store().batch()?;
    let mut state = live(&batch, key, &scope, context, active)?;
    if state.legacy.as_ref() != Some(expected)
        || remaining > state.remaining
        || (progress == Progress::Complete && remaining != 0)
        || !matches!(
            progress,
            Progress::More | Progress::Complete | Progress::Unavailable
        )
    {
        return Err(invalid("legacy history checkpoint binding"));
    }
    state.remaining = remaining;
    state.progress = progress;
    put(&mut batch, key, &scope, &state)?;
    commit(batch, active, context)?;
    if progress.terminal() {
        active.valid = false;
    }
    Ok(())
}

pub(crate) fn pause_precharged(
    context: &Context,
    active: &mut Active,
    _charge: &AdmissionCharge,
) -> Result<()> {
    let key = key(context)?;
    let scope = scope(context);
    let mut batch = context.store().batch()?;
    let mut state = live(&batch, key, &scope, context, active)?;
    state.serial = next_serial(state.serial)?;
    state.progress = Progress::Paused;
    put(&mut batch, key, &scope, &state)?;
    commit(batch, active, context)?;
    active.valid = false;
    Ok(())
}

/// First fence demand atomically; bounded reclamation is separate and never starts peer traffic.
pub fn cancel(context: &Context, request: RequestId, job: &Job) -> Result<()> {
    let charge = AdmissionCharge::reserve(job)?;
    cancel_precharged(context, request, &charge)
}

/// Cancel using an already-accounted state workspace; no allocation admission occurs here.
pub(crate) fn cancel_precharged(
    context: &Context,
    request: RequestId,
    _charge: &AdmissionCharge,
) -> Result<()> {
    let key = key(context)?;
    let scope = scope(context);
    let mut batch = context.store().batch()?;
    let mut state = load(&batch, key, &scope)?.ok_or_else(|| invalid("no history demand"))?;
    if state.request != request {
        return Err(invalid("history request ID changed"));
    }
    if state.progress.terminal() {
        return Ok(());
    }
    state.serial = next_serial(state.serial)?;
    state.progress = Progress::Cancelled;
    schedule_cleanup(&mut state);
    put(&mut batch, key, &scope, &state)?;
    commit_context(batch, context)
}

/// Commit the exact local cancellation and return capability-bound cleanup ownership. Lifecycle
/// cancellation immediately before commit still refuses; cancellation observed after a successful
/// commit cannot change the durable outcome into an error.
pub(crate) fn cancel_owned_precharged(
    context: &Context,
    request: RequestId,
    _charge: &AdmissionCharge,
) -> Result<LocalCancelOutcome> {
    let key = key(context)?;
    let scope = scope(context);
    let mut batch = context.store().batch()?;
    let mut state = load(&batch, key, &scope)?.ok_or_else(|| invalid("no history demand"))?;
    if state.request != request {
        return Err(invalid("history request ID changed"));
    }
    let binding = state.binding;
    let committed = || CommittedCancel {
        node: context.node,
        scope,
        request,
        binding,
    };
    match state.progress {
        Progress::Cancelled => {
            return Ok(LocalCancelOutcome::AlreadyCancelled(Box::new(committed())));
        }
        Progress::Complete => return Ok(LocalCancelOutcome::AlreadyComplete),
        _ => {}
    }
    state.serial = next_serial(state.serial)?;
    state.progress = Progress::Cancelled;
    schedule_cleanup(&mut state);
    put(&mut batch, key, &scope, &state)?;
    // Preserve the lifecycle fence until the commit's linearization point. A later observation
    // cannot truthfully deny the committed result.
    context.check()?;
    batch.commit()?;
    Ok(LocalCancelOutcome::NewlyCancelled(Box::new(committed())))
}

/// Reclaim one bounded slice owned by an exact durable Cancelled capability. The retained Context
/// keeps the key and secret-work lease alive, but postcommit lifecycle cancellation cannot revoke
/// deletion of this exact request. Missing or replaced state is never recreated.
pub(crate) fn reclaim_committed(
    context: &Context,
    committed: &CommittedCancel,
    _charge: &AdmissionCharge,
) -> Result<CommittedReclaim> {
    if context.node != committed.node || context.scope != committed.scope {
        return Err(invalid("history cancellation owner changed"));
    }
    let key = &context.key;
    let mut batch = context.store().batch()?;
    let Some(mut state) = load(&batch, key, &committed.scope)? else {
        return Ok(CommittedReclaim::Superseded);
    };
    if state.request != committed.request
        || state.binding != committed.binding
        || state.progress != Progress::Cancelled
    {
        return Ok(CommittedReclaim::Superseded);
    }
    let Some(mut cleanup) = state.cleanup else {
        return Ok(CommittedReclaim::Complete);
    };
    let end = cleanup.last.min(cleanup.next + RECLAIM_ROWS - 1);
    for page in cleanup.next..=end {
        batch.delete_segment(&committed.scope, KIND, page)?;
    }
    cleanup.next = end + 1;
    state.cleanup = (cleanup.next <= cleanup.last).then_some(cleanup);
    put(&mut batch, key, &committed.scope, &state)?;
    batch.commit()?;
    Ok(if state.cleanup.is_none() {
        CommittedReclaim::Complete
    } else {
        CommittedReclaim::More
    })
}

/// At most 14 page deletes plus one header write (also <=1 MiB). New start waits for true.
/// Safe after restart for cancelled/completed staging: reclamation does not authorize any sync.
pub fn reclaim(context: &Context, request: RequestId, job: &Job) -> Result<bool> {
    let charge = AdmissionCharge::reserve(job)?;
    reclaim_precharged(context, request, &charge)
}

/// Reclaim one bounded slice using an already-accounted state workspace.
pub(crate) fn reclaim_precharged(
    context: &Context,
    request: RequestId,
    _charge: &AdmissionCharge,
) -> Result<bool> {
    let key = key(context)?;
    let scope = scope(context);
    let mut batch = context.store().batch()?;
    let mut state = load(&batch, key, &scope)?.ok_or_else(|| invalid("no history demand"))?;
    if state.request != request {
        return Err(invalid("history request ID changed"));
    }
    let Some(mut cleanup) = state.cleanup else {
        return Ok(true);
    };
    let end = cleanup.last.min(cleanup.next + RECLAIM_ROWS - 1);
    for page in cleanup.next..=end {
        batch.delete_segment(&scope, KIND, page)?;
    }
    cleanup.next = end + 1;
    state.cleanup = (cleanup.next <= cleanup.last).then_some(cleanup);
    put(&mut batch, key, &scope, &state)?;
    commit_context(batch, context)?;
    Ok(state.cleanup.is_none())
}

/// Finish only already-admitted page reclamation for an interrupted public request.
/// The exact activation identity prevents an old owner touching a replacement. This
/// does not cancel the request or discard any unfinished body.
pub(crate) fn retire_admitted_cleanup(
    context: &Context,
    active: &Active,
    _admission: &AdmissionCharge,
    committed: &std::sync::atomic::AtomicBool,
) -> Result<(bool, bool)> {
    let scope = scope(context);
    let mut batch = context.store().batch()?;
    let Some(mut state) = load(&batch, &context.key, &scope)? else {
        return Ok((true, false));
    };
    if active.node != context.node
        || active.scope != scope
        || state.request != active.request
        || state.binding != active.binding
        || state.serial != active.serial
    {
        return Ok((true, false));
    }
    if let Some(mut cleanup) = state.cleanup {
        let end = cleanup.last.min(cleanup.next + RECLAIM_ROWS - 1);
        for page in cleanup.next..=end {
            batch.delete_segment(&scope, KIND, page)?;
        }
        cleanup.next = end + 1;
        state.cleanup = (cleanup.next <= cleanup.last).then_some(cleanup);
    }
    if state.cleanup.is_none()
        && state.body.is_none()
        && state.remaining == 0
        && state.progress == Progress::Pending
    {
        state.cursor = None;
        state.progress = Progress::Complete;
    }
    put(&mut batch, &context.key, &scope, &state)?;
    batch.commit()?;
    committed.store(true, std::sync::atomic::Ordering::Release);
    Ok((
        state.cleanup.is_none(),
        state.progress == Progress::Complete,
    ))
}

/// Retirement deletion only. The room owner first holds the room mutex and verifies its
/// unlocked incarnation. Observer cancellation cannot revoke permission to delete this exact
/// abandoned staging, but a replacement request/binding is always left untouched. This route
/// cannot start/resume demand, admit entries, append bodies, acknowledge bytes or grant access.
pub(crate) fn retire_staging(
    context: &Context,
    active: &mut Active,
    _admission: &AdmissionCharge,
    committed: &std::sync::atomic::AtomicBool,
) -> Result<bool> {
    let key = &context.key;
    let scope = scope(context);
    let mut batch = context.store().batch()?;
    let Some(mut state) = load(&batch, key, &scope)? else {
        return Ok(true);
    };
    if active.node != context.node
        || active.scope != scope
        || state.request != active.request
        || state.binding != active.binding
        || state.serial != active.serial
    {
        return Ok(true);
    }
    if state.progress.terminal() && state.cleanup.is_none() {
        return Ok(true);
    }
    if !state.progress.terminal() {
        state.serial = next_serial(state.serial)?;
        state.progress = Progress::Cancelled;
        schedule_cleanup(&mut state);
    }
    if let Some(mut cleanup) = state.cleanup {
        let end = cleanup.last.min(cleanup.next + RECLAIM_ROWS - 1);
        for page in cleanup.next..=end {
            batch.delete_segment(&scope, KIND, page)?;
        }
        cleanup.next = end + 1;
        state.cleanup = (cleanup.next <= cleanup.last).then_some(cleanup);
    }
    put(&mut batch, key, &scope, &state)?;
    batch.commit()?;
    committed.store(true, std::sync::atomic::Ordering::Release);
    // Keep only this retired deletion owner's serial current across bounded page slices.
    // It remains invalid for all ordinary body/admission/ACK operations.
    active.serial = state.serial;
    active.valid = false;
    Ok(state.cleanup.is_none())
}
