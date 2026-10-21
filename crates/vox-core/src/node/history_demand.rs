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

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
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
    job.reserve(bytes)
        .ok_or_else(|| invalid("history demand buffer budget is busy"))
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
    });
    sha256(&bytes)
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
    let charge = charge(job, STATE_WORK)?;
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

/// The caller supplies freshly rechecked authority. Bounds and remaining count come only from disk.
pub fn resume(
    context: &Context,
    request: RequestId,
    binding: Binding,
    job: &Job,
) -> Result<Active> {
    let _charge = charge(job, STATE_WORK)?;
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
    commit_context(batch, context)?;
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
pub fn append(
    context: &Context,
    active: &mut Active,
    entry: Digest32,
    offset: u64,
    bytes: &[u8],
    job: &Job,
) -> Result<u64> {
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
        return Ok(end);
    }
    body.offset = end;
    state.cursor = None;
    put(&mut batch, key, &scope, &state)?;
    commit(batch, active, context)?;
    Ok(end)
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
pub fn entry_admitted(
    batch: &mut Batch<'_>,
    context: &Context,
    active: &Active,
    entry: Digest32,
    job: &Job,
) -> Result<()> {
    let _charge = charge(job, STATE_WORK)?;
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
    schedule_cleanup(&mut state);
    put(batch, key, &scope, &state)
}

/// Commit one bodyless, authenticated entry that is complete for this node's recipient role.
/// The caller invokes this only from the exact entry's semantic-effect transaction, after its
/// inclusion proof and typed dispatch have succeeded. Unlike body staging, this both advances
/// the archive count and moves the cursor below the role-only header atomically.
pub fn role_header_admitted(
    batch: &mut Batch<'_>,
    context: &Context,
    active: &Active,
    seq: u64,
    job: &Job,
) -> Result<()> {
    let _charge = charge(job, STATE_WORK)?;
    let key = key(context)?;
    let scope = scope(context);
    let mut state = live(batch, key, &scope, context, active)?;
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
    let _charge = charge(job, STATE_WORK)?;
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
    state.cursor = if let Some(cursor) = cursor {
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

pub fn pause(context: &Context, active: &mut Active, job: &Job) -> Result<()> {
    let _charge = charge(job, STATE_WORK)?;
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
    let _charge = charge(job, STATE_WORK)?;
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

/// At most 14 page deletes plus one header write (also <=1 MiB). New start waits for true.
/// Safe after restart for cancelled/completed staging: reclamation does not authorize any sync.
pub fn reclaim(context: &Context, request: RequestId, job: &Job) -> Result<bool> {
    let _charge = charge(job, STATE_WORK)?;
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
