//! Prototype index primitive, deliberately not wired into history replies yet. A scan
//! borrows ONE pinned RenderView; yielding never switches roots, policy, or query time.
//! The eventual request owner must retain the snapshot/secret-work lease, check current
//! authority before publication, and destroy the scan on cancellation/lock/room replacement.
use super::*;
use std::sync::atomic::{AtomicBool, Ordering};

/// One fixed query's policy. Zero is forever; step activity cannot outlive messages.
#[derive(Clone, Copy)]
pub(crate) struct ExpiryPolicy {
    pub now: u64,
    pub regular: u64,
    pub steps: u64,
}
impl ExpiryPolicy {
    fn ttl(self, class: u64) -> u64 {
        match class {
            0 => self.regular,
            1 => crate::node::retention::shortest(self.regular, self.steps),
            _ => 0,
        }
    }
    fn live(self, base: u64, class: u64) -> bool {
        !crate::node::channel::expired_at(base, self.now, self.ttl(class))
    }
}

/// A producer may stamp this only from FINAL canonical Tracked metadata and exact
/// retention classification in the same Batch as every affected render/filter fact.
/// None is UNKNOWN, including all existing encodings. No timestamp is guessed from created.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct RenderExpiry {
    base: u64,
    class: u64, // 0 regular, 1 steps, 2 durable control
}
impl RenderExpiry {
    pub(super) fn tracked(value: crate::node::retention::Tracked) -> Self {
        Self {
            base: value.base(),
            class: u64::from(value.steps),
        }
    }
    pub(super) fn header(base: u64, steps: bool) -> Self {
        Self {
            base,
            class: u64::from(steps),
        }
    }
    pub(super) fn durable(base: u64) -> Self {
        Self { base, class: 2 }
    }

    pub(super) fn write_option(value: Option<Self>, e: &mut Encoder) {
        match value {
            Some(value) => {
                e.array(2).uint(value.base).uint(value.class);
            }
            None => {
                e.array(0);
            }
        }
    }
    pub(super) fn read_option(d: &mut Decoder<'_>) -> Result<Option<Self>> {
        match d.array()? {
            0 => Ok(None),
            2 => {
                let value = Self {
                    base: d.uint()?,
                    class: d.uint()?,
                };
                if value.class > 2 {
                    return Err(invalid("render retention class"));
                }
                Ok(Some(value))
            }
            _ => Err(invalid("render retention arity")),
        }
    }
}

/// Canonical owed-header metadata. A missing legacy age remains UNKNOWN; a header
/// need not have a retained-body record. `created` remains the displayed signed time.
#[derive(Clone, Copy)]
pub(crate) struct OwedVisibility {
    pub(super) created: u64,
    pub(super) expires: u64,
    pub(super) expiry: Option<RenderExpiry>,
}
impl OwedVisibility {
    pub(crate) fn new(created: u64, base: Option<u64>, steps: bool, ttl: u64) -> Self {
        Self {
            created,
            expires: if ttl == 0 {
                u64::MAX
            } else {
                base.unwrap_or(created)
                    .saturating_add(ttl.saturating_mul(1_000))
            },
            expiry: base.map(|base| RenderExpiry::header(base, steps)),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Bases {
    count: u64,
    min: u64,
    max: u64,
}
impl Bases {
    fn one(base: u64) -> Self {
        Self {
            count: 1,
            min: base,
            max: base,
        }
    }
    fn merge(self, other: Self) -> Result<Self> {
        if self.count == 0 {
            return Ok(other);
        }
        if other.count == 0 {
            return Ok(self);
        }
        Ok(Self {
            count: self
                .count
                .checked_add(other.count)
                .ok_or(invalid("expiry count overflow"))?,
            min: self.min.min(other.min),
            max: self.max.max(other.max),
        })
    }
    fn write(self, e: &mut Encoder) {
        e.array(3).uint(self.count).uint(self.min).uint(self.max);
    }
    fn read(d: &mut Decoder<'_>) -> Result<Self> {
        if d.array()? != 3 {
            return Err(invalid("expiry bounds arity"));
        }
        let found = Self {
            count: d.uint()?,
            min: d.uint()?,
            max: d.uint()?,
        };
        if found.min > found.max || (found.count == 0 && (found.min != 0 || found.max != 0)) {
            return Err(invalid("expiry bounds order"));
        }
        Ok(found)
    }
    fn live_count(self, policy: ExpiryPolicy, class: u64) -> Option<u64> {
        if self.count == 0 || !policy.live(self.max, class) {
            Some(0)
        } else if policy.live(self.min, class) {
            Some(self.count)
        } else {
            None
        }
    }
}

/// Enrichment of the existing ranked summary, not a new index or a constant-time
/// dominance-count index. Mixed classes/ages require descent, potentially O(n).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct ExpiryBounds {
    regular: Bases,
    steps: Bases,
    durable: u64,
}
impl ExpiryBounds {
    pub(super) fn one(value: RenderExpiry) -> Self {
        match value.class {
            0 => Self {
                regular: Bases::one(value.base),
                ..Self::default()
            },
            1 => Self {
                steps: Bases::one(value.base),
                ..Self::default()
            },
            _ => Self {
                durable: 1,
                ..Self::default()
            },
        }
    }
    pub(super) fn count(self) -> Option<u64> {
        self.regular
            .count
            .checked_add(self.steps.count)?
            .checked_add(self.durable)
    }
    pub(super) fn merge(self, other: Self) -> Result<Self> {
        Ok(Self {
            regular: self.regular.merge(other.regular)?,
            steps: self.steps.merge(other.steps)?,
            durable: self
                .durable
                .checked_add(other.durable)
                .ok_or(invalid("expiry count overflow"))?,
        })
    }
    fn live_count(self, policy: ExpiryPolicy) -> Option<u64> {
        self.regular
            .live_count(policy, 0)?
            .checked_add(self.steps.live_count(policy, 1)?)?
            .checked_add(self.durable)
    }
    pub(super) fn write_option(value: Option<Self>, e: &mut Encoder) {
        match value {
            Some(value) => {
                e.array(3);
                value.regular.write(e);
                value.steps.write(e);
                e.uint(value.durable);
            }
            None => {
                e.array(0);
            }
        }
    }
    pub(super) fn read_option(d: &mut Decoder<'_>) -> Result<Option<Self>> {
        match d.array()? {
            0 => Ok(None),
            3 => Ok(Some(Self {
                regular: Bases::read(d)?,
                steps: Bases::read(d)?,
                durable: d.uint()?,
            })),
            _ => Err(invalid("expiry summary arity")),
        }
    }
}

#[derive(Clone, Copy)]
struct Frame {
    page: u64,
    next: usize,
}

#[derive(Clone, Copy)]
struct PendingCandidate {
    key: OrderKey,
    value: Value,
}

pub(crate) enum VisibilityResolution {
    Resolved { key: OrderKey, visible: bool },
    Yielded,
    MissingAge { key: OrderKey },
    Cancelled,
}

pub(crate) enum VisibilityStep {
    /// Metadata candidate only. Call resolve_pending before another step. This is never permission to expose plaintext or a fake EOF.
    Candidate {
        key: OrderKey,
    },
    Yielded,
    Cancelled,
    Complete {
        count: u64,
    },
}

/// Scalar frames only (at most MAX_DEPTH), no per-room row mirror or retained page Vec.
/// Selection and exact count are independent scans over the SAME borrowed snapshot.
/// A selected page must not interpret Yielded as empty/complete. Existing caller/reply
/// integration and physical request ownership are intentionally outside this prototype.
pub(crate) struct VisibilityScan<'scan, 'view> {
    view: &'scan RenderView<'view>,
    policy: ExpiryPolicy,
    after: Option<Key>,
    before: Option<Key>,
    backwards: bool,
    count_only: bool,
    frames: Vec<Frame>,
    pending: Option<PendingCandidate>,
    count: u64,
    cancelled: bool,
}
impl<'scan, 'view> VisibilityScan<'scan, 'view> {
    /// Resolves only THIS scan's pending candidate under its captured snapshot/policy.
    /// No caller-provided boolean or callback can credit another key or a newer view.
    /// This proves expiry eligibility, not a substitute for final current authorization
    /// or the existing non-expiry projection/classification fences.
    pub(crate) fn resolve_pending(
        &mut self,
        budget: &mut crate::log::history::WorkBudget,
        cancel: &AtomicBool,
    ) -> Result<VisibilityResolution> {
        if cancel.load(Ordering::Acquire) || self.cancelled {
            self.cancelled = true;
            self.pending = None;
            self.frames.clear();
            return Ok(VisibilityResolution::Cancelled);
        }
        let pending = self
            .pending
            .ok_or(invalid("visibility candidate not pending"))?;
        if !budget.take_control_lookup() {
            return Ok(VisibilityResolution::Yielded);
        }
        let hash = &pending.key.1;
        let visible = match pending.value {
            Value::Rendered(fact) => {
                if self.view.fact(hash)? != Some(fact) {
                    return Err(invalid("render candidate differs"));
                }
                self.view.retained_visible(hash, self.policy)?
            }
            Value::Owed(fact) => {
                let current = self.view.source().find_value(
                    self.view.order.read.sek,
                    self.view.order.read.channel,
                    self.view.roots().owed_hash,
                    &hashed(hash),
                )?;
                if current != Some(Value::Owed(fact)) {
                    return Err(invalid("owed candidate differs"));
                }
                let entry = self
                    .view
                    .order
                    .entry(hash)?
                    .ok_or(invalid("owed source missing"))?;
                if entry.payload.is_some()
                    || !self
                        .view
                        .missing_contains(&entry.skeleton.author_id, entry.skeleton.seq)?
                {
                    false
                } else {
                    let Some(expiry) = self.view.header_expiry(hash, &entry)? else {
                        return Ok(VisibilityResolution::MissingAge { key: pending.key });
                    };
                    self.policy.live(expiry.base, expiry.class)
                }
            }
            _ => return Err(invalid("visibility candidate kind")),
        };
        if cancel.load(Ordering::Acquire) {
            self.cancelled = true;
            self.pending = None;
            self.frames.clear();
            return Ok(VisibilityResolution::Cancelled);
        }
        self.pending = None;
        if visible {
            self.count = self
                .count
                .checked_add(1)
                .ok_or(invalid("visible count overflow"))?;
        }
        Ok(VisibilityResolution::Resolved {
            key: pending.key,
            visible,
        })
    }
    pub(crate) fn step(
        &mut self,
        budget: &mut crate::log::history::WorkBudget,
        cancel: &AtomicBool,
    ) -> Result<VisibilityStep> {
        if cancel.load(Ordering::Acquire) || self.cancelled {
            self.cancelled = true;
            self.pending = None;
            self.frames.clear();
            return Ok(VisibilityStep::Cancelled);
        }
        if self.pending.is_some() {
            return Err(invalid("visibility candidate not resolved"));
        }
        loop {
            let Some(frame) = self.frames.last_mut() else {
                return Ok(VisibilityStep::Complete { count: self.count });
            };
            if cancel.load(Ordering::Acquire) {
                self.cancelled = true;
                self.frames.clear();
                return Ok(VisibilityStep::Cancelled);
            }
            // Charge before page open/decode; the existing page cache is separately bounded.
            if !budget.take_object_load() {
                return Ok(VisibilityStep::Yielded);
            }
            let page = self.view.source().page(
                self.view.order.read.sek,
                self.view.order.read.channel,
                frame.page,
            )?;
            let len = match &page {
                Page::Leaf(rows) => rows.len(),
                Page::Ranked(rows) => rows.len(),
                Page::Branch(_) => return Err(invalid("unranked visibility tree")),
            };
            if frame.next == usize::MAX {
                frame.next = len;
            }
            let at = if self.backwards {
                if frame.next == 0 {
                    self.frames.pop();
                    continue;
                }
                frame.next -= 1;
                frame.next
            } else {
                if frame.next == len {
                    self.frames.pop();
                    continue;
                }
                let at = frame.next;
                frame.next += 1;
                at
            };
            match page {
                Page::Leaf(rows) => {
                    let (key, value) = rows[at];
                    if self.after.is_some_and(|bound| key <= bound)
                        || self.before.is_some_and(|bound| key >= bound)
                    {
                        continue;
                    }
                    // Even a newly stamped leaf is validated canonically by the caller.
                    if !matches!(value, Value::Rendered(_) | Value::Owed(_)) {
                        return Err(invalid("visibility candidate kind"));
                    }
                    let key = order_key(key)?;
                    self.pending = Some(PendingCandidate { key, value });
                    return Ok(VisibilityStep::Candidate { key });
                }
                Page::Ranked(rows) => {
                    let (max, id, summary) = rows[at];
                    let min_exclusive = at.checked_sub(1).map(|i| rows[i].0);
                    if self.after.is_some_and(|bound| max <= bound)
                        || self
                            .before
                            .zip(min_exclusive)
                            .is_some_and(|(bound, min)| min >= bound)
                    {
                        continue;
                    }
                    // A summary can contribute only if the ENTIRE child lies in the range.
                    let whole = self
                        .after
                        .is_none_or(|bound| min_exclusive.is_some_and(|min| min >= bound))
                        && self.before.is_none_or(|bound| max < bound);
                    if let Some(live) = summary
                        .expiry
                        .and_then(|bounds| bounds.live_count(self.policy))
                    {
                        if live == 0 {
                            continue;
                        }
                        if self.count_only && whole {
                            self.count = self
                                .count
                                .checked_add(live)
                                .ok_or(invalid("visible count overflow"))?;
                            continue;
                        }
                    }
                    if self.frames.len() >= MAX_DEPTH {
                        return Err(invalid("visibility tree depth"));
                    }
                    self.frames.push(Frame {
                        page: id,
                        next: if self.backwards { usize::MAX } else { 0 },
                    });
                }
                Page::Branch(_) => unreachable!(),
            }
        }
    }
}
impl<'view> RenderView<'view> {
    pub(crate) fn visibility_scan<'scan>(
        &'scan self,
        filter: Option<&Filter>,
        display: bool,
        after: Option<OrderKey>,
        before: Option<OrderKey>,
        backwards: bool,
        count_only: bool,
        policy: ExpiryPolicy,
    ) -> Result<VisibilityScan<'scan, 'view>> {
        let root = self.root(filter, display)?;
        Ok(VisibilityScan {
            view: self,
            policy,
            after: after.map(ordered),
            before: before.map(ordered),
            backwards,
            count_only,
            frames: {
                let mut frames = Vec::with_capacity(MAX_DEPTH);
                if root != 0 {
                    frames.push(Frame {
                        page: root,
                        next: if backwards { usize::MAX } else { 0 },
                    });
                }
                frames
            },
            pending: None,
            count: 0,
            cancelled: false,
        })
    }

    /// Does not open plaintext. Only a rendered body requires Tracked/cache identity.
    fn retained_visible(&self, hash: &Digest32, policy: ExpiryPolicy) -> Result<bool> {
        let Some(fact) = self.fact(hash)? else {
            return Ok(false);
        };
        let tracked = self
            .retention(hash)?
            .ok_or(invalid("rendered retention missing"))?;
        if tracked.cache_id != Some(fact.cache) {
            return Err(invalid("rendered retention cache differs"));
        }
        if self.order.read.log_id(hash)? != Some(tracked.log_id) {
            return Err(invalid("rendered retention log differs"));
        }
        let entry = self
            .order
            .entry(hash)?
            .ok_or(invalid("rendered source missing"))?;
        let expiry = if entry
            .payload
            .as_deref()
            .is_some_and(crate::node::channel::retained_control)
        {
            RenderExpiry::durable(tracked.base())
        } else {
            RenderExpiry::tracked(tracked)
        };
        Ok(policy.live(expiry.base, expiry.class))
    }
    fn header_expiry(&self, hash: &Digest32, entry: &Entry) -> Result<Option<RenderExpiry>> {
        if let Some(tracked) = self.retention(hash)? {
            return Ok(Some(RenderExpiry::tracked(tracked)));
        }
        let Some(log) = self.order.read.log_id(hash)? else {
            return Ok(None);
        };
        let Some(bytes) = self.source().open(
            self.order.read.sek,
            self.order.read.channel,
            SegmentKind::Index,
            log,
        )?
        else {
            return Ok(None);
        };
        let (seen, steps) = crate::node::channel::parse_first_seen(&bytes)?;
        Ok(Some(RenderExpiry::header(
            entry.skeleton.claimed_ms.min(seen),
            steps,
        )))
    }
}
