//! Channel-facing checked queries and one-turn governance maintenance.

use super::super::{ChannelState, RoomNotice, Share};
use super::{facts, View};
use crate::atrest::sek::Sek;
use crate::error::Result;
use crate::governance::entry::{GovBody, GovEntry};
use crate::hash::Digest32;
use crate::node::store::Store;

#[derive(Clone, Copy, Debug)]
pub(crate) struct Presence {
    pub last: (u64, bool),
    pub last_ms: Option<u64>,
    pub back: Option<(u64, u64)>,
}

impl Presence {
    /// Fold one authenticated presence statement, already indexed in `batch`. A membership
    /// starts at the earliest `here` after the member's latest stated leave; a sender-key
    /// rotation's `here` statement is not a return. A statement learned out of order is placed
    /// against the author's held authenticated governance positions. A later start is always
    /// taken; an earlier one only when the author's feed is held without a gap across the
    /// positions it passes over, and otherwise the later start stands (fail closed).
    pub(in crate::node::channel) fn fold(
        old: Option<Self>,
        batch: &crate::node::store::Batch<'_>,
        entries: &super::EntryIndex,
        sek: &Sek,
        room: &Digest32,
        entry: &crate::log::entry::Entry,
        here: bool,
    ) -> Result<Self> {
        let (seq, ms) = (entry.skeleton.seq, entry.skeleton.claimed_ms);
        let Some(mut state) = old else {
            return Ok(Self {
                last: (seq, here),
                last_ms: Some(ms),
                back: None,
            });
        };
        let prior = state.last;
        if seq > prior.0 {
            state.last = (seq, here);
            state.last_ms = Some(ms);
            if here && !prior.1 {
                state.back = Some((seq, ms));
            }
            return Ok(state);
        }
        // Out of order: only the start of a membership that still stands can move.
        if seq == prior.0 || !prior.1 {
            return Ok(state);
        }
        let author = &entry.skeleton.author_id;
        let facts = facts::Read::from_batch(batch, sek, room)?;
        if !here {
            // A leave learned late, with no known return after it: the first statement after
            // it is that return. A later leave there was already folded when it arrived.
            if state.back.is_none_or(|(back, _)| back < seq) {
                if let Some((next, next_ms, true)) = next_presence(&facts, author, seq)? {
                    state.back = Some((next, next_ms));
                }
            }
        } else if let Some((back, _)) = state.back.filter(|(back, _)| *back > seq) {
            // A return learned late, before the known one and after the same leave.
            if facts.current_ready()?
                && entries
                    .in_batch(batch, sek, room)?
                    .published_through(author)
                    >= back
                && !leave_between(&facts, author, seq, back)?
            {
                state.back = Some((seq, ms));
            }
        }
        Ok(state)
    }

    /// Derived repair of each stored membership start a sender-key rotation's `here` statement
    /// moved (v0.4.19 and earlier), from the room's held authenticated governance positions. The
    /// start of a member who is here now is recomputed as the earliest `here` after its latest
    /// stated leave. A later start is always taken; an earlier one only when the governance facts
    /// hold every source row and the author's feed is held without a gap through its latest
    /// statement. Otherwise the stored, later start stands (fail closed).
    pub(in crate::node::channel) fn repair(
        store: &Store,
        entries: &super::EntryIndex,
        sek: &Sek,
        room: &Digest32,
        presence: &mut std::collections::BTreeMap<Digest32, Self>,
        published_through: impl Fn(&Digest32) -> u64,
    ) -> Result<()> {
        let Some(facts) = facts::Read::open_existing(store, sek, room)? else {
            return Ok(());
        };
        let complete = facts.current_ready()?;
        let mut repaired = Vec::new();
        for (author, state) in presence.iter() {
            let Some((back, _)) = state.back.filter(|_| state.last.1) else {
                continue;
            };
            let derived = held_return(&facts, author)?;
            if derived == state.back {
                continue;
            }
            let later = derived.is_some_and(|(seq, _)| seq > back);
            if later || (complete && published_through(author) >= state.last.0) {
                repaired.push((
                    *author,
                    Self {
                        back: derived,
                        ..*state
                    },
                ));
            }
        }
        drop(facts);
        if repaired.is_empty() {
            return Ok(());
        }
        let mut batch = store.batch()?;
        let mut index = entries.write(&mut batch, sek, room)?;
        for (author, state) in &repaired {
            index.note_presence(*author, *state)?;
        }
        index.seal()?;
        batch.commit()?;
        presence.extend(repaired);
        Ok(())
    }
}

/// The author's held presence statement, as (seq, claimed time, here), behind one position row.
fn presence_at(facts: &facts::Read<'_>, log: u64) -> Result<Option<(u64, u64, bool)>> {
    let entry = facts.entry(log)?;
    Ok(match GovEntry::body_bound_to(&entry) {
        Ok(GovBody::Presence(presence)) => Some((
            entry.skeleton.seq,
            entry.skeleton.claimed_ms,
            presence.body.here,
        )),
        _ => None,
    })
}

/// The author's first held presence statement after `seq`.
fn next_presence(
    facts: &facts::Read<'_>,
    author: &Digest32,
    seq: u64,
) -> Result<Option<(u64, u64, bool)>> {
    let mut after = facts::position(author, seq);
    while let Some((key, log)) = facts
        .first(facts::Table::Positions, Some(after))?
        .filter(|(key, _)| key[..32] == author[..])
    {
        if let Some(presence) = presence_at(facts, log)? {
            return Ok(Some(presence));
        }
        after = key;
    }
    Ok(None)
}

/// Whether the author stated a leave strictly between `low` and `high`.
fn leave_between(facts: &facts::Read<'_>, author: &Digest32, low: u64, high: u64) -> Result<bool> {
    let low = facts::position(author, low);
    let mut before = facts::position(author, high);
    while let Some((key, log)) = facts
        .last(facts::Table::Positions, Some(before))?
        .filter(|(key, _)| *key > low)
    {
        if presence_at(facts, log)?.is_some_and(|(_, _, here)| !here) {
            return Ok(true);
        }
        before = key;
    }
    Ok(false)
}

/// The earliest held `here` after the author's latest held leave; `None` without a leave.
fn held_return(facts: &facts::Read<'_>, author: &Digest32) -> Result<Option<(u64, u64)>> {
    let mut before = facts::position(author, u64::MAX);
    let mut back = None;
    while let Some((key, log)) = facts
        .last(facts::Table::Positions, Some(before))?
        .filter(|(key, _)| key[..32] == author[..])
    {
        match presence_at(facts, log)? {
            Some((_, _, false)) => return Ok(back),
            Some((seq, ms, true)) => back = Some((seq, ms)),
            None => {}
        }
        before = key;
    }
    Ok(None)
}

/// Checked application-content eligibility at the published governance revision.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContentEligibility {
    Eligible,
    Ineligible,
    /// Its authenticated source/frontier or bounded projection is not yet current.
    Refreshing,
}

/// A turn may publish current authority while later ordinary causal work remains.
#[derive(Clone, Copy, Debug)]
pub struct GovernanceProgress {
    /// Current source and authority facts are ready for checked reads at this turn's time.
    pub ready: bool,
    /// Another bounded maintenance turn is needed, possibly only for later ordinary entries.
    pub pending: bool,
    /// This turn published a different display revision or restored readiness.
    pub changed: bool,
}

/// At most 64 inspected target slots; an empty result may still have a continuation.
pub struct GovernanceTargets {
    /// Matching current targets in fingerprint order.
    pub targets: Vec<Digest32>,
    /// Last inspected target; continue strictly after it, even when `targets` is empty.
    pub next: Option<Digest32>,
}

/// Current shares selected from at most 64 inspected service slots.
pub struct GovernanceShares {
    /// Shared services whose hosts have not left the room.
    pub shares: Vec<Share>,
    /// Last inspected host and service-name hash; none exhausts the listing.
    pub next: Option<(Digest32, Digest32)>,
}

/// Chronological notices from one newest-first disk page. Continue strictly before
/// `before` with this same revision; do not replace a visible page on read failure.
pub struct GovernanceNotices {
    /// Selected notices in chronological order.
    pub notices: Vec<RoomNotice>,
    /// Continue strictly before this canonical clock and entry hash; none exhausts the listing.
    pub before: Option<(u64, Digest32)>,
    /// Governance revision to preserve for the next page.
    pub revision: u64,
}

/// Proof that this room's governance fold was current through the node's local receipt
/// frontier when it was obtained: every control entry the node has accepted is ordered and
/// evaluated (ADR-037 R3). The three irreversible egresses — the encryption audience of a
/// Session append, a drive-key release, and a consent key release — take one by value, and
/// nothing but [`ChannelState::require_governance_ready`] can make one, so no call site
/// reaches an egress without the fold's proof. A revocation the node holds but has not folded
/// therefore cannot let a removed member be encrypted to.
#[derive(Clone, Copy, Debug)]
pub struct GovernanceCurrent(());

impl ChannelState {
    /// A pending replay is retryable. A malformed or unreadable stored fact is
    /// never classified as refreshing, so callers must preserve that error.
    pub fn governance_refreshing(error: &crate::error::Error) -> bool {
        super::refreshing(error)
    }

    /// Check one target against current authority at `now`, including the genesis creator.
    /// Pending replay or authority expiry returns refreshing rather than an absence claim.
    pub fn is_admin(&self, store: &Store, target: &Digest32, now: crate::time::Ms) -> Result<bool> {
        if self
            .checked_governance(store, now.get())?
            .is_member_removed(target)?
        {
            return Ok(false);
        }
        self.with_semantic_facts(now.get(), |facts| {
            facts.is_admin(target, &self.genesis.creator_pubkey().fingerprint())
        })
    }

    /// Require non-expiring policy authority and a known, non-root room member.
    pub fn validate_member_removal(
        &self,
        store: &Store,
        issuer: &Digest32,
        target: &Digest32,
        now: crate::time::Ms,
    ) -> Result<()> {
        let root = self.genesis.creator_pubkey().fingerprint();
        if *target == root {
            return Err(crate::error::Error::Profile(
                "the room creator cannot be removed",
            ));
        }
        let view = self.checked_governance(store, now.get())?;
        if !self.is_member(target) || view.is_member_removed(target)? {
            return Err(crate::error::Error::Profile("room member not found"));
        }
        #[cfg(feature = "test-knobs")]
        if std::env::var("VOX_TEST_FX62_MUTANT").as_deref() == Ok("nonadmin-remove") {
            return Ok(());
        }
        if view.is_member_removed(issuer)?
            || (*issuer != root && !self.is_member(issuer))
            || !self.with_semantic_facts(now.get(), |facts| facts.grants_policy(issuer, &root))?
        {
            return Err(crate::error::Error::Profile(
                "room policy authority required",
            ));
        }
        view.require_member_removal_certificate(issuer)
    }

    /// Return every validated removal of this identity, sorted by log entry hash.
    pub fn validated_member_removals(
        &self,
        store: &Store,
        target: &Digest32,
        now: crate::time::Ms,
    ) -> Result<Vec<Digest32>> {
        self.checked_governance(store, now.get())?
            .validated_member_removals(target)
    }

    /// Whether this exact member governance entry was accepted by the current fold.
    pub fn member_governance_applied(
        &self,
        store: &Store,
        hash: &Digest32,
        now: crate::time::Ms,
    ) -> Result<bool> {
        self.checked_governance(store, now.get())?
            .member_governance_applied(hash)
    }

    /// Whether any validated removal remains unsuperseded by creator readmission.
    pub fn is_member_removed(&self, store: &Store, target: &Digest32) -> Result<bool> {
        self.checked_governance(store, self.now_hint)?
            .is_member_removed(target)
    }

    pub(crate) fn peer_removal_applied(&self, store: &Store, peer: &Digest32) -> Result<bool> {
        super::peer_removal_applied(store, &self.sek, &self.channel_id, peer)
    }

    /// Current public exchange authority, without changing historical author membership.
    /// This node's own removal does not gate receiving readmission and its ancestry.
    pub(crate) fn room_peer_current(&self, store: &Store, peer: &Digest32) -> Result<bool> {
        Ok(self.is_member(peer) && !self.peer_removal_applied(store, peer)?)
    }

    /// Whether a retained public entry is eligible under the current checked fold.
    pub fn content_eligible(
        &self,
        store: &Store,
        entry: &crate::log::entry::Entry,
    ) -> Result<bool> {
        self.checked_governance(store, self.now_hint)?
            .content_eligible(entry)
    }

    /// Nonblocking exact-entry decision from the bounded durable projection.
    pub(crate) fn content_eligibility(
        &self,
        store: &Store,
        entry: &crate::log::entry::Entry,
    ) -> Result<ContentEligibility> {
        match self.checked_governance(store, self.now_hint) {
            Ok(view) => view.content_eligibility(entry),
            Err(error) if super::refreshing(&error) => Ok(ContentEligibility::Refreshing),
            Err(error) => Err(error),
        }
    }

    pub(crate) fn is_member_removed_in(
        &self,
        read: &super::super::entry_store::Read<'_>,
        target: &Digest32,
    ) -> Result<bool> {
        if read.channel() != &self.channel_id {
            return Err(crate::error::Error::MalformedAtRest(
                "member query room binding",
            ));
        }
        View::pinned(
            read.snapshot(),
            read.sek(),
            read.channel(),
            self.genesis.creator_pubkey().fingerprint(),
            self.now_hint,
        )?
        .is_member_removed(target)
    }

    /// Page current removed identities under one checked authority generation.
    pub fn removed_member_page(
        &self,
        store: &Store,
        after: Option<Digest32>,
        generation: Option<u64>,
        now: crate::time::Ms,
    ) -> Result<(Vec<Digest32>, Option<Digest32>, u64)> {
        let view = self.checked_governance(store, now.get())?;
        let current = view.authority_generation();
        if generation.is_some_and(|expected| expected != current) {
            return Err(crate::error::Error::Profile(super::view::REFRESHING));
        }
        let (rows, next) = view.removed_page(after)?;
        Ok((rows, next, current))
    }

    /// Durable removal incarnation, for fencing previously prepared work.
    pub fn removal_generation(&self, store: &Store) -> Result<u64> {
        super::removal_generation(store, &self.channel_id)
    }

    /// Current governance revision, requiring authority to be ready at the room's latest time.
    pub fn governance_revision(&self, now: crate::time::Ms) -> Result<u64> {
        if self.poisoned {
            return Err(self.save_failure());
        }
        if !self.governance_display_current(now.get()) {
            return Err(crate::error::Error::Profile(super::view::REFRESHING));
        }
        Ok(self.governance_display.revision)
    }

    /// Resolve an exact service name or base32 service fingerprint from current source facts.
    /// A departed host or a withdrawn share returns none; incomplete source replay is an error.
    pub fn shared_service(
        &self,
        _store: &Store,
        host: &Digest32,
        name: &str,
    ) -> Result<Option<Share>> {
        self.with_semantic_facts(self.now_hint, |facts| {
            if self.has_left(host) {
                Ok(None)
            } else {
                facts.share_selector(host, name)
            }
        })?
    }

    /// Answer one exact lookup or page inspecting at most 64 slots.
    /// Supplied revisions must match; authority-dependent selections also require a ready fold.
    pub fn governance_page(
        &self,
        store: &Store,
        query: crate::node::api::GovernanceQuery,
    ) -> Result<crate::node::api::GovernancePage> {
        use crate::node::api::{GovernancePage as Page, GovernanceQuery as Query};
        let expected = match &query {
            Query::Notices { revision, .. }
            | Query::NoticesAfter { revision, .. }
            | Query::Admins { revision, .. }
            | Query::Shares { revision, .. }
            | Query::Consent { revision, .. } => *revision,
            Query::Service { .. } | Query::Admin { .. } => None,
        };
        let revision = self.governance_revision(crate::time::Ms(self.now_hint))?;
        if expected.is_some_and(|expected| expected != revision) {
            return Err(crate::error::Error::Profile(
                "room governance changed; reload the page",
            ));
        }
        Ok(match query {
            Query::Admin { target } => Page::Admin {
                target,
                admin: self.is_admin(store, &target, crate::time::Ms(self.now_hint))?,
                revision,
            },
            Query::Service { host, selector } => Page::Service {
                share: self.shared_service(store, &host, &selector)?,
                revision,
            },
            Query::NoticesAfter { entry, after, .. } => {
                let rendered = self
                    .entries
                    .render_view(store, &self.sek, &self.channel_id)?;
                let start = entry
                    .map(|entry| rendered.order().key(&entry))
                    .transpose()?
                    .flatten();
                if entry.is_some()
                    && (start.is_none()
                        || entry
                            .map(|hash| rendered.fact(&hash))
                            .transpose()?
                            .flatten()
                            .is_none())
                {
                    return Err(crate::error::Error::Profile(
                        "notice anchor is no longer visible; reload the page",
                    ));
                }
                let end = rendered.step(None, true, start, false)?.map(|(key, _)| key);
                if after.is_some_and(|cursor| {
                    start.is_some_and(|start| cursor < start)
                        || end.is_some_and(|end| cursor >= end)
                }) {
                    return Err(crate::error::Error::Profile(
                        "notice cursor is outside the selected message range",
                    ));
                }
                let page = self
                    .checked_governance(store, self.now_hint)?
                    .notices_between(after.or(start), end, true, Some(revision), 64)?;
                let rows = page
                    .rows
                    .into_iter()
                    .map(|(_, mut notice)| {
                        notice.after = entry;
                        notice
                    })
                    .collect();
                Page::NoticesAfter {
                    rows,
                    next: page.next,
                    revision,
                }
            }
            Query::Notices { before, .. } => {
                let p = self.notice_page(store, before, Some(revision), 64)?;
                Page::Notices {
                    rows: p.notices,
                    before: p.before,
                    revision,
                }
            }
            Query::Shares { after, .. } => {
                let p = self.share_page(store, after, 64)?;
                Page::Shares {
                    rows: p.shares,
                    next: p.next,
                    revision,
                }
            }
            Query::Admins { after, .. } => {
                let p = self.admin_page(store, after, 64, crate::time::Ms(self.now_hint))?;
                Page::Admins {
                    creator: self.genesis.creator_pubkey().fingerprint(),
                    members: p.targets,
                    next: p.next,
                    revision,
                }
            }
            Query::Consent { author, after, .. } => {
                let author = author.unwrap_or_else(|| self.me());
                let p = self.consent_page(store, &author, after, 64)?;
                Page::Consent {
                    author,
                    targets: p.targets,
                    next: p.next,
                    revision,
                }
            }
        })
    }

    pub(in crate::node::channel) fn current_governance(&self, store: &Store) -> Result<View<'_>> {
        if self.poisoned {
            return Err(self.save_failure());
        }
        View::current(
            store,
            &self.sek,
            &self.channel_id,
            self.genesis.creator_pubkey().fingerprint(),
        )
    }

    /// The ordinary semantic query boundary. Neither readiness nor the answer opens storage.
    fn with_semantic_facts<T>(
        &self,
        now: u64,
        answer: impl FnOnce(&super::view::SemanticFacts) -> T,
    ) -> Result<T> {
        self.governance_revision(crate::time::Ms(now))?;
        let state = self
            .governance_semantic
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Ok(answer(state.current(
            self.governance_display.revision,
            self.governance_display.valid_until,
        )?))
    }

    pub(in crate::node::channel) fn semantic_admin_clock(&self) -> Result<Option<u64>> {
        self.with_semantic_facts(self.now_hint, super::view::SemanticFacts::admin_clock)
    }

    pub(in crate::node::channel) fn semantic_share_exact(
        &self,
        host: &Digest32,
        name: &str,
    ) -> Result<Option<Share>> {
        self.with_semantic_facts(self.now_hint, |facts| facts.share_exact(host, name))?
    }

    pub(in crate::node::channel) fn advance_semantic_facts(&self, view: &View<'_>) -> Result<bool> {
        self.governance_semantic
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .advance(view)
    }

    pub(in crate::node::channel) fn checked_governance(
        &self,
        store: &Store,
        now: u64,
    ) -> Result<View<'_>> {
        if self.poisoned {
            return Err(self.save_failure());
        }
        View::open(
            store,
            &self.sek,
            &self.channel_id,
            self.genesis.creator_pubkey().fingerprint(),
            now,
        )
    }

    /// Called by the actor's shared round-robin maintenance hook, never drained
    /// in a loop while the room mutex is held. No snapshot survives this turn.
    pub fn advance_governance(
        &mut self,
        store: &Store,
        now: crate::time::Ms,
    ) -> Result<GovernanceProgress> {
        if self.poisoned {
            return Err(self.save_failure());
        }
        self.now_hint = self.now_hint.max(now.get());
        let was_ready = self.governance_ready;
        let updated = (|| -> Result<GovernanceProgress> {
            let state = super::advance(
                store,
                &self.entries,
                &self.sek,
                &self.channel_id,
                &self.authors,
                &self.genesis.creator_pubkey().fingerprint(),
                &self.me(),
                now.get(),
            )?;
            let mut changed = false;
            let mut consent_ready = false;
            if state.ready {
                let view = self.checked_governance(store, now.get())?;
                let display = view.display(&self.genesis)?;
                consent_ready = self.advance_semantic_facts(&view)?;
                changed = self.governance_display.revision != display.revision
                    || (!was_ready && consent_ready);
                self.governance_display = display;
                self.governance_ready = consent_ready;
            }
            Ok(GovernanceProgress {
                // Irreversible work needs the current checked disk fold, not merely the retained
                // last-good display that ordinary reads continue to show during a no-op replay.
                ready: state.ready && consent_ready,
                pending: state.pending || (state.ready && !consent_ready),
                changed,
            })
        })();
        if let Err(ref error) = updated {
            if !super::refreshing(error) {
                self.poison(error);
            }
        }
        updated
    }

    /// Whether a bounded render turn still has work under current consent facts.
    pub fn governance_backfill_pending(&self, store: &Store) -> Result<bool> {
        if self.legacy_cache_only(store)? {
            return Ok(false);
        }
        match self.consent_facts() {
            Ok(facts) => drop(facts),
            // A backfill drained into a refreshing view is still pending work: the turn after
            // the refresh renders it (ADR-038 FX-22, #1007).
            Err(error) if super::refreshing(&error) => return Ok(self.backfill_awaits_refresh()),
            Err(error) => return Err(error),
        }
        Ok(self
            .entries
            .render_view(store, &self.sek, &self.channel_id)?
            .has_backfill())
    }

    /// Projection callers retain their last good view while this returns refreshing. The
    /// token it returns is the only proof an irreversible egress accepts (ADR-037 R3).
    pub fn require_governance_ready(
        &self,
        store: &Store,
        now: crate::time::Ms,
    ) -> Result<GovernanceCurrent> {
        self.require_legacy_current(store)?;
        self.checked_governance(store, now.get())
            .map(|_| GovernanceCurrent(()))
    }

    /// A local setting is visible only after the same checked revision has reached
    /// the bounded in-memory display. A ready disk fold alone is not publication.
    pub(crate) fn require_governance_display(
        &self,
        _store: &Store,
        now: crate::time::Ms,
    ) -> Result<()> {
        if self.poisoned {
            return Err(self.save_failure());
        }
        if !self.governance_display_current(now.get()) {
            return Err(crate::error::Error::Profile(super::view::REFRESHING));
        }
        Ok(())
    }

    pub(in crate::node::channel) fn governance_display_current(&self, now: u64) -> bool {
        self.governance_ready
            && (self.governance_display.valid_until == 0
                || now < self.governance_display.valid_until)
    }

    /// The exact wall-clock boundary at which current authority must be re-evaluated. The actor
    /// arms this deadline directly; periodic traffic is not a correctness wake.
    pub(crate) fn governance_deadline(&self) -> Option<u64> {
        (self.governance_display.valid_until != 0).then_some(self.governance_display.valid_until)
    }

    pub(in crate::node::channel) fn grants_policy(
        &self,
        store: &Store,
        who: &Digest32,
        now: u64,
    ) -> Result<bool> {
        if self.poisoned {
            return Err(self.save_failure());
        }
        // Genesis authority is immutable; creation can append its initial facts
        // without synchronously draining the new room's derived index.
        if *who == self.genesis.creator_pubkey().fingerprint() {
            return Ok(true);
        }
        if self
            .checked_governance(store, now)?
            .is_member_removed(who)?
        {
            return Ok(false);
        }
        self.with_semantic_facts(now, |facts| {
            facts.grants_policy(who, &self.genesis.creator_pubkey().fingerprint())
        })
    }

    /// Select current consent targets, including identities outside the admitted roster.
    /// Inspect at most `limit` clamped to 1..=64 slots strictly after `after`.
    pub fn consent_page(
        &self,
        _store: &Store,
        author: &Digest32,
        after: Option<Digest32>,
        limit: usize,
    ) -> Result<GovernanceTargets> {
        let page = self.with_semantic_facts(self.now_hint, |facts| {
            facts.consenters(author, after, limit)
        })?;
        Ok(GovernanceTargets {
            targets: page.rows,
            next: page.next,
        })
    }

    /// Page through active admins under checked authority at `now`, excluding the creator.
    /// Inspect at most `limit` clamped to 1..=64 slots strictly after `after`.
    pub fn admin_page(
        &self,
        _store: &Store,
        after: Option<Digest32>,
        limit: usize,
        now: crate::time::Ms,
    ) -> Result<GovernanceTargets> {
        let page = self.with_semantic_facts(now.get(), |facts| facts.admins(after, limit))?;
        // The genesis creator is a separate scalar and is not repeated in this page.
        Ok(GovernanceTargets {
            targets: page.rows,
            next: page.next,
        })
    }

    /// Page through current shares, filtering withdrawn announcements and departed hosts.
    /// Inspect at most `limit` clamped to 1..=64 slots; an empty page may still continue.
    pub fn share_page(
        &self,
        _store: &Store,
        after: Option<(Digest32, Digest32)>,
        limit: usize,
    ) -> Result<GovernanceShares> {
        let page = self.with_semantic_facts(self.now_hint, |facts| facts.shares(after, limit))?;
        Ok(GovernanceShares {
            shares: page
                .rows
                .into_iter()
                .filter(|share| !self.has_left(&share.host))
                .collect(),
            next: page.next,
        })
    }

    /// Select up to `limit` clamped to 1..=64 older notice slots, in chronological order.
    /// Require current authority and, when supplied, the exact continuation revision.
    pub fn notice_page(
        &self,
        store: &Store,
        before: Option<(u64, Digest32)>,
        revision: Option<u64>,
        limit: usize,
    ) -> Result<GovernanceNotices> {
        let mut page = self
            .checked_governance(store, self.now_hint)?
            .notices(before, revision, limit)?;
        let rendered = self
            .entries
            .render_view(store, &self.sek, &self.channel_id)?;
        for (clock, notice) in &mut page.rows {
            notice.after = rendered
                .step(None, true, Some((*clock, notice.entry_hash)), true)?
                .map(|(key, _)| key.1);
        }
        Ok(GovernanceNotices {
            notices: page.rows.into_iter().map(|(_, notice)| notice).collect(),
            before: page.next,
            revision: page.revision,
        })
    }

    /// A semantic-changing durable receipt retires publication before its current-input
    /// mirror or presence can become visible. Last-good saved reads retain their own facts.
    pub(in crate::node::channel) fn retire_governance(&mut self) -> Result<()> {
        self.governance_ready = false;
        self.governance_semantic
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .retire()
    }

    pub(in crate::node::channel) fn observe_governance_into(
        &mut self,
        store: &Store,
        batch: &mut crate::node::store::Batch<'_>,
        entry: &crate::log::entry::Entry,
        log: u64,
    ) -> Result<bool> {
        // A read transaction sees the roots before this caller's publication Batch.
        // Descendants accepted in this same signed batch are ordinary forward progress;
        // only a previously published child makes this a late-parent/body repair.
        let late = self
            .entries
            .read(store, &self.sek, &self.channel_id)?
            .child_after(&entry.entry_hash(), None)?
            .is_some();
        let accepted = super::accepted_into(
            batch,
            &self.entries,
            &self.sek,
            &self.channel_id,
            &self.authors,
            &self.genesis.creator_pubkey().fingerprint(),
            &self.me(),
            log,
            entry,
            late,
        )?;
        // The Batch failure path poisons this ChannelState, so it is safe to advance the
        // in-memory mirror here with the same accepted input: no usable state can outlive a
        // failed commit. This covers every publication path without polling a sealed header.
        if accepted.work_changed {
            self.retire_governance()?;
        }
        if accepted.current_advanced {
            self.note_committed_consent(entry)?;
        }
        if accepted.work_changed {
            if let Ok(body) = GovEntry::body_bound_to(entry) {
                if let Some(key) = self.authors.get(&entry.skeleton.author_id) {
                    if body.verify(key).is_ok() {
                        if let GovBody::Presence(presence) = &body {
                            let state = Presence::fold(
                                self.presence.get(&entry.skeleton.author_id).copied(),
                                batch,
                                &self.entries,
                                &self.sek,
                                &self.channel_id,
                                entry,
                                presence.body.here,
                            )?;
                            self.presence.insert(entry.skeleton.author_id, state);
                            let mut index =
                                self.entries.write(batch, &self.sek, &self.channel_id)?;
                            index.note_presence(entry.skeleton.author_id, state)?;
                            index.seal()?;
                        }
                    }
                }
            }
        }
        Ok(accepted.work_changed)
    }
}
