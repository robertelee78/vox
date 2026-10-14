//! Channel-facing checked queries and one-turn governance maintenance.

use super::super::{ChannelState, RoomNotice, Share};
use super::View;
use crate::error::Result;
use crate::governance::capability::Capability;
use crate::governance::entry::{GovBody, GovEntry};
use crate::hash::Digest32;
use crate::node::store::Store;
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug)]
pub(in crate::node::channel) struct Presence {
    pub last: (u64, bool),
    pub back: Option<(u64, u64)>,
}

pub(in crate::node::channel) fn remember_presence(
    state: &mut BTreeMap<Digest32, Presence>,
    entry: &GovEntry,
) {
    if let GovBody::Presence(presence) = &entry.body {
        let held = state.entry(entry.author_id).or_insert(Presence {
            last: (entry.seq, presence.body.here),
            back: None,
        });
        if entry.seq >= held.last.0 {
            held.last = (entry.seq, presence.body.here);
        }
        if presence.body.here && held.back.is_none_or(|(seq, _)| seq < entry.seq) {
            held.back = Some((entry.seq, entry.claimed_ms));
        }
    }
}

/// A turn may publish current authority while later ordinary causal work remains.
#[derive(Clone, Copy, Debug)]
pub struct GovernanceProgress {
    pub ready: bool,
    pub pending: bool,
    pub changed: bool,
}

/// At most 64 inspected target slots; an empty result may still have a continuation.
pub struct GovernanceTargets {
    pub targets: Vec<Digest32>,
    pub next: Option<Digest32>,
}

pub struct GovernanceShares {
    pub shares: Vec<Share>,
    pub next: Option<(Digest32, Digest32)>,
}

/// Chronological notices from one newest-first disk page. Continue strictly before
/// `before` with this same revision; do not replace a visible page on read failure.
pub struct GovernanceNotices {
    pub notices: Vec<RoomNotice>,
    pub before: Option<(u64, Digest32)>,
    pub revision: u64,
}

impl ChannelState {
    /// A pending replay is retryable. A malformed or unreadable stored fact is
    /// never classified as refreshing, so callers must preserve that error.
    pub fn governance_refreshing(error: &crate::error::Error) -> bool {
        super::refreshing(error)
    }

    pub fn is_admin(&self, store: &Store, target: &Digest32, now: crate::time::Ms) -> Result<bool> {
        self.checked_governance(store, now.get())?.is_admin(target)
    }

    pub fn governance_revision(&self, store: &Store) -> Result<u64> {
        Ok(self.checked_governance(store, self.now_hint)?.revision())
    }

    pub fn shared_service(
        &self,
        store: &Store,
        host: &Digest32,
        name: &str,
    ) -> Result<Option<Share>> {
        let view = self.current_governance(store)?;
        if self.has_left(host) {
            return Ok(None);
        }
        view.share_selector(host, name)
    }

    pub fn governance_page(
        &self,
        store: &Store,
        query: crate::node::api::GovernanceQuery,
    ) -> Result<crate::node::api::GovernancePage> {
        use crate::node::api::{GovernancePage as Page, GovernanceQuery as Query};
        let (expected, authority) = match &query {
            Query::Notices { revision, .. }
            | Query::NoticesAfter { revision, .. }
            | Query::Admins { revision, .. } => (*revision, true),
            Query::Shares { revision, .. } | Query::Consent { revision, .. } => (*revision, false),
            Query::Service { .. } => (None, false),
            Query::Admin { .. } => (None, true),
        };
        let revision = if authority {
            self.checked_governance(store, self.now_hint)?.revision()
        } else {
            self.current_governance(store)?.revision()
        };
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
            self.governance_ready = state.ready;
            let mut changed = false;
            if state.ready {
                let display = self
                    .checked_governance(store, now.get())?
                    .display(&self.genesis)?;
                changed = !was_ready || self.governance_display.revision != display.revision;
                self.governance_display = display;
            }
            Ok(GovernanceProgress {
                ready: state.ready,
                pending: state.pending,
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

    /// One bounded render continuation. Consent can be current while the
    /// authority fold still has work, so schedule this independently of pruning.
    pub fn advance_governance_backfill(
        &mut self,
        store: &Store,
        now: crate::time::Ms,
    ) -> Result<usize> {
        if self.poisoned {
            return Err(self.save_failure());
        }
        self.now_hint = self.now_hint.max(now.get());
        self.drain_backfill(store, now.get())
    }

    /// Whether a bounded render turn still has work under current consent facts.
    pub fn governance_backfill_pending(&self, store: &Store) -> Result<bool> {
        match self.current_governance(store) {
            Ok(view) => drop(view),
            Err(error) if super::refreshing(&error) => return Ok(false),
            Err(error) => return Err(error),
        }
        Ok(self
            .entries
            .render_view(store, &self.sek, &self.channel_id)?
            .has_backfill())
    }

    /// Projection callers retain their last good view while this returns refreshing.
    pub fn require_governance_ready(&self, store: &Store, now: crate::time::Ms) -> Result<()> {
        self.checked_governance(store, now.get()).map(|_| ())
    }

    pub(in crate::node::channel) fn governance_display_current(&self, now: u64) -> bool {
        self.governance_ready
            && (self.governance_display.valid_until == 0
                || now < self.governance_display.valid_until)
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
        Ok(self
            .checked_governance(store, now)?
            .grants(who, &Capability::Policy)?
            .is_granted())
    }

    pub fn consent_page(
        &self,
        store: &Store,
        author: &Digest32,
        after: Option<Digest32>,
        limit: usize,
    ) -> Result<GovernanceTargets> {
        let page = self
            .current_governance(store)?
            .consenters(author, after, limit)?;
        Ok(GovernanceTargets {
            targets: page.rows,
            next: page.next,
        })
    }

    pub fn admin_page(
        &self,
        store: &Store,
        after: Option<Digest32>,
        limit: usize,
        now: crate::time::Ms,
    ) -> Result<GovernanceTargets> {
        let page = self
            .checked_governance(store, now.get())?
            .admins(after, limit)?;
        // The genesis creator is a separate scalar and is not repeated in this page.
        Ok(GovernanceTargets {
            targets: page.rows,
            next: page.next,
        })
    }

    pub fn share_page(
        &self,
        store: &Store,
        after: Option<(Digest32, Digest32)>,
        limit: usize,
    ) -> Result<GovernanceShares> {
        let page = self.current_governance(store)?.shares(after, limit)?;
        Ok(GovernanceShares {
            shares: page
                .rows
                .into_iter()
                .filter(|share| !self.has_left(&share.host))
                .collect(),
            next: page.next,
        })
    }

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

    pub(in crate::node::channel) fn observe_governance_into(
        &mut self,
        store: &Store,
        batch: &mut crate::node::store::Batch<'_>,
        entry: &crate::log::entry::Entry,
        log: u64,
    ) -> Result<()> {
        // A read transaction sees the roots before this caller's publication Batch.
        // Descendants accepted in this same signed batch are ordinary forward progress;
        // only a previously published child makes this a late-parent/body repair.
        let late = self
            .entries
            .read(store, &self.sek, &self.channel_id)?
            .child_after(&entry.entry_hash(), None)?
            .is_some();
        super::accepted_into(
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
        if late {
            self.governance_ready = false;
        }
        if let Ok(body) = GovEntry::body_bound_to(entry) {
            if let Some(key) = self.authors.get(&entry.skeleton.author_id) {
                if body.verify(key).is_ok() {
                    self.governance_ready = false;
                    if let GovBody::Presence(presence) = &body {
                        let held =
                            self.presence
                                .entry(entry.skeleton.author_id)
                                .or_insert(Presence {
                                    last: (entry.skeleton.seq, presence.body.here),
                                    back: None,
                                });
                        if entry.skeleton.seq >= held.last.0 {
                            held.last = (entry.skeleton.seq, presence.body.here);
                        }
                        if presence.body.here
                            && held.back.is_none_or(|(seq, _)| seq < entry.skeleton.seq)
                        {
                            held.back = Some((entry.skeleton.seq, entry.skeleton.claimed_ms));
                        }
                    }
                }
            }
        }
        Ok(())
    }
}
