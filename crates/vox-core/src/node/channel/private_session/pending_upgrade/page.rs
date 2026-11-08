//! A retained private response advances only on actual native receipts. This is continuation
//! state for the common save owner, not another queue, task, lease or retry convention.
use super::*;
use crate::node::history_demand::{Bounds, PrivatePlan};

pub(crate) enum PagePreparation {
    Work(Box<PendingUpgrade>),
    Finished(PageResult),
}
#[derive(Clone, Copy)]
pub(crate) enum LivePageResult {
    Complete(bool),
    ProjectionPending,
}
pub(crate) enum PageResult {
    Live(LivePageResult),
    Archive(PrivatePlan),
}

#[derive(Clone, Copy)]
enum Stage {
    Authenticate(usize),
    Cached(usize),
    Behind(usize),
    Preview(usize),
    Apply(usize),
    Inventory(usize),
    Cursor,
    AutoCursor,
    Done(bool),
}

pub(crate) struct PageFlow {
    peer: Digest32,
    revision: u64,
    authority: TrustNonce,
    page: Page,
    headers: Vec<Option<CheckedRecord>>,
    stage: Stage,
    preview: Option<SessionRow>,
    archive: Option<(Bounds, PrivatePlan)>,
    missing: Vec<crate::node::sessionstream::Locator>,
    blocked: Vec<(Locator, CheckedRecord, Option<Digest32>)>,
    gap: bool,
    gap_stamp: Option<Digest32>,
    opening_basis: Option<Digest32>,
    automatic: Option<AutoSelection>,
    resolved: Vec<Digest32>,
    wanted: Option<BTreeSet<Digest32>>,
    unknown: Option<(u64, u64)>,
}

impl PageFlow {
    pub(crate) fn live(
        channel: &mut ChannelState,
        store: &Store,
        peer: Digest32,
        revision: u64,
        page: Result<Page>,
        now: u64,
        authority: TrustNonce,
    ) -> Result<Self> {
        if revision != channel.private_sessions.revision {
            return Err(Error::StreamRefused(
                "private live request or authority changed",
            ));
        }
        channel.private_sessions.pulling.remove(&peer);
        let page = page?;
        channel.require_governance_ready(store, crate::time::Ms(now))?;
        if channel.poisoned
            || !channel.private_peer_current(store, &peer)?
            || page.revision != revision
            || page.query != PrivateQuery::LiveTail
        {
            return Err(Error::StreamRefused(
                "private live request or authority changed",
            ));
        }
        let previous = channel.private_recovery_after(&peer, page.cursor.incarnation);
        let gap =
            page.more || page.cursor.after.saturating_sub(previous) > page.records.len() as u64;
        if page.records.is_empty() && page.cursor.after > previous {
            let mut restored = !channel
                .validated_member_removals(store, &channel.me(), crate::time::Ms(now))?
                .is_empty();
            if !restored {
                for author in channel.authors.keys() {
                    if !channel
                        .validated_member_removals(store, author, crate::time::Ms(now))?
                        .is_empty()
                    {
                        restored = true;
                        break;
                    }
                }
            }
            if !restored {
                return Err(Error::StreamRefused(
                    "private donor advertised a gap without authenticated records",
                ));
            }
        }
        let overflow_possible = channel
            .private_sessions
            .demands
            .get(&peer)
            .map_or(0, |demand| demand.marks.len())
            .saturating_add(page.records.len())
            > PULL_MARKS_PER_DONOR;
        let unknown_possible = page.records.iter().any(|wire| {
            Record::read(wire).is_ok_and(|record| {
                !channel
                    .authors
                    .contains_key(&record.message.header.author_id)
            })
        });
        let gap_stamp = if gap || overflow_possible || unknown_possible {
            let mut demand = channel
                .private_sessions
                .demands
                .get(&peer)
                .cloned()
                .unwrap_or(PullDemand {
                    incarnation: page.cursor.incarnation,
                    marks: BTreeMap::new(),
                    range: Some((1, page.cursor.after.max(1))),
                    scan_after: None,
                    scan_through: None,
                    pending: Vec::new(),
                    completed_stamp: None,
                    active_stamp: None,
                    successor_stamp: None,
                    unidentified: false,
                    rediscover: false,
                    projection: None,
                    pending_projection: false,
                });
            // Preserve rediscovery's cross-donor mark-list component. A synthetic demand
            // gives completed scans a different stamp from their otherwise unchanged tail.
            demand.range = Some((1, page.cursor.after.max(1)));
            Some(channel.private_refetch_stamp(store, &demand)?)
        } else {
            None
        };
        Ok(Self {
            peer,
            revision,
            authority,
            headers: Vec::with_capacity(page.records.len()),
            page,
            stage: Stage::Authenticate(0),
            preview: None,
            archive: None,
            missing: Vec::new(),
            blocked: Vec::new(),
            gap,
            gap_stamp,
            opening_basis: None,
            automatic: None,
            wanted: None,
            resolved: Vec::new(),
            unknown: None,
        })
    }

    pub(crate) fn archive(
        channel: &ChannelState,
        store: &Store,
        bounds: Bounds,
        plan: PrivatePlan,
        page: Page,
        authority: TrustNonce,
    ) -> Result<Self> {
        let ask = channel.private_history_ask(store, bounds, &plan)?;
        if page.revision != ask.revision || page.query != ask.query {
            return Err(Error::StreamRefused(
                "private history request changed during transfer",
            ));
        }
        channel.index_session_floors(store)?;
        let stage = match &page.query {
            PrivateQuery::ArchiveInventory { .. } => {
                if page.more {
                    return Err(Error::StreamRefused(
                        "private inventory did not finish its fixed interval",
                    ));
                }
                Stage::Inventory(0)
            }
            PrivateQuery::ArchiveRecords { .. } => Stage::Preview(0),
            PrivateQuery::LiveTail => {
                return Err(Error::StreamRefused(
                    "live delivery is not an archive quantum",
                ))
            }
        };
        Ok(Self {
            peer: plan.donor,
            revision: ask.revision,
            authority,
            page,
            stage,
            headers: Vec::new(),
            preview: None,
            archive: Some((bounds, plan)),
            missing: Vec::new(),
            blocked: Vec::new(),
            gap: false,
            gap_stamp: None,
            opening_basis: None,
            automatic: None,
            resolved: Vec::new(),
            wanted: None,
            unknown: None,
        })
    }

    pub(crate) fn automatic(
        channel: &mut ChannelState,
        store: &Store,
        peer: Digest32,
        revision: u64,
        page: Result<Page>,
        now: u64,
        authority: TrustNonce,
    ) -> Result<Self> {
        channel.private_sessions.pulling.remove(&peer);
        let selected = channel
            .private_sessions
            .automatic
            .remove(&peer)
            .ok_or(Error::StreamRefused("private refetch selection missing"))?;
        let page = page?;
        channel.require_governance_ready(store, crate::time::Ms(now))?;
        let (boundary, _) = channel.private_history_scope(store, &peer)?;
        if channel.private_sessions.revision != revision
            || page.revision != revision
            || page.query != selected.query
            || page.cursor.incarnation != selected.cursor.incarnation
            || boundary.incarnation != selected.cursor.incarnation
            || boundary.after < selected.cursor.after
        {
            return Err(Error::StreamRefused("private refetch authority changed"));
        }
        let stage = match &page.query {
            PrivateQuery::ArchiveInventory { .. } if !page.more => Stage::Inventory(0),
            PrivateQuery::ArchiveRecords { .. } => Stage::Authenticate(0),
            _ => return Err(Error::StreamRefused("private refetch response invalid")),
        };
        let wanted = channel
            .private_sessions
            .demands
            .get(&peer)
            .filter(|demand| demand.rediscover && !demand.unidentified && demand.range.is_none())
            .map(|_| {
                channel
                    .private_sessions
                    .demands
                    .values()
                    .flat_map(|demand| demand.marks.keys().copied())
                    .collect()
            });
        Ok(Self {
            peer,
            revision,
            authority,
            page,
            headers: Vec::new(),
            stage,
            preview: None,
            archive: None,
            missing: Vec::new(),
            blocked: Vec::new(),
            opening_basis: None,
            gap: false,
            gap_stamp: None,
            automatic: Some(selected),
            resolved: Vec::new(),
            wanted,
            unknown: None,
        })
    }

    fn projection_overflows(&self, channel: &ChannelState, hash: &Digest32) -> bool {
        let held = channel.private_sessions.demands.get(&self.peer);
        let held_mark = |hash: &Digest32| {
            held.is_some_and(|demand| {
                demand.marks.contains_key(hash) && !self.resolved.contains(hash)
            })
        };
        if held_mark(hash)
            || self
                .blocked
                .iter()
                .any(|(locator, _, _)| locator.hash == *hash)
        {
            return false;
        }
        let occupied = held.map_or(0, |demand| {
            demand
                .marks
                .keys()
                .filter(|hash| !self.resolved.contains(hash))
                .count()
        });
        let fresh = self
            .blocked
            .iter()
            .enumerate()
            .filter(|(index, (locator, _, _))| {
                !held_mark(&locator.hash)
                    && !self.blocked[..*index]
                        .iter()
                        .any(|(prior, _, _)| prior.hash == locator.hash)
            })
            .count();
        occupied + fresh >= PULL_MARKS_PER_DONOR
    }

    /// Called under the short exact-room preparation lock, after asynchronous publication
    /// authority acquisition. Every returned Work uses the same native owner and result wake.
    pub(crate) fn prepare(
        &mut self,
        channel: &mut ChannelState,
        store: &Arc<Store>,
        owner: Arc<()>,
        now: crate::time::Ms,
    ) -> Result<PagePreparation> {
        if channel.private_sessions.revision != self.revision
            || channel.poisoned
            || !channel.private_peer_current(store, &self.peer)?
        {
            return Err(Error::StreamRefused(
                "private live request or authority changed",
            ));
        }
        if let Some((bounds, plan)) = &self.archive {
            // The original immutable interval/grant is revalidated at each continuation.
            channel.private_history_ask(store, *bounds, plan)?;
        }
        loop {
            match self.stage {
                Stage::Authenticate(i) if i == self.page.records.len() => {
                    if self.automatic.is_none() {
                        channel
                            .private_sessions
                            .observed_tips
                            .insert(self.peer, self.page.cursor.clone());
                    }
                    self.stage = Stage::Cached(0);
                }
                Stage::Authenticate(i) => {
                    let wire = std::mem::take(&mut self.page.records[i]);
                    return channel
                        .prepare_pending_private_check(store, owner, wire, false, now)
                        .map(PagePreparation::Work);
                }
                Stage::Cached(i) if i == self.page.records.len() => {
                    self.stage = if self.automatic.is_some() {
                        Stage::AutoCursor
                    } else {
                        Stage::Cursor
                    };
                }
                Stage::Cached(i) => {
                    let Some(header) = self.headers[i] else {
                        self.stage = Stage::Cached(i + 1);
                        continue;
                    };
                    if !header.allowed {
                        self.blocked.push((
                            Locator {
                                id: self.page.positions[i],
                                hash: header.hash,
                            },
                            header,
                            None,
                        ));
                        self.stage = Stage::Cached(i + 1);
                        continue;
                    }
                    return channel
                        .prepare_pending_private_cached(store, owner, header.hash, now)
                        .map(PagePreparation::Work);
                }
                Stage::Behind(i) => {
                    let header = self.headers[i].ok_or(Error::Profile("private header missing"))?;
                    if header.author_id != channel.me()
                        && !channel
                            .drive
                            .receivers
                            .contains_key(&(header.author_id, header.chain_id))
                    {
                        self.blocked.push((
                            Locator {
                                id: self.page.positions[i],
                                hash: header.hash,
                            },
                            header,
                            None,
                        ));
                        self.stage = Stage::Cached(i + 1);
                    } else {
                        self.stage = Stage::Preview(i);
                    }
                }
                Stage::Preview(i) if i == self.page.records.len() => {
                    self.stage = Stage::Done(false)
                }
                Stage::Preview(i) => {
                    let wire = std::mem::take(&mut self.page.records[i]);
                    return channel
                        .prepare_pending_private_check(store, owner, wire, true, now)
                        .map(PagePreparation::Work);
                }
                Stage::Apply(i) => {
                    let row = self
                        .preview
                        .take()
                        .ok_or(Error::Profile("private receive preview missing"))?;
                    if self.archive.is_none()
                        && !crate::node::sessions::is_record(&row.body)
                        && row.session_id != crate::node::drive::KEY_CHANGED
                    {
                        use super::super::super::session_projection::{Query, Reply};
                        let projection = channel
                            .author_opening_fingerprint(store, &row.author)?
                            .unwrap_or(PROJECTION_UNAVAILABLE);
                        match channel.session_query_typed(
                            store,
                            Query::Lookup {
                                node: row.author,
                                id: row.session_id,
                            },
                            1,
                            now.get(),
                        ) {
                            Ok(Reply::Lookup(Some(_))) => {}
                            Ok(Reply::Lookup(None)) => {
                                let header = self.headers[i]
                                    .ok_or(Error::Profile("private header missing"))?;
                                if self.opening_basis.is_none()
                                    && self.projection_overflows(channel, &header.hash)
                                {
                                    let basis = channel
                                        .private_opening_basis(store)?
                                        .unwrap_or(PROJECTION_UNAVAILABLE);
                                    // Capture only on actual overflow. If an opening changed
                                    // after Lookup, do not baseline away its completion edge.
                                    let current = channel
                                        .author_opening_fingerprint(store, &header.author_id)?
                                        .unwrap_or(PROJECTION_UNAVAILABLE);
                                    self.opening_basis = Some(if current == projection {
                                        basis
                                    } else {
                                        PROJECTION_UNAVAILABLE
                                    });
                                }
                                self.blocked.push((
                                    Locator {
                                        id: self.page.positions[i],
                                        hash: header.hash,
                                    },
                                    header,
                                    Some(projection),
                                ));
                                self.stage = Stage::Cached(i + 1);
                                continue;
                            }
                            Ok(_) => {
                                return Err(Error::Profile("private Session lookup reply mismatch"))
                            }
                            Err(failure) if failure.projection_pending() => {
                                return Ok(PagePreparation::Finished(PageResult::Live(
                                    LivePageResult::ProjectionPending,
                                )));
                            }
                            Err(failure) => return Err(failure.into_error()),
                        }
                    }
                    let wire = std::mem::take(&mut self.page.records[i]);
                    return channel
                        .prepare_pending_private_record(
                            store,
                            owner,
                            wire,
                            now,
                            Some(self.authority),
                        )
                        .map(PagePreparation::Work);
                }
                Stage::Inventory(i) if i == self.page.hints.len() => {
                    if self.automatic.is_some() {
                        self.stage = Stage::AutoCursor;
                    } else {
                        let (_, plan) = self
                            .archive
                            .as_mut()
                            .ok_or(Error::Profile("private inventory plan missing"))?;
                        plan.positions = std::mem::take(&mut self.missing);
                        plan.inventory_done = true;
                        self.stage = Stage::Done(false);
                    }
                }
                Stage::Inventory(i) => {
                    return channel
                        .prepare_pending_private_cached(store, owner, self.page.hints[i].hash, now)
                        .map(PagePreparation::Work)
                }
                Stage::Cursor => {
                    let needs_context = self.gap || self.unknown.is_some();
                    let mut restored = needs_context
                        && !channel
                            .validated_member_removals(store, &channel.me(), now)?
                            .is_empty();
                    if needs_context && !restored {
                        for author in channel.authors.keys() {
                            if !channel
                                .validated_member_removals(store, author, now)?
                                .is_empty()
                            {
                                restored = true;
                                break;
                            }
                        }
                    }
                    if self.unknown.is_some() && !restored {
                        self.stage = Stage::Done(false);
                        continue;
                    }
                    let gap = self.gap && restored;
                    let rediscover = !channel.private_sessions.demands.contains_key(&self.peer)
                        && channel.private_sessions.demands.values().any(|d| {
                            !d.marks.is_empty()
                                || d.range.is_some()
                                || d.projection.is_some()
                                || d.unidentified
                        });
                    if !gap
                        && self.unknown.is_none()
                        && !rediscover
                        && self.blocked.is_empty()
                        && channel.private_sessions.cursors.get(&self.peer)
                            == Some(&self.page.cursor)
                    {
                        self.stage = Stage::Done(
                            channel.private_sessions.auto_continue.contains(&self.peer),
                        );
                        continue;
                    }
                    return channel
                        .prepare_pending_private_cursor(
                            store,
                            owner,
                            (
                                self.peer,
                                self.page.cursor.clone(),
                                self.revision,
                                self.authority,
                                std::mem::take(&mut self.blocked),
                                gap,
                                self.unknown.take(),
                                self.gap_stamp,
                                self.opening_basis.unwrap_or(PROJECTION_UNAVAILABLE),
                            ),
                            now,
                        )
                        .map(PagePreparation::Work);
                }
                Stage::AutoCursor => {
                    let selected = self
                        .automatic
                        .as_ref()
                        .ok_or(Error::Profile("private refetch selection missing"))?;
                    return channel
                        .prepare_pending_private_auto_cursor(
                            store,
                            owner,
                            self.peer,
                            self.revision,
                            self.authority,
                            selected,
                            &self.page,
                            std::mem::take(&mut self.missing),
                            std::mem::take(&mut self.blocked),
                            std::mem::take(&mut self.resolved),
                            self.opening_basis.unwrap_or(PROJECTION_UNAVAILABLE),
                            now,
                        )
                        .map(PagePreparation::Work);
                }
                Stage::Done(advanced) => {
                    let result = if let Some((_, mut plan)) = self.archive.take() {
                        if matches!(&self.page.query, PrivateQuery::ArchiveRecords { .. }) {
                            plan.positions.drain(..self.page.records.len());
                        }
                        PageResult::Archive(plan)
                    } else {
                        PageResult::Live(LivePageResult::Complete(advanced))
                    };
                    return Ok(PagePreparation::Finished(result));
                }
            }
        }
    }

    /// Only a matching installed successful capsule reaches here. Its original Result error
    /// terminates the flow instead; no cursor or recovery-plan success can be synthesized.
    pub(crate) fn accept(&mut self, mut saved: Saved) -> Result<()> {
        self.stage = match self.stage {
            Stage::Authenticate(i) => {
                self.page.records[i] = saved
                    .checked_wire
                    .take()
                    .ok_or(Error::Profile("private authentication receipt missing"))?;
                if saved.checked_invalid {
                    if saved.checked_unknown && self.automatic.is_none() {
                        let position = self.page.positions[i];
                        self.unknown = Some(match self.unknown {
                            Some((lo, hi)) => (lo.min(position), hi.max(position)),
                            None => (position, position),
                        });
                    }
                    self.headers.push(None);
                } else {
                    self.headers
                        .push(Some(saved.checked_record.take().ok_or(Error::Profile(
                            "private authenticated header receipt missing",
                        ))?));
                }
                Stage::Authenticate(i + 1)
            }
            Stage::Cached(i) => {
                if saved
                    .cached
                    .ok_or(Error::Profile("private cache receipt missing"))?
                {
                    Stage::Preview(i)
                } else {
                    Stage::Behind(i)
                }
            }
            Stage::Preview(i) => {
                self.page.records[i] = saved
                    .checked_wire
                    .take()
                    .ok_or(Error::Profile("private preview wire missing"))?;
                match saved
                    .preview
                    .take()
                    .ok_or(Error::Profile("private preview receipt missing"))?
                {
                    Some(row) => {
                        self.preview = Some(row);
                        Stage::Apply(i)
                    }
                    None if self.archive.is_none() => {
                        let header =
                            self.headers[i].ok_or(Error::Profile("private header missing"))?;
                        self.blocked.push((
                            Locator {
                                id: self.page.positions[i],
                                hash: header.hash,
                            },
                            header,
                            None,
                        ));
                        Stage::Cached(i + 1)
                    }
                    None => {
                        return Err(Error::StreamRefused(
                            "requested private history key is no longer retained",
                        ))
                    }
                }
            }
            Stage::Apply(i) => {
                saved
                    .received
                    .ok_or(Error::Profile("private record receipt missing"))?;
                if self.automatic.is_some() {
                    let header = self.headers[i].ok_or(Error::Profile("private header missing"))?;
                    self.resolved.push(header.hash);
                }
                // The native receive includes its original bounded private-expiry sweep.
                if self.archive.is_some() {
                    Stage::Preview(i + 1)
                } else {
                    Stage::Cached(i + 1)
                }
            }
            Stage::Inventory(i) => {
                if self
                    .wanted
                    .as_ref()
                    .is_some_and(|wanted| !wanted.contains(&self.page.hints[i].hash))
                {
                    self.stage = Stage::Inventory(i + 1);
                    return Ok(());
                }
                if !saved
                    .cached
                    .ok_or(Error::Profile("private inventory receipt missing"))?
                {
                    self.missing.push(self.page.hints[i].clone());
                } else if self.automatic.is_some() {
                    self.resolved.push(self.page.hints[i].hash);
                }
                Stage::Inventory(i + 1)
            }
            Stage::Cursor if saved.cursor_committed => Stage::Done(true),
            Stage::AutoCursor if saved.cursor_committed => Stage::Done(true),
            _ => {
                return Err(Error::Profile(
                    "private page completion does not match its continuation",
                ))
            }
        };
        Ok(())
    }
}
