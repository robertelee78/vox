//! A retained private response advances only on actual native receipts. This is continuation
//! state for the common save owner, not another queue, task, lease or retry convention.
use super::*;
use crate::node::history_demand::{Bounds, PrivatePlan};

pub(crate) enum PagePreparation {
    Work(Box<PendingUpgrade>),
    Finished(PageResult),
}
pub(crate) enum PageResult {
    Live(bool),
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
    Done(bool),
}

pub(crate) struct PageFlow {
    peer: Digest32,
    revision: u64,
    authority: TrustNonce,
    page: Page,
    headers: Vec<CheckedRecord>,
    stage: Stage,
    preview: Option<SessionRow>,
    archive: Option<(Bounds, PrivatePlan)>,
    missing: Vec<crate::node::sessionstream::Locator>,
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
            || !channel.drive_members().contains(&peer)
            || page.revision != revision
            || page.query != PrivateQuery::LiveTail
        {
            return Err(Error::StreamRefused(
                "private live request or authority changed",
            ));
        }
        if page.records.is_empty()
            && page.cursor.after > channel.private_recovery_after(&peer, page.cursor.incarnation)
        {
            return Err(Error::StreamRefused(
                "private donor advertised a gap without authenticated records",
            ));
        }
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
        })
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
            || !channel.drive_members().contains(&self.peer)
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
                    channel
                        .private_sessions
                        .observed_tips
                        .insert(self.peer, self.page.cursor.clone());
                    self.stage = Stage::Cached(0);
                }
                Stage::Authenticate(i) => {
                    let wire = std::mem::take(&mut self.page.records[i]);
                    return channel
                        .prepare_pending_private_check(store, owner, wire, false, now)
                        .map(PagePreparation::Work);
                }
                Stage::Cached(i) if i == self.page.records.len() => self.stage = Stage::Cursor,
                Stage::Cached(i) => {
                    return channel
                        .prepare_pending_private_cached(store, owner, self.headers[i].hash, now)
                        .map(PagePreparation::Work);
                }
                Stage::Behind(i) => {
                    let header = &self.headers[i];
                    if header.author_id != channel.me() {
                        let receiver = channel
                            .drive
                            .receivers
                            .get(&(header.author_id, header.chain_id));
                        let behind = receiver.is_none_or(|receiver| {
                            receiver.has_skipped_iterations()
                                || header.iteration != receiver.next_iteration()
                        });
                        if behind {
                            if channel.key_packages.pending_from(&header.author_id)
                                || receiver.is_some()
                            {
                                self.stage = Stage::Done(false);
                            } else {
                                self.stage = Stage::Cached(i + 1);
                            }
                            continue;
                        }
                    }
                    self.stage = Stage::Preview(i);
                }
                Stage::Preview(i) if i == self.page.records.len() => {
                    self.stage = Stage::Done(false)
                }
                Stage::Preview(i) => {
                    if self.archive.is_none()
                        && channel
                            .key_packages
                            .pending_from(&self.headers[i].author_id)
                    {
                        self.stage = Stage::Done(false);
                        continue;
                    }
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
                        if !matches!(
                            channel.session_query(
                                store,
                                Query::Lookup {
                                    node: row.author,
                                    id: row.session_id
                                },
                                1,
                                now.get()
                            ),
                            Ok(Reply::Lookup(Some(_)))
                        ) {
                            self.stage = Stage::Done(false);
                            continue;
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
                    let (_, plan) = self
                        .archive
                        .as_mut()
                        .ok_or(Error::Profile("private inventory plan missing"))?;
                    plan.positions = std::mem::take(&mut self.missing);
                    plan.inventory_done = true;
                    self.stage = Stage::Done(false);
                }
                Stage::Inventory(i) => {
                    return channel
                        .prepare_pending_private_cached(store, owner, self.page.hints[i].hash, now)
                        .map(PagePreparation::Work)
                }
                Stage::Cursor => {
                    if channel.private_sessions.cursors.get(&self.peer) == Some(&self.page.cursor) {
                        self.stage = Stage::Done(false);
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
                            ),
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
                        PageResult::Live(advanced)
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
                self.headers
                    .push(saved.checked_record.take().ok_or(Error::Profile(
                        "private authenticated header receipt missing",
                    ))?);
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
                    None if self.archive.is_none() => Stage::Done(false),
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
                // The native receive includes its original bounded private-expiry sweep.
                if self.archive.is_some() {
                    Stage::Preview(i + 1)
                } else {
                    Stage::Cached(i + 1)
                }
            }
            Stage::Inventory(i) => {
                if !saved
                    .cached
                    .ok_or(Error::Profile("private inventory receipt missing"))?
                {
                    self.missing.push(self.page.hints[i].clone());
                }
                Stage::Inventory(i + 1)
            }
            Stage::Cursor if saved.cursor_committed => Stage::Done(true),
            _ => {
                return Err(Error::Profile(
                    "private page completion does not match its continuation",
                ))
            }
        };
        Ok(())
    }
}
