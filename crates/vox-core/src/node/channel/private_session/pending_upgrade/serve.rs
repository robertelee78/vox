//! Private serving uses the same compact permission view as receive/replay. Continuity and
//! the first donor incarnation save run on the native owner, never under the room lock.
use super::*;
use crate::node::history_budget::BufferCharge;
use crate::node::sessionstream::{MAX_PAGE, MAX_RECORD, PAGE_OVERHEAD, PAGE_RECORDS};

pub(super) struct Serving {
    ask: Ask,
    peer: Digest32,
    holder: bool,
    charge: BufferCharge,
    incarnation: Option<Digest32>,
    cursors: BTreeMap<Digest32, Cursor>,
    binding: Digest32,
}

impl ChannelState {
    pub(crate) fn prepare_pending_private_page(
        &mut self,
        store: &Arc<Store>,
        owner: Arc<()>,
        ask: Ask,
        peer: Digest32,
        holders: &BTreeSet<Digest32>,
        charge: BufferCharge,
    ) -> Result<Box<PendingUpgrade>> {
        self.require_governance_ready(store, crate::time::Ms(self.now_hint))?;
        if self.poisoned
            || self.needs_session_upgrade()
            || ask.room != self.channel_id
            || ask.epoch != self.epoch
            || !self.drive_members().contains(&peer)
        {
            return Err(Error::StreamRefused("private Session room unavailable"));
        }
        self.index_session_floors(store)?;
        let serving = Serving {
            ask,
            peer,
            holder: holders.contains(&peer),
            charge,
            incarnation: self.private_sessions.incarnation,
            cursors: if self.private_sessions.incarnation.is_none() {
                self.private_sessions.cursors.clone()
            } else {
                BTreeMap::new()
            },
            binding: self.private_pull_binding(),
        };
        self.prepare_private_component(
            store,
            owner,
            crate::time::Ms(self.now_hint),
            false,
            Work::Serve(serving),
        )
    }
}

impl PendingUpgrade {
    pub(super) fn serve(&mut self, store: &Store, sek: &Sek, serving: Serving) -> Result<Page> {
        let Serving {
            ask,
            peer,
            holder,
            charge,
            incarnation,
            cursors,
            binding,
        } = serving;
        let incarnation = match incarnation {
            Some(incarnation) => incarnation,
            None => {
                let mut incarnation = [0; 32];
                getrandom::fill(&mut incarnation).map_err(|_| Error::Rng)?;
                self.save_cursor(store, sek, &cursors, Some(incarnation), binding, None)?;
                self.incarnation = Some(incarnation);
                incarnation
            }
        };
        let mut page = Page {
            revision: 0,
            query: ask.query,
            cursor: Cursor {
                incarnation,
                after: 0,
            },
            more: false,
            records: Vec::new(),
            positions: Vec::new(),
            hints: Vec::new(),
            charge,
        };
        let mut wire_bytes = PAGE_OVERHEAD;
        let permitted = |saved: &Stored| -> Result<bool> {
            Ok(!expired(saved, self.now, self.retention)
                && (saved.record.message.header.author_id != self.me || holder)
                && self.permitted_to(store, sek, &saved.record, &peer)?)
        };
        match &page.query {
            PrivateQuery::LiveTail => {
                let tip = self.progress.next.saturating_sub(1);
                page.cursor.after = tip;
                let lower = tip.saturating_sub(PAGE_RECORDS as u64 - 1).max(1);
                let seen = if ask.cursor.incarnation == incarnation {
                    ask.cursor.after
                } else {
                    0
                };
                let mut before = tip.checked_add(1);
                for _ in 0..PAGE_RECORDS {
                    let Some(id) =
                        private_index::arrival_before(&store.snapshot()?, sek, &self.room, before)?
                    else {
                        break;
                    };
                    if id < lower || id <= seen {
                        break;
                    }
                    before = Some(id);
                    let saved = self
                        .at(store, sek, id)?
                        .ok_or(Error::MalformedAtRest("private live locator missing"))?;
                    if !permitted(&saved)? {
                        continue;
                    }
                    let wire = saved.record.wire();
                    if wire.len() > MAX_RECORD {
                        return Err(Error::SizeLimitExceeded("private Session record"));
                    }
                    if wire_bytes + wire.len() + 16 > MAX_PAGE {
                        page.more = true;
                        break;
                    }
                    wire_bytes += wire.len() + 16;
                    page.positions.push(id);
                    page.records.push(wire);
                }
                page.positions.reverse();
                page.records.reverse();
                page.more |= lower > seen.saturating_add(1);
            }
            PrivateQuery::ArchiveInventory { lo, hi, before } => {
                if ask.cursor.incarnation != incarnation {
                    return Err(Error::StreamRefused(
                        "private history donor incarnation changed",
                    ));
                }
                let mut before = *before;
                for _ in 0..PAGE_RECORDS {
                    let Some(id) = private_index::arrival_before(
                        &store.snapshot()?,
                        sek,
                        &self.room,
                        Some(before),
                    )?
                    else {
                        break;
                    };
                    if id < *lo {
                        break;
                    }
                    if id > *hi {
                        return Err(Error::MalformedBundle("private history interval widened"));
                    }
                    before = id;
                    let saved = self
                        .at(store, sek, id)?
                        .ok_or(Error::MalformedAtRest("private history locator missing"))?;
                    if permitted(&saved)? {
                        page.hints.push(Locator {
                            id,
                            hash: saved.record.hash(),
                        });
                    }
                }
                page.hints.reverse();
                page.cursor.after = before.max(*lo);
                page.more = private_index::arrival_before(
                    &store.snapshot()?,
                    sek,
                    &self.room,
                    Some(before),
                )?
                .is_some_and(|id| id >= *lo && id <= *hi);
            }
            PrivateQuery::ArchiveRecords { positions, .. } => {
                if ask.cursor.incarnation != incarnation {
                    return Err(Error::StreamRefused(
                        "private history donor incarnation changed",
                    ));
                }
                for position in positions {
                    let saved = self
                        .at(store, sek, position.id)?
                        .ok_or(Error::StreamRefused(
                            "requested private history is no longer retained",
                        ))?;
                    if saved.record.hash() != position.hash || !permitted(&saved)? {
                        return Err(Error::StreamRefused(
                            "requested private history is not authorized",
                        ));
                    }
                    let wire = saved.record.wire();
                    if wire.len() > MAX_RECORD {
                        return Err(Error::SizeLimitExceeded("private Session record"));
                    }
                    if wire_bytes + wire.len() + 16 > MAX_PAGE {
                        page.more = true;
                        break;
                    }
                    wire_bytes += wire.len() + 16;
                    page.cursor.after = position.id;
                    page.positions.push(position.id);
                    page.records.push(wire);
                }
            }
        }
        Ok(page)
    }
}
