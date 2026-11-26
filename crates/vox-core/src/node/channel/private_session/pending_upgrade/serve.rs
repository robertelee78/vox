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
    demands: BTreeMap<Digest32, PullDemand>,
    binding: Digest32,
}

/// One quantum of a connection teller's discovery walk (ruling-private-tip §1, §4): below
/// `before` and above `floor`, the newest retained, unexpired record the serve's own
/// `permitted` would give `peer` now. At most `WORK_ROWS` records and `WORK_BYTES` per quantum.
/// A looking quantum (`write: false`) only reads: it holds no publication ownership and writes
/// nothing; a step that must write (a permission preparation step, the first donor incarnation)
/// is a writing quantum under the room's pending-write ownership.
pub(crate) struct Discovery {
    peer: Digest32,
    holder: bool,
    before: u64,
    floor: u64,
    incarnation: Option<Digest32>,
    cursors: BTreeMap<Digest32, Cursor>,
    demands: BTreeMap<Digest32, PullDemand>,
    binding: Digest32,
    write: bool,
}

impl Discovery {
    /// Only reads (`PendingUpgrade::read_only`).
    pub(super) fn looks(&self) -> bool {
        !self.write
    }
}

/// The most record bytes one discovery quantum reads (`WORK_BYTES`): the capacity its caller
/// admits it under.
pub(crate) const QUANTUM_BYTES: usize = super::super::WORK_BYTES;

/// What one discovery quantum found.
pub(crate) enum Discovered {
    /// The newest record the peer may be served now: the donor-local cursor a Have tells it,
    /// with the removal generation this decision was made under (its write is fenced on it).
    Found(Cursor, u64),
    /// The quantum examined its bound; the walk goes on below this position.
    Below(u64),
    /// Nothing between the floor and the walk's bound may be served to the peer.
    Exhausted,
    /// A permission fact is not known here yet: an author's Session controls not current (any
    /// author's, for the whole walk), or a fact the next record needs. The walk stays at this
    /// position until that fact's own event (`history_stream::private::Wait::Author`). The
    /// author named: the one whose facts are missing.
    Waiting(u64, Digest32),
    /// Every fact the next record's permission needs is here, but its bounded local
    /// preparation has more steps (progress saved): the walk stays at this position and its
    /// teller schedules the next quantum itself.
    Preparing(u64),
}

/// One image request naming this node's own sealed Session record: admitted only for the
/// exact `omp-media` record of `tag` and `media`, and only if the private serving rule below
/// would give `peer` that record now (#1171). Produces no page bytes.
pub(crate) struct MediaAdmission {
    pub(crate) peer: Digest32,
    pub(crate) hash: Digest32,
    pub(crate) holder: bool,
    pub(crate) tag: String,
    pub(crate) media: crate::node::shares::media::Binding,
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
        if self.poisoned.get()
            || self.needs_session_upgrade()
            || ask.room != self.channel_id
            || ask.epoch != self.epoch
            || !self.private_peer_current(store, &peer)?
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
            demands: self.private_sessions.demands.clone(),
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

    /// One quantum of discovery for `peer` (`Discovery`): the same room and peer preconditions
    /// as a served page, then a bounded native step. Every author's Session controls being
    /// current (`index_session_floors`) is checked by the step itself, off the room's lock, so
    /// that an author not current is the fact the walk waits for (`Discovered::Waiting`). A
    /// looking quantum (`write: false`) is only captured: no pending-write ownership, no history
    /// pin; nothing of it is installed. A writing quantum takes the room's pending-write
    /// ownership, which its caller releases before the next quantum.
    pub(crate) fn prepare_pending_private_discovery(
        &mut self,
        store: &Arc<Store>,
        owner: Arc<()>,
        peer: Digest32,
        holders: &BTreeSet<Digest32>,
        (before, floor): (u64, u64),
        write: bool,
    ) -> Result<Box<PendingUpgrade>> {
        self.require_governance_ready(store, crate::time::Ms(self.now_hint))?;
        if self.poisoned.get()
            || self.needs_session_upgrade()
            || !self.private_peer_current(store, &peer)?
        {
            return Err(Error::StreamRefused("private Session room unavailable"));
        }
        let discovery = Discovery {
            peer,
            holder: holders.contains(&peer),
            before,
            floor,
            incarnation: self.private_sessions.incarnation,
            cursors: if self.private_sessions.incarnation.is_none() {
                self.private_sessions.cursors.clone()
            } else {
                BTreeMap::new()
            },
            demands: self.private_sessions.demands.clone(),
            binding: self.private_pull_binding(),
            write,
        };
        let now = crate::time::Ms(self.now_hint);
        if !write {
            return self.capture_private_component(store, now, false, Work::Discover(discovery));
        }
        self.prepare_private_component(store, owner, now, false, Work::Discover(discovery))
    }

    /// The same room/peer preconditions as [`Self::prepare_pending_private_page`].
    pub(crate) fn prepare_pending_private_admission(
        &mut self,
        store: &Arc<Store>,
        owner: Arc<()>,
        admission: MediaAdmission,
    ) -> Result<Box<PendingUpgrade>> {
        self.require_governance_ready(store, crate::time::Ms(self.now_hint))?;
        if self.poisoned.get()
            || self.needs_session_upgrade()
            || !self.private_peer_current(store, &admission.peer)?
        {
            return Err(Error::StreamRefused("private Session room unavailable"));
        }
        self.index_session_floors(store)?;
        self.prepare_private_component(
            store,
            owner,
            crate::time::Ms(self.now_hint),
            false,
            Work::Admit(admission),
        )
    }
}

impl PendingUpgrade {
    /// Serve's `permitted` conjunction for one exact own record (removal generation, removed
    /// members, unexpired, drive holder, unchanged per-recipient `permitted_to`), plus the
    /// record's binding to the image. OMP media is only ever sealed as a private-proof record
    /// (`PendingSession` via `Record::new`); a legacy public entry is never this image's.
    pub(super) fn admit(
        &self,
        store: &Store,
        sek: &Sek,
        admission: &MediaAdmission,
    ) -> Result<bool> {
        governance::check_removal_generation(store, sek, &self.room, self.removal_generation)?;
        if !admission.holder
            || self.removed.contains(&admission.peer)
            || self.removed.contains(&self.me)
        {
            return Ok(false);
        }
        let Some(id) = private_index::find(&store.snapshot()?, sek, &self.room, &admission.hash)?
        else {
            return Ok(false);
        };
        let Some(saved) = self.at(store, sek, id)? else {
            return Ok(false);
        };
        let bound = saved.record.hash() == admission.hash
            && saved.record.legacy_entry().is_none()
            && saved.record.message.header.author_id == self.me
            && !expired(&saved, self.now, self.retention)
            && saved.row.as_ref().is_some_and(|row| {
                row.entry_hash == admission.hash
                    && admission.media.names(row, &self.me, &admission.tag)
            });
        Ok(bound && self.permitted_to(store, sek, &saved.record, &admission.peer)?)
    }

    /// The donor incarnation, created (and saved with the cursors) the first time it is needed:
    /// a bounded local prerequisite of a served page or a found anchor.
    fn served_incarnation(
        &mut self,
        store: &Store,
        sek: &Sek,
        incarnation: Option<Digest32>,
        cursors: &BTreeMap<Digest32, Cursor>,
        demands: &BTreeMap<Digest32, PullDemand>,
        binding: Digest32,
    ) -> Result<Digest32> {
        if let Some(incarnation) = incarnation {
            return Ok(incarnation);
        }
        let mut incarnation = [0; 32];
        getrandom::fill(&mut incarnation).map_err(|_| Error::Rng)?;
        self.save_cursor(
            store,
            sek,
            cursors,
            demands,
            (Some(incarnation), binding),
            (None, None),
        )?;
        self.incarnation = Some(incarnation);
        Ok(incarnation)
    }

    /// One bounded quantum of a teller's discovery walk (`Discovery`). Only the local teller
    /// commissions it; a remote ask never does.
    pub(super) fn discover(
        &mut self,
        store: &Store,
        sek: &Sek,
        discovery: Discovery,
    ) -> Result<Discovered> {
        let Discovery {
            peer,
            holder,
            mut before,
            floor,
            incarnation,
            cursors,
            demands,
            binding,
            write,
        } = discovery;
        governance::check_removal_generation(store, sek, &self.room, self.removal_generation)?;
        if self.removed.contains(&peer) || self.removed.contains(&self.me) {
            return Ok(Discovered::Exhausted);
        }
        // Every author's Session controls current here (`index_session_floors`, the same
        // predicate on the heads and flags captured with this step): an author whose controls
        // are not is the fact this walk waits for, raised as permission news by the step that
        // makes them current (`Work::Controls`, a control-effects admission).
        let read = self.index.read(store, sek, &self.room)?;
        for (author, head) in &self.heads {
            if !control_ready(&read, sek, &self.room, author, *head, self.controls_pending)? {
                return Ok(Discovered::Waiting(before, *author));
            }
        }
        drop(read);
        let mut bytes = 0usize;
        // A writing quantum exists only for the one record whose step must write; the records
        // below it are looked at again by looking quanta.
        let rows = if write { 1 } else { super::super::WORK_ROWS };
        // One snapshot for every locator and record this quantum reads: a record whose
        // locator it selected cannot be expired away between the two reads.
        let snapshot = store.snapshot()?;
        for _ in 0..rows {
            if bytes >= super::super::WORK_BYTES {
                break;
            }
            let Some(id) = private_index::arrival_before(&snapshot, sek, &self.room, Some(before))?
            else {
                return Ok(Discovered::Exhausted);
            };
            if id <= floor {
                return Ok(Discovered::Exhausted);
            }
            // A record gone in this snapshot is not a fact to wait for: it is skipped.
            let Some(saved) = self.at_in(&snapshot, sek, id)? else {
                before = id;
                continue;
            };
            bytes = bytes.saturating_add(saved.record.message.ciphertext.len());
            // The serve's `permitted` conjunction, exactly; a fact not known yet is a wait.
            let allowed = !expired(&saved, self.now, self.retention)
                && (saved.record.message.header.author_id != self.me || holder)
                && match self.permitted_to(store, sek, &saved.record, &peer) {
                    Ok(allowed) => allowed,
                    Err(error) if floor_index::preparing(&error) => {
                        return Ok(Discovered::Preparing(before));
                    }
                    Err(error) if floor_index::refreshing(&error) => {
                        return Ok(Discovered::Waiting(
                            before,
                            saved.record.message.header.author_id,
                        ));
                    }
                    Err(error) => return Err(error),
                };
            // The first donor incarnation is a write: a looking quantum leaves it to a writing
            // one, at this same position.
            if allowed && incarnation.is_none() && !write {
                return Ok(Discovered::Preparing(before));
            }
            if allowed {
                let incarnation =
                    self.served_incarnation(store, sek, incarnation, &cursors, &demands, binding)?;
                return Ok(Discovered::Found(
                    Cursor {
                        incarnation,
                        after: id,
                    },
                    self.removal_generation,
                ));
            }
            before = id;
        }
        Ok(Discovered::Below(before))
    }

    pub(super) fn serve(&mut self, store: &Store, sek: &Sek, serving: Serving) -> Result<Page> {
        let Serving {
            ask,
            peer,
            holder,
            charge,
            incarnation,
            cursors,
            demands,
            binding,
        } = serving;
        governance::check_removal_generation(store, sek, &self.room, self.removal_generation)?;
        if self.removed.contains(&peer) || self.removed.contains(&self.me) {
            return Err(Error::StreamRefused("private Session room unavailable"));
        }
        let incarnation =
            self.served_incarnation(store, sek, incarnation, &cursors, &demands, binding)?;
        let mut page = Page {
            revision: 0,
            removal_generation: Some(self.removal_generation),
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
            PrivateQuery::LiveTail { through } => {
                let seen = if ask.cursor.incarnation == incarnation {
                    ask.cursor.after
                } else {
                    0
                };
                // Only the anchor the peer was told (`through`, from its Have) and the fixed
                // window ending at it; no search. An anchor that is not this donor's, not above
                // the peer's cursor, or no longer servable answers the peer's own cursor, no
                // records and no `more`: nothing about this feed.
                let snapshot = store.snapshot()?;
                let anchored = through.incarnation == incarnation
                    && through.after > seen
                    && match self.at_in(&snapshot, sek, through.after)? {
                        Some(saved) => permitted(&saved)?,
                        None => false,
                    };
                if !anchored {
                    page.cursor = ask.cursor.clone();
                } else {
                    page.cursor.after = through.after;
                    let lower = through.after.saturating_sub(PAGE_RECORDS as u64 - 1).max(1);
                    let mut before = through.after.checked_add(1);
                    for _ in 0..PAGE_RECORDS {
                        let Some(id) =
                            private_index::arrival_before(&snapshot, sek, &self.room, before)?
                        else {
                            break;
                        };
                        if id < lower || id <= seen {
                            break;
                        }
                        before = Some(id);
                        // Gone in this snapshot (expired and swept): nothing to serve.
                        let Some(saved) = self.at_in(&snapshot, sek, id)? else {
                            continue;
                        };
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
            }
            PrivateQuery::ArchiveInventory { lo, hi, before } => {
                if ask.cursor.incarnation != incarnation {
                    return Err(Error::StreamRefused(
                        "private history donor incarnation changed",
                    ));
                }
                let mut before = *before;
                let snapshot = store.snapshot()?;
                for _ in 0..PAGE_RECORDS {
                    let Some(id) =
                        private_index::arrival_before(&snapshot, sek, &self.room, Some(before))?
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
                    // Gone in this snapshot (expired and swept): not listed.
                    let Some(saved) = self.at_in(&snapshot, sek, id)? else {
                        continue;
                    };
                    if permitted(&saved)? {
                        page.hints.push(Locator {
                            id,
                            hash: saved.record.hash(),
                        });
                    }
                }
                page.hints.reverse();
                page.cursor.after = before.max(*lo);
                page.more =
                    private_index::arrival_before(&snapshot, sek, &self.room, Some(before))?
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
