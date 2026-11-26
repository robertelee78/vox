//! Private Sessions on the one loop (ruling correction 2, settled disagreement (b), build order
//! 6). A connection's loop asks its peer the existing Session-stream queries (`LiveTail`,
//! `ArchiveInventory`, `ArchiveRecords`) on the existing Session stream, as one exchange of the
//! loop, chosen from what this node owes that peer: a person's saved private request owed to
//! this donor (its original donor, incarnation, bounds and Drive grant), the durable automatic
//! private debt (marks, ranges, overflow), or the peer's newer private tip from its Have. The
//! page goes to the existing native private admission (`actor::private_save`, `PageFlow`), which
//! keeps every receive check. Nothing here paces, retries or waits on another connection: a
//! refused exchange parks the connection until news (`Connection::refused`), and a step that
//! found nothing to do is not looked at again until the peer's tip or the room's private news
//! changes.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use tokio::sync::oneshot;

use super::pull::{Connection, PrivateOwed};
use super::RequestId;
use crate::error::{Error, Result};
use crate::hash::Digest32;
use crate::node::channel::pending_upgrade::LivePageResult;
use crate::node::channel::{ChannelState, PrivateAsk, RoomSnapshot};
use crate::node::history_budget::{BufferCharge, Job};
use crate::node::history_demand::PrivatePlan;
use crate::node::sessionstream::{self, Ask, Cursor, Page};
use crate::node::status::RoundReason;
use crate::node::store::Store;

/// What the native admission made of a page.
pub(crate) enum Delivered {
    /// Live or automatic: whether the private pull advanced, or its projection is pending.
    Live(LivePageResult),
    /// A saved private request's page: its plan afterwards.
    Archive(PrivatePlan),
}

/// One private page a loop fetched, for the native admission. `archive` names the saved
/// request and the capability it was owed under (`PrivateOwed`: its original binding, bounds,
/// plan as asked and fence); `None` is live or automatic delivery.
pub(crate) struct PrivatePage {
    pub(crate) room: Digest32,
    pub(crate) instance: Arc<crate::node::channel::RoomLock>,
    pub(crate) peer: Digest32,
    pub(crate) revision: u64,
    pub(crate) page: Result<Page>,
    pub(crate) job: Job,
    pub(crate) charge: BufferCharge,
    pub(crate) archive: Option<(RequestId, PrivateOwed)>,
    pub(crate) answer: oneshot::Sender<std::result::Result<Delivered, String>>,
}

/// Where a loop hands its private pages (the actor's native private admission).
pub(crate) type PrivateSink =
    Arc<dyn Fn(PrivatePage) -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + Sync>;

/// One connection's private asking.
#[derive(Default)]
pub(super) struct Asking {
    /// The peer's private anchor with its announcement count, and the room's private news, at
    /// which the last look found no automatic or live work, or whose exchange advanced nothing:
    /// not looked at again until either changes. A same-number re-announcement is news too.
    quiet: Option<(Option<(Cursor, u64)>, u64)>,
    /// The room could not decide at the last look (`PrivateAsk::Undecided`: its governance,
    /// floors or the peer's Session controls refreshing): the publication it looked under. A
    /// later publication, which is where the room decides, ends the quiet (`undecided`).
    undecided: Option<Arc<RoomSnapshot>>,
    /// The last automatic-or-live exchange was a live tail: the next prefers old debt.
    live_last: bool,
    /// A private exchange just ran: the public plan has the next turn.
    pub(super) yielded: bool,
}

impl Asking {
    /// The last look could not decide: the loop's next publication is news for it.
    pub(super) fn undecided(&self) -> bool {
        self.undecided.is_some()
    }
}

fn gone() -> Error {
    Error::Unreachable("connection ended")
}

/// One private exchange of this connection, if one is owed. `Ok(true)`: an exchange ran.
/// `Err`: the peer refused or failed it (the caller parks the connection until news).
pub(super) async fn ask(c: &Connection, state: &mut Asking) -> Result<bool> {
    if let Some((request, owed)) = c.frontier.private_owed(c.room, c.peer) {
        archive(c, request, owed).await?;
        return Ok(true);
    }
    let tip = c.holdings.private_tip(c.room, c.peer, c.conn.serial());
    let at = (tip.clone(), c.frontier.private_news(c.room));
    let published = c.cell.current();
    let republished = state
        .undecided
        .as_ref()
        .is_some_and(|was| !published.as_ref().is_some_and(|now| Arc::ptr_eq(was, now)));
    if state.quiet.as_ref() == Some(&at) && !republished {
        return Ok(false);
    }
    let (peer, prefer_live, told) = (c.peer, !state.live_last, tip);
    let chosen = locked(c, move |room, store| {
        room.select_private_ask(
            store,
            peer,
            told.as_ref().map(|(anchor, _)| anchor),
            prefer_live,
        )
    })
    .await?;
    let ask = match chosen {
        PrivateAsk::Ask(ask) => ask,
        PrivateAsk::Nothing => {
            state.quiet = Some(at);
            state.undecided = None;
            return Ok(false);
        }
        PrivateAsk::Undecided => {
            state.quiet = Some(at);
            state.undecided = published;
            return Ok(false);
        }
    };
    state.undecided = None;
    let automatic = ask.query.archive();
    state.live_last = !automatic;
    let revision = ask.revision;
    // The peer's answer arrives in this connection's own memory; shared admission (a job and
    // the page's capacity) is taken only for the local work that follows (Amendment 3).
    let fetched = match fetch(c, &ask).await {
        Err(error) if !automatic => return Err(error),
        fetched => fetched,
    };
    let (job, charge, page_charge) = charges(c).await?;
    let (page, refused) =
        match fetched.and_then(|bytes| sessionstream::read_page(ask, &bytes, page_charge)) {
            Ok(page) => (Ok(page), None),
            // A failed automatic step is still handed to the native admission, which records the
            // attempt against its evidence (the step stays owed, `prepare_pending_private_auto_failure`).
            Err(error) if automatic => (Err(again(&error)), Some(error)),
            Err(error) => return Err(error),
        };
    let delivered = deliver(c, revision, page, job, charge, None).await;
    if let Some(error) = refused {
        return Err(error);
    }
    match delivered {
        Ok(Delivered::Live(LivePageResult::Complete(true))) => {
            c.answered(RoundReason::Hint, true);
        }
        Ok(_) => {
            c.answered(RoundReason::Hint, false);
            state.quiet = Some(at);
        }
        Err(reason) => {
            if c.fence.is_retired() {
                return Err(gone());
            }
            crate::node::status::SyncBook::with(&c.book, c.room, c.peer, |status| {
                status.note_failure(reason);
            });
            state.quiet = Some(at);
        }
    }
    Ok(true)
}

/// One page of a person's saved private request, asked of its original donor only: the ask is
/// built and checked by the unchanged `private_history_ask` (donor current, same incarnation,
/// same Drive grant, interval within the donor's boundary). What no longer authorizes it stops
/// the request (paused for the person); a refusal by the donor parks the connection and the
/// request stays owed.
async fn archive(c: &Connection, request: RequestId, owed: PrivateOwed) -> Result<()> {
    let asked = {
        let (bounds, plan) = (owed.bounds, owed.plan.clone());
        locked(c, move |room, store| {
            room.private_history_ask(store, bounds, &plan)
        })
        .await
    };
    let ask = match asked {
        Ok(ask) => ask,
        Err(error) if c.fence.is_retired() => return Err(error),
        Err(error) => {
            c.frontier.private_stopped(request, error.to_string());
            return Ok(());
        }
    };
    let revision = ask.revision;
    let bytes = fetch(c, &ask).await?;
    let (job, charge, page_charge) = charges(c).await?;
    let page = sessionstream::read_page(ask, &bytes, page_charge)?;
    drop(bytes);
    match deliver(c, revision, Ok(page), job, charge, Some((request, owed))).await {
        Ok(Delivered::Archive(next)) => {
            c.answered(RoundReason::Page, true);
            c.frontier.private_progress(request, next);
        }
        Ok(Delivered::Live(_)) => c
            .frontier
            .private_stopped(request, "private history page kind changed".into()),
        Err(_) if c.fence.is_retired() => return Err(gone()),
        Err(reason) => c.frontier.private_stopped(request, reason),
    }
    Ok(())
}

/// One bounded local step under the room's lock, off the async runtime.
async fn locked<T: Send + 'static>(
    c: &Connection,
    work: impl FnOnce(&mut ChannelState, &Store) -> Result<T> + Send + 'static,
) -> Result<T> {
    let room = tokio::select! {
        biased;
        () = c.fence.retired() => return Err(gone()),
        room = Arc::clone(&c.shared).lock_owned() => room,
    };
    let store = Arc::clone(&c.store);
    tokio::task::spawn_blocking(move || {
        let mut room = room;
        work(&mut room, &store)
    })
    .await
    .map_err(|_| Error::Unreachable("private Session step stopped"))?
}

/// What tells a connection's teller its last decision may no longer stand: the room's
/// permission-change serial (`Frontier::private_permission`: membership, removal, standing,
/// keyring Drive holders, this node's own floors, an author's Session controls becoming
/// current, a completed preparation) and the private permission generation the room's last
/// publication read (every committed Session floor or floor source,
/// `RoomSnapshot::private_permission`).
pub(super) type Serial = (u64, Option<u64>);

/// The one fact a waiting walk waits for, named by the look that could not decide without it;
/// another serial ends every wait. Each keeps the publication it compares against, so an
/// address it watches cannot be reused while it waits.
enum Wait {
    /// The room could not decide at all: its governance refreshing, its Session upgrade work
    /// running, the keyring or the roster moving under the look (`RoomSnapshot::private_peer`
    /// undecided, or a look refused). It resumes at the first later publication that can
    /// decide: the step that ends a refresh commits and publishes the room.
    Room(Arc<RoomSnapshot>),
    /// A permission fact of `author`'s records is not here: its Session controls current (an
    /// event, raised as permission news by the step that makes them current), a floor source
    /// (the floor generation), or a fact its own next entries bring (that author's held history
    /// moving; untouched authors' rows are shared between publications). A new private record
    /// (another tip than this one) resumes it too, as before this wait was named.
    Author(Digest32, u64, Arc<RoomSnapshot>),
}

/// Where `author`'s row of this held history is: it moves only when a commit touched that
/// author (`HeldHistory` shares untouched rows).
fn watched(snapshot: &RoomSnapshot, author: &Digest32) -> usize {
    snapshot
        .history()
        .and_then(|history| history.author(author))
        .map_or(0, |row| std::ptr::from_ref(row) as usize)
}

/// One pass of the discovery walk under `serial`: from `upper` (exclusive: this node's private
/// tip when it began) down to `floor` (exclusive), next below `before`.
struct Pass {
    serial: Serial,
    upper: u64,
    before: u64,
    floor: u64,
}

/// An anchor a pass found, to tell: the donor-local cursor, the authority its native decision
/// ran under (the Have's write is fenced on it) and the serial of that pass.
pub(super) struct Tell {
    pub(super) anchor: Cursor,
    pub(super) authority: sessionstream::Authority,
    serial: Serial,
}

/// One connection's teller of this node's private Sessions (ruling-private-tip §1-§5). What it
/// tells its peer is computed at use, by a resumable walk of bounded native quanta
/// (`actor::private_serve::discover`: the serve's own per-record check). It keeps only the
/// walk's disposable progress, what the last finished pass covered and under which serial, a
/// dirty flag and what it last told; no permission result.
#[derive(Default)]
pub(super) struct Telling {
    pass: Option<Pass>,
    /// The last finished pass: positions below this bound were walked under this serial.
    walked: Option<(Serial, u64)>,
    /// News came while a pass ran: decide after it whether another is due.
    dirty: bool,
    /// The anchor last told and the serial of the pass that found it.
    told: Option<(Cursor, Serial)>,
    /// A quantum found the room's publication (or a policy transition) held: its release edge,
    /// subscribed before that attempt.
    held: Option<Pin<Box<dyn Future<Output = ()> + Send>>>,
    /// The walk waits for one named fact (`Wait`) and the serial it waits under.
    waiting: Option<(Serial, Wait)>,
    /// The serial, this node's private tip and the room publication the last wake saw.
    seen: Option<(Serial, u64, Arc<RoomSnapshot>)>,
    /// A found anchor not yet written to the peer (its connection could not write).
    unsent: Option<Tell>,
    /// The last quantum stopped at a record whose permission needed more local preparation:
    /// the next quantum runs at once, and the one that decides that record completed it.
    preparing: bool,
}

impl Telling {
    /// The peer may be told nothing now (not eligible, or this node locked): the walk is
    /// forgotten; the next eligible look starts from the newest record.
    pub(super) fn reset(&mut self) {
        *self = Self::default();
    }

    /// The room cannot decide now (`RoomSnapshot::private_peer` undecided: its governance
    /// refreshing, its Session upgrade work running). The walk keeps its progress, what it told
    /// and any fact it already waits for; it takes no step and tells nothing, and resumes once
    /// at the first later publication that can decide (`news`).
    pub(super) fn undecided(&mut self, serial: Serial, snapshot: &Arc<RoomSnapshot>) {
        if self.waiting.is_none() {
            self.waiting = Some((serial, Wait::Room(Arc::clone(snapshot))));
        }
    }

    /// A wake of the teller with this node's private tip, the serial and the room publication
    /// now, which can decide. Only three things start a walk: the connection's first look, a
    /// tip above what was walked, and another serial; a publication that changed none of them
    /// starts and restarts nothing. A waiting walk moves again only at its fact's own event
    /// (`Wait`) or another serial. A running pass goes on (a change is coalesced, `dirty`).
    /// Under an unchanged serial only arrivals above the last pass's bound are walked
    /// (positions below it were walked under the same permission facts); a changed serial
    /// walks again from the newest record down, and an anchor found under the old one is
    /// decided again rather than written. A room with no private record walks nothing.
    pub(super) fn news(&mut self, tip: &Cursor, serial: Serial, snapshot: &Arc<RoomSnapshot>) {
        if let Some((at, wait)) = &self.waiting {
            let ended = *at != serial
                || match wait {
                    Wait::Room(was) => !Arc::ptr_eq(was, snapshot),
                    Wait::Author(author, was_tip, was) => {
                        *was_tip != tip.after || watched(snapshot, author) != watched(was, author)
                    }
                };
            if ended {
                self.waiting = None;
            }
        }
        if self
            .unsent
            .as_ref()
            .is_some_and(|tell| tell.serial != serial)
        {
            self.unsent = None;
        }
        self.seen = Some((serial, tip.after, Arc::clone(snapshot)));
        let upper = tip.after.saturating_add(1);
        if let Some(pass) = &self.pass {
            self.dirty |= upper > pass.upper || serial != pass.serial;
            return;
        }
        self.dirty = false;
        // No private record was ever stored here: nothing to walk, no native step.
        if tip.after == 0 {
            self.walked = Some((serial, upper));
            return;
        }
        let floor = match &self.walked {
            Some((walked, bound)) if *walked == serial => {
                if upper <= *bound {
                    return;
                }
                bound.saturating_sub(1)
            }
            _ => 0,
        };
        self.pass = Some(Pass {
            serial,
            upper,
            before: upper,
            floor,
        });
    }

    /// The walk now waits, under the serial last seen, for the fact `wait` names.
    fn wait(&mut self, wait: impl FnOnce(u64, Arc<RoomSnapshot>) -> Wait) {
        if let Some((serial, tip, snapshot)) = &self.seen {
            self.waiting = Some((*serial, wait(*tip, Arc::clone(snapshot))));
        }
    }

    /// Run the walk's next quantum, if one may run now; a found anchor waits in `unsent` until
    /// the Have writes it (`take`).
    pub(super) async fn advance(&mut self, c: &Connection) -> Result<()> {
        if let Some(tell) = self.step(c).await? {
            self.unsent = Some(tell);
        }
        Ok(())
    }

    /// The found anchor to write now, if any.
    pub(super) fn take(&mut self) -> Option<Tell> {
        self.unsent.take()
    }

    /// The anchor could not be written: it waits for the connection's next write.
    pub(super) fn unsent(&mut self, tell: Tell) {
        self.unsent.get_or_insert(tell);
    }

    /// One native quantum of the running pass, when it may run: at most `WORK_ROWS` records
    /// and `WORK_BYTES`, under its own job and capacity, which end with it. It only looks (takes
    /// no room publication ownership) unless the last quantum stopped at a step that must write
    /// (`preparing`): then this one is a writing quantum at the same position. What it found,
    /// if the peer was not already told it under the same serial.
    async fn step(&mut self, c: &Connection) -> Result<Option<Tell>> {
        if self.held.is_some() || self.waiting.is_some() {
            return Ok(None);
        }
        let Some(pass) = self.pass.as_mut() else {
            return Ok(None);
        };
        let admitted = admit(c, crate::node::channel::pending_upgrade::QUANTUM_BYTES).await?;
        let quantum = crate::node::actor::private_discover(
            &c.serving,
            c.peer,
            (c.room, c.epoch),
            (pass.before, pass.floor),
            self.preparing,
            admitted,
        )
        .await;
        use crate::node::actor::PrivateQuantum as Quantum;
        let prepared = std::mem::take(&mut self.preparing);
        // A record whose preparation the previous quantum left unfinished is decided now: the
        // prerequisite completed, which is permission news for every teller of the room
        // (`Frontier::private_permission`).
        let completed = || {
            if prepared {
                c.frontier.private_permission(c.room);
            }
        };
        match quantum {
            Ok(Quantum::Below(at)) => {
                completed();
                pass.before = at;
            }
            // A step that must write (a permission preparation step with progress to save, or
            // the first donor incarnation): the walk stays at this position and its next
            // quantum, a writing one, runs at once (`ready`), after this one let go of its
            // admission; cancellation and a waiting own post are observed before it, as before
            // every quantum.
            Ok(Quantum::Preparing(at)) => {
                pass.before = at;
                self.preparing = true;
            }
            // A fact of `author`'s records is missing here (its Session controls current, a
            // floor source, a causal fact): the walk waits for that fact's own event.
            Ok(Quantum::Waiting(at, author)) => {
                pass.before = at;
                self.wait(|tip, snapshot| Wait::Author(author, tip, snapshot));
            }
            Ok(Quantum::Held(released)) => {
                self.preparing = prepared;
                self.held = Some(released);
            }
            Ok(Quantum::Exhausted) => {
                completed();
                self.finish();
            }
            Ok(Quantum::Found(anchor, authority)) => {
                completed();
                let serial = pass.serial;
                self.finish();
                if self.told.as_ref() != Some(&(anchor.clone(), serial)) {
                    return Ok(Some(Tell {
                        anchor,
                        authority,
                        serial,
                    }));
                }
            }
            Err(_) if c.fence.is_retired() => return Err(gone()),
            // Not decided now: the room refused the look (its governance refreshing under it,
            // the roster, keyring or at-rest lock moving) or a store fault. The walk stays
            // where it is and moves at the first later publication that can decide, or another
            // serial; nothing is concluded.
            Err(_) => self.wait(|_, snapshot| Wait::Room(snapshot)),
        }
        Ok(None)
    }

    /// The found anchor was written to the peer.
    pub(super) fn told(&mut self, tell: Tell) {
        self.told = Some((tell.anchor, tell.serial));
    }

    fn finish(&mut self) {
        if let Some(pass) = self.pass.take() {
            self.walked = Some((pass.serial, pass.upper));
        }
    }

    /// Resolves when the walk can take its next step without other news: a held quantum's
    /// release, or, while it waits for no fact, a running pass or news coalesced during the
    /// last pass. Otherwise never; the teller's other wakes bring news.
    pub(super) async fn ready(&mut self) {
        if let Some(released) = self.held.as_mut() {
            released.await;
            self.held = None;
            return;
        }
        if self.waiting.is_none() && (self.pass.is_some() || self.dirty) {
            return;
        }
        std::future::pending().await
    }
}

/// Local work's shared admission (a job and `bytes` of capacity), waited for on this
/// connection only and never across a network wait.
async fn admit(c: &Connection, bytes: usize) -> Result<(Job, BufferCharge)> {
    loop {
        let job = c.job().await?;
        match job.reserve_or_pressure_with_headroom(bytes, bytes) {
            Ok(charge) => return Ok((job, charge)),
            Err(Error::HistoryCapacity(pressure)) => {
                drop(job);
                tokio::select! {
                    biased;
                    () = c.fence.retired() => return Err(gone()),
                    () = pressure.released() => {}
                }
            }
            Err(error) => return Err(error),
        }
    }
}

/// The page's checking and its later room/store application work, admitted together
/// (`sessionstream::CURRENT_PAGE_ENVELOPE`) once the answer is in: local capacity, waited for
/// on this connection only.
async fn charges(c: &Connection) -> Result<(Job, BufferCharge, BufferCharge)> {
    let (job, mut work) = admit(c, sessionstream::CURRENT_PAGE_ENVELOPE).await?;
    let page = work
        .split_off(sessionstream::PAGE_ENVELOPE)
        .ok_or(Error::Profile(
            "private page reservation is smaller than its page envelope",
        ))?;
    Ok((job, work, page))
}

/// The exchange: the existing Session-stream ask and its bounded answer, unchecked.
async fn fetch(c: &Connection, ask: &Ask) -> Result<Vec<u8>> {
    tokio::select! {
        biased;
        () = c.fence.retired() => Err(gone()),
        bytes = sessionstream::pull(&c.conn, ask) => bytes,
    }
}

/// Hand the page to the native private admission and wait for what it made of it.
async fn deliver(
    c: &Connection,
    revision: u64,
    page: Result<Page>,
    job: Job,
    charge: BufferCharge,
    archive: Option<(RequestId, PrivateOwed)>,
) -> std::result::Result<Delivered, String> {
    let (answer, wait) = oneshot::channel();
    (c.private)(PrivatePage {
        room: c.room,
        instance: Arc::clone(&c.shared),
        peer: c.peer,
        revision,
        page,
        job,
        charge,
        archive,
        answer,
    })
    .await;
    tokio::select! {
        biased;
        () = c.fence.retired() => Err("connection ended".into()),
        done = wait => done.unwrap_or_else(|_| Err("private Session admission stopped".into())),
    }
}

/// The same failure, for the native admission's record of an automatic step's attempt (the
/// original goes to the connection's refusal).
fn again(error: &Error) -> Error {
    match error {
        Error::Unreachable(why) => Error::Unreachable(why),
        Error::StreamRefused(why) => Error::StreamRefused(why),
        Error::PeerRefused(code) => Error::PeerRefused(*code),
        Error::MalformedBundle(why) => Error::MalformedBundle(why),
        Error::SizeLimitExceeded(why) => Error::SizeLimitExceeded(why),
        _ => Error::Unreachable("private Session donor did not answer"),
    }
}
