//! Public fetching (design simple-sync §1): each side of a connection tells the other what it
//! holds (a Have, on connect and again only when it changes), and one loop per connection asks
//! that peer, one Range bundle at a time, for what this node owes and the peer holds. Nothing
//! here runs on a timer and no loop waits on another connection: a loop waits only for its own
//! peer, for this node's own verified changes, or for the connection to end.
//!
//! What a node owes is never derived from what peers say: it is the floor and debt of each
//! author's walk, the positions its saved archive intents cover, and the exact needs the node's
//! admission frontier recorded. A loop plans
//! from three things in memory only: the peer's last Have, the room's published record of what
//! this node holds (`channel::held_history`), and the frontier. A peer's Have only says where
//! to ask; a holder's answer corrects it.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex as StdMutex};

use crate::error::{Error, Result};
use crate::hash::Digest32;
use crate::log::entry::Entry;
use crate::log::history::{SignedEntryKind, SignedHead, MAX_PAGE_ENTRIES};
use crate::node::channel::held_history::{self, HeldAuthor, HeldHistory, Runs};
use crate::node::channel::history::PendingHistoryRead;
use crate::node::channel::{
    ChannelState, PinnedHistory, RoomSnapshot, RoomSnapshotCell, ServedRoom,
};
use crate::node::history_budget::{Budget, Lane};
use crate::node::store::Store;
use crate::transport::quic::VoxConnection;
use crate::transport::stream_transport::Fence;

use super::bundle::{self, Partial};
use super::transport::{Private, Read};
use super::{AuthorHave, Frame, Preamble, Purpose, Query, RangeWant, Status};

fn lock<T>(mutex: &StdMutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Mutant arms (test-knobs only; ADR-054's settle table M2, M3, M13): whether the named
/// `VOX_MUTANT_*` switch is set. The first time it is read set, says `vox: <name> engaged`.
#[cfg(feature = "test-knobs")]
pub(super) fn mutant(name: &'static str) -> bool {
    static SAID: StdMutex<BTreeSet<&'static str>> = StdMutex::new(BTreeSet::new());
    let on = std::env::var_os(name).is_some();
    if on && lock(&SAID).insert(name) {
        eprintln!("vox: {name} engaged");
    }
    on
}

/// M2's one request in flight per node (`VOX_MUTANT_ONE_ASK_PER_NODE`).
#[cfg(feature = "test-knobs")]
static ONE_ASK: std::sync::LazyLock<tokio::sync::Mutex<()>> =
    std::sync::LazyLock::new(|| tokio::sync::Mutex::new(()));

// ---------------------------------------------------------------------------------------------
// What a peer said it holds.

/// One peer's Have of one author, as it last said it or corrected it in an answer.
#[derive(Clone, Debug, Default)]
pub(crate) struct PeerAuthor {
    /// `(head id, size, signed head bytes)`, unverified until this node observes them.
    pub(crate) heads: Vec<(Digest32, u64, Vec<u8>)>,
    /// The head it serves under, `(id, size)`: its committed one.
    pub(crate) committed: Option<(Digest32, u64)>,
    /// Its heads were observed here ([`observe`]), and its committed head is held here: once
    /// per Have.
    observed: bool,
    head: Option<Arc<SignedHead>>,
    pub(crate) proof: Vec<(u64, u64)>,
    pub(crate) bodies: Vec<(u64, u64)>,
    pub(crate) controls: Vec<(u64, u64)>,
    /// MP-9: the peer holds a verified fork proof of the author (a reason to ask it for the
    /// proof, never evidence).
    fork: bool,
    /// MP-9 (rule 6): the peer's kept head of the author whose continuity with its accepted
    /// chain is unresolved, `(id, size)` (a reason to ask it by id, never a committed head).
    unresolved: Option<(Digest32, u64)>,
    /// The peer's role-complete head of the author, `(id, size)`: a reason for the author to
    /// ask the exact receipt, never one itself.
    role: Option<(Digest32, u64)>,
    /// MP-9: what this peer's Have makes this node ask it next about the author, read with its
    /// heads in [`observe`] and taken by the next ask (`Holdings::take_listing`).
    listing: Option<Listing>,
    /// MP-9: the last listing taken for this peer and author. The same step is not asked again
    /// while the peer lists the same fork and unresolved head: it is asked once per thing
    /// listed, and again only when what the peer lists or this node's comparison changed.
    listed: Option<Listing>,
}

/// MP-9: one ask a peer's Have makes this node owe that peer: its fork proof of an author, its
/// unresolved head by id, or the next opening or proof comparing a second signed head with the
/// accepted one, asked as a Range under the head it names.
#[derive(Clone, Debug)]
enum Listing {
    Object(Query),
    Range {
        head: Arc<SignedHead>,
        anchor: u64,
        want: RangeWant,
    },
}

impl PartialEq for Listing {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Object(a), Self::Object(b)) => a == b,
            (
                Self::Range { head, anchor, want },
                Self::Range {
                    head: h,
                    anchor: a,
                    want: w,
                },
            ) => head.id() == h.id() && anchor == a && want == w,
            _ => false,
        }
    }
}

/// What [`observe`] read of a peer's row to decide what to stage and ask: its heads' ids, its
/// committed head, and what it lists of a fork proof (the proof's identity) or of an unresolved
/// head (its id). The row is marked observed only while it still says this.
#[derive(Clone, Debug)]
struct Inspected {
    ids: Vec<Digest32>,
    committed: Option<(Digest32, u64)>,
    fork: bool,
    unresolved: Option<Digest32>,
}

/// The identity in an `unresolved` slot: a listed fork proof's digest, or an unresolved head's
/// id. Its second half (the proof's advertised position, the head's size) is never compared:
/// the digest commits to the proof's two entries, the id to the head, so a peer that changes
/// only that half says nothing new, and buys no ask (the fork rule, [`FORK_ASKS`]).
fn slot_id(slot: Option<(Digest32, u64)>) -> Option<Digest32> {
    slot.map(|(id, _)| id)
}

impl PeerAuthor {
    /// What [`observe`] reads of this row ([`Inspected`]).
    fn inspected(&self) -> Inspected {
        Inspected {
            ids: self.heads.iter().map(|(id, _, _)| *id).collect(),
            committed: self.committed,
            fork: self.fork,
            unresolved: slot_id(self.unresolved),
        }
    }

    /// This row still says what `seen` read of it.
    fn says(&self, seen: &Inspected) -> bool {
        self.heads.iter().map(|(id, _, _)| id).eq(&seen.ids)
            && self.committed == seen.committed
            && self.fork == seen.fork
            && slot_id(self.unresolved) == seen.unresolved
    }

    /// The newest page `other` tells of the author what this row already says, bodies apart:
    /// the same heads, committed head, proof and control runs, fork, unresolved and role heads.
    fn tells_same(&self, other: &Self) -> bool {
        self.heads
            .iter()
            .map(|(id, size, _)| (id, size))
            .eq(other.heads.iter().map(|(id, size, _)| (id, size)))
            && self.committed == other.committed
            && self.proof == other.proof
            && self.controls == other.controls
            && self.fork == other.fork
            && slot_id(self.unresolved) == slot_id(other.unresolved)
            && self.role == other.role
    }

    fn from_have(have: &AuthorHave) -> Self {
        let heads: Vec<(Digest32, u64, Vec<u8>)> = have
            .heads
            .iter()
            .filter_map(|wire| {
                let head = SignedHead::from_wire(wire).ok()?;
                (head.binding.author == have.author)
                    .then(|| (head.id(), head.root.leaves, wire.clone()))
            })
            .collect();
        let committed = have
            .committed
            .then(|| heads.first().map(|(id, size, _)| (*id, *size)))
            .flatten();
        Self {
            heads,
            committed,
            observed: false,
            head: None,
            proof: canonical(&have.proof),
            bodies: canonical(&have.bodies),
            controls: canonical(&have.controls),
            fork: have.fork,
            unresolved: have.unresolved,
            role: have.role,
            listing: None,
            listed: None,
        }
    }

    /// The peer can answer under `head`: it is the peer's committed head, or a prefix of it
    /// inside the run of positions from 1 whose headers the peer holds, which rebuilds it.
    fn serves_under(&self, head: &SignedHead) -> bool {
        let leaves = head.root.leaves;
        self.committed.is_some_and(|(id, size)| {
            id == head.id()
                || (size >= leaves
                    && self
                        .proof
                        .first()
                        .is_some_and(|&(a, b)| a == 1 && b >= leaves))
        })
    }

    /// `have`, this node's Have of the same author, goes beyond what the peer said it holds: a
    /// head the peer did not name, at or above its committed size, or proof, body or control
    /// positions outside its runs.
    fn lacks(&self, have: &AuthorHave) -> bool {
        let floor = self.committed.map_or(0, |(_, size)| size);
        let head = have.heads.iter().any(|wire| {
            !self.heads.iter().any(|(_, _, held)| held == wire)
                && SignedHead::from_wire(wire).is_ok_and(|head| head.root.leaves >= floor)
        });
        let outside = |ours: &[(u64, u64)], theirs: &[(u64, u64)]| {
            ours.iter().any(|&(a, b)| !covers(theirs, a, b))
        };
        head || outside(&have.proof, &self.proof)
            || outside(&have.bodies, &self.bodies)
            || outside(&have.controls, &self.controls)
            || (have.fork && !self.fork)
            || (have.unresolved.is_some() && slot_id(have.unresolved) != slot_id(self.unresolved))
    }

    /// What this row keeps in memory, as its peer's bound counts it ([`HAVE_KEPT_BYTES`]):
    /// one fixed row (ids, sizes, flags and the listing, whose head is one of these), its
    /// signed heads and its runs. Neither its heads nor its proof and control runs grow across
    /// pages (a newest page replaces them, each within `MAX_HAVE_HEADS`/`MAX_HAVE_RUNS`); its
    /// body runs do, page by page.
    fn kept_bytes(&self) -> usize {
        const ROW: usize = 256;
        ROW + self
            .heads
            .iter()
            .map(|(_, _, wire)| wire.len())
            .sum::<usize>()
            + std::mem::size_of::<(u64, u64)>()
                * (self.proof.len() + self.bodies.len() + self.controls.len())
    }
}

/// The most one peer's live connections keep of its Have in one room, together, across
/// authors, pages and connections: 16 MiB, each connection's record charged
/// [`RECORD_KEPT_BYTES`] when it is made and its rows as [`PeerAuthor::kept_bytes`] counts them.
/// This is an accounting bound, not a measured resident-memory peak: it counts each row's heads
/// and runs at their encoded and in-memory sizes plus a fixed row, not allocator overhead or map
/// nodes. Checked under the one lock of the records before a record is made or a row is merged,
/// on the holder's copy (a Have the peer sent, `server::answer`) and on the reader's (a holder's
/// corrected Have in an answer) alike. Bytes are charged in the order they arrive, and a charge
/// never takes back what another live connection of the peer holds: the connection whose
/// record or row would pass the bound is closed (`WireError::ProtocolLimits`), and its record
/// goes with it ([`Holdings::entry`]). That keeps what each connection already holds, not room
/// to grow: a later connection may take what is left, and the first one's own later growth then
/// closes it. Before the bound is read, the peer's records in the room whose connection has
/// closed are removed under the same lock ([`Holdings::others`]): what is charged is what is
/// kept, at every moment. Only one peer's connections in one room share it: no member spends
/// another's.
///
/// What it leaves an honest peer, not a limit the protocol puts on a room's history: a legal
/// 64-member room's 64 rows without body runs take at most 64 × (256 + 4 × 8 KiB heads + 512
/// proof and control runs × 16 B) = 2,637,824 B on a connection; two connections at once (one
/// displacing the other, each told everything) with their records take 2 × (2,637,824 +
/// 1,024) = 5,277,696 B, leaving 11,499,520 B, some 718,000 body runs, about 5,610 per author
/// on each connection (three at once: about 2,880). An honest holder's body runs of an author
/// break only where it lacks a body between two it holds: sealed packages for other members
/// (one break per stretch of them, a stretch per key rotation of the author, split at most once
/// more by the package this holder opens), and bodies whose lifetime ended between controls and
/// packages it keeps. 5,610 runs per author takes some 2,800 such stretches by every member of
/// the room; a history with more passes it, and the connection that would pass it is closed.
const HAVE_KEPT_BYTES: usize = 16 * 1024 * 1024;

/// What a connection's record keeps besides its rows, charged when it is made: the record, its
/// watch and private anchor (a fixed 1 KiB).
const RECORD_KEPT_BYTES: usize = 1024;

fn covers(runs: &[(u64, u64)], lo: u64, hi: u64) -> bool {
    runs.iter().any(|&(a, b)| a <= lo && hi <= b)
}

/// The positions `runs` lists, as ascending runs with no two overlapping or adjacent: one
/// spelling per set of positions, so a row compares by what it covers, never by how a peer
/// split or ordered its runs, and a split adds no run to keep.
fn canonical(runs: &[(u64, u64)]) -> Vec<(u64, u64)> {
    let mut sorted: Vec<(u64, u64)> = runs.iter().copied().filter(|&(a, b)| a <= b).collect();
    sorted.sort_unstable();
    let mut out: Vec<(u64, u64)> = Vec::with_capacity(sorted.len());
    for (a, b) in sorted {
        match out.last_mut() {
            Some(last) if a <= last.1.saturating_add(1) => last.1 = last.1.max(b),
            _ => out.push((a, b)),
        }
    }
    out
}

/// The positions inside `span` that both `a` and `b` list, as runs. Each list is a set of runs
/// in any order (a Have's or a row's); the result is bounded by their combined length.
fn intersect(a: &[(u64, u64)], b: &[(u64, u64)], (lo, hi): (u64, u64)) -> Vec<(u64, u64)> {
    let clip = |runs: &[(u64, u64)]| {
        let mut runs: Vec<(u64, u64)> = runs
            .iter()
            .map(|&(x, y)| (x.max(lo), y.min(hi)))
            .filter(|&(x, y)| x <= y)
            .collect();
        runs.sort_unstable();
        runs
    };
    let (a, b) = (clip(a), clip(b));
    let (mut i, mut j, mut out) = (0, 0, Vec::new());
    while i < a.len() && j < b.len() {
        let (x, y) = (a[i].0.max(b[j].0), a[i].1.min(b[j].1));
        if x <= y {
            out.push((x, y));
        }
        if a[i].1 < b[j].1 {
            i += 1;
        } else {
            j += 1;
        }
    }
    out
}

fn run_of(runs: &[(u64, u64)], seq: u64) -> Option<(u64, u64)> {
    runs.iter().copied().find(|&(a, b)| a <= seq && seq <= b)
}

struct Peer {
    authors: BTreeMap<Digest32, PeerAuthor>,
    /// What this record keeps, as [`HAVE_KEPT_BYTES`] counts it: [`RECORD_KEPT_BYTES`] and its
    /// rows ([`PeerAuthor::kept_bytes`]).
    kept: usize,
    /// The connection's quinn handle: a record of a closed one is removed before the peer's
    /// bound in the room is read ([`Holdings::others`]).
    quinn: quinn::Connection,
    version: tokio::sync::watch::Sender<u64>,
    /// The peer's private Session anchor as its last Have that carried one told it (only a
    /// peer that found a record it may serve this node, `Frame::PrivateHolding`), with how many
    /// private announcements this connection received: each one, the same number again
    /// included, is private news for the asking (`private::Asking`). An observation of the
    /// donor, never a permission.
    private: Option<(crate::node::sessionstream::Cursor, u64)>,
    /// The size of the largest own-feed receipt (`Query::Head(peer)` under Control) this node
    /// served the peer on this connection: what ends the tell-only loop toward a departed
    /// author once it covers its departure ([`standing`]).
    receipt_served: u64,
    /// The room epoch of the last version-3 preamble exchange on this connection: a request
    /// of this node's that the peer answered, or one of the peer's this node authorized. A room
    /// key goes on this connection, or is taken from it, only at that epoch (R10).
    exchanged: Option<u64>,
    /// The fork rule's allowance ([`FORK_ASKS`]): per room author, how many fork proofs this
    /// connection was asked for. Only ever grows; at most one entry per room author.
    fork_asks: BTreeMap<Digest32, u8>,
}

/// Runs kept, and runs inside a span.
type RunSplit = (Vec<(u64, u64)>, Vec<(u64, u64)>);

/// Every connected peer's last Have, per room and per connection: what a peer told on one
/// connection is that connection's, and no other connection to the same peer reads or replaces
/// it, or drops it while it is live (two connections to a peer overlap while one displaces the
/// other, and a retired one can become the peer's connection again,
/// `ConnectionManager::existing`). A connection's record exists exactly as long as the
/// connection is live: made by its first Have (or its loop's first look), whether or not a loop
/// runs on it, and removed once it has closed, whatever path made it ([`Self::entry`]); nothing
/// removes one before the close, and none is made after it.
#[derive(Default)]
pub(crate) struct Holdings {
    /// Per (room, peer, connection serial).
    peers: StdMutex<HashMap<(Digest32, Digest32, u64), Peer>>,
    /// Per (room, peer): the room generation whose holdings this node last told that peer.
    told: StdMutex<HashMap<(Digest32, Digest32), u64>>,
}

impl Holdings {
    /// The record of what `peer` told on connection `conn` in `room`, with what the peer's
    /// other live connections in the room keep ([`Self::others`]): the one place a record is
    /// made, and the one place its removal is registered, with it. It is removed only once the
    /// connection has closed, by the first of its watch and the peer's next charge in the room
    /// ([`Self::others`]), so the record stays while the connection is live, a retired one
    /// promoted back included, and goes with it whether or not a loop ever ran on it. The watch
    /// holds the connection's quinn handle as its stream loop does, never the `VoxConnection`
    /// (whose count says whether a retired one is still carried). `None` once the connection is
    /// closed: checked under the lock the removal takes, so no record is made after its close.
    /// A record whose [`RECORD_KEPT_BYTES`] would take the peer's connections in the room past
    /// [`HAVE_KEPT_BYTES`] is not made: this connection is closed instead.
    fn entry<'a>(
        self: &Arc<Self>,
        peers: &'a mut HashMap<(Digest32, Digest32, u64), Peer>,
        room: Digest32,
        peer: Digest32,
        conn: &VoxConnection,
    ) -> Option<(&'a mut Peer, usize)> {
        let quinn = conn.quinn();
        if quinn.close_reason().is_some() {
            return None;
        }
        let key = (room, peer, conn.serial());
        let others = Self::others(peers, key);
        let held = match peers.entry(key) {
            std::collections::hash_map::Entry::Occupied(held) => held.into_mut(),
            std::collections::hash_map::Entry::Vacant(vacant) => {
                if others + RECORD_KEPT_BYTES > HAVE_KEPT_BYTES {
                    conn.close(crate::wire::WireError::ProtocolLimits);
                    return None;
                }
                let (holdings, watched) = (Arc::downgrade(self), quinn.clone());
                tokio::spawn(async move {
                    watched.closed().await;
                    if let Some(holdings) = holdings.upgrade() {
                        lock(&holdings.peers).remove(&key);
                    }
                });
                vacant.insert(Peer {
                    authors: BTreeMap::new(),
                    kept: RECORD_KEPT_BYTES,
                    quinn: quinn.clone(),
                    version: tokio::sync::watch::Sender::new(0),
                    private: None,
                    receipt_served: 0,
                    exchanged: None,
                    fork_asks: BTreeMap::new(),
                })
            }
        };
        Some((held, others))
    }

    /// What the peer's connections other than `key`'s keep of its Have in `key`'s room: the
    /// part of [`HAVE_KEPT_BYTES`] they hold, which a charge to this one never takes back. In
    /// the same pass, under the lock every charge takes, it removes each of those records whose
    /// connection has closed (its watch would remove it a moment later): every record left in
    /// the map is counted, so the bytes charged are the bytes kept whenever the bound is read.
    /// `key`'s own record is left to its watch: no record is made again after its close.
    fn others(
        peers: &mut HashMap<(Digest32, Digest32, u64), Peer>,
        (room, peer, serial): (Digest32, Digest32, u64),
    ) -> usize {
        let mut others = 0;
        peers.retain(|&(r, p, s), held| {
            if r != room || p != peer || s == serial {
                return true;
            }
            if held.quinn.close_reason().is_some() {
                return false;
            }
            others += held.kept;
            true
        });
        others
    }

    /// The connection's loop subscribes to its peer's Have. On a closed connection the watch
    /// has no sender: the loop's wait on it ends at once.
    pub(crate) fn open(
        self: &Arc<Self>,
        room: Digest32,
        peer: Digest32,
        conn: &VoxConnection,
    ) -> tokio::sync::watch::Receiver<u64> {
        match self.entry(&mut lock(&self.peers), room, peer, conn) {
            Some((entry, _)) => entry.version.subscribe(),
            None => tokio::sync::watch::channel(0).1,
        }
    }

    /// How many times what this node knows the peer holds changed on connection `serial` (0
    /// before its first Have; [`Self::merge`]): what a parked loop compares its news with.
    fn version(&self, room: Digest32, peer: Digest32, serial: u64) -> u64 {
        lock(&self.peers)
            .get(&(room, peer, serial))
            .map_or(0, |p| *p.version.borrow())
    }

    /// A Have the peer sent on connection `conn`. News for that connection's loop only when it
    /// changes what this node knows the peer holds ([`Self::replace`]): a page told again
    /// unchanged is not news. A private section is private news each time, a same-number one
    /// included (`ruling-private-tip.md`). Returns its version on that connection (0 once it is
    /// closed: not kept).
    pub(crate) fn merge(
        self: &Arc<Self>,
        room: Digest32,
        peer: Digest32,
        conn: &VoxConnection,
        have: &[AuthorHave],
        private: Option<crate::node::sessionstream::Cursor>,
    ) -> u64 {
        let mut peers = lock(&self.peers);
        let Some((entry, others)) = self.entry(&mut peers, room, peer, conn) else {
            return 0;
        };
        let mut news = false;
        for author in have {
            let Some(changed) = Self::replace(entry, others, author, false) else {
                // Past the peer's bound in the room: this connection is closed, and its record
                // goes with it; no other connection's record is touched.
                conn.close(crate::wire::WireError::ProtocolLimits);
                return 0;
            };
            news |= changed;
        }
        if let Some(told) = private {
            let heard = entry.private.as_ref().map_or(0, |(_, heard)| *heard);
            entry.private = Some((told, heard.wrapping_add(1)));
            news = true;
        }
        if news {
            entry.version.send_modify(|at| *at = at.wrapping_add(1));
        }
        let version = *entry.version.borrow();
        version
    }

    /// A version-3 preamble exchange for `room` at `epoch` completed on connection `conn`
    /// with `peer` ([`Peer::exchanged`]).
    pub(crate) fn exchanged(
        self: &Arc<Self>,
        room: Digest32,
        peer: Digest32,
        conn: &VoxConnection,
        epoch: u64,
    ) {
        if let Some((entry, _)) = self.entry(&mut lock(&self.peers), room, peer, conn) {
            entry.exchanged = Some(epoch);
        }
    }

    /// Whether connection `serial` to `peer` completed a version-3 preamble exchange for
    /// `room` at `epoch`: the one condition under which a room key is written to it or taken
    /// from it. A connection's record goes with its close, so a new connection exchanges again.
    pub(crate) fn exchanged_at(
        &self,
        room: Digest32,
        peer: Digest32,
        serial: u64,
        epoch: u64,
    ) -> bool {
        lock(&self.peers)
            .get(&(room, peer, serial))
            .is_some_and(|p| p.exchanged == Some(epoch))
    }

    /// The private Session anchor peer `peer` last told on connection `serial`, if any, and how
    /// many private announcements that connection received.
    pub(crate) fn private_tip(
        &self,
        room: Digest32,
        peer: Digest32,
        serial: u64,
    ) -> Option<(crate::node::sessionstream::Cursor, u64)> {
        lock(&self.peers)
            .get(&(room, peer, serial))
            .and_then(|p| p.private.clone())
    }

    /// This node served the peer, on connection `conn`, the receipt of its own feed through
    /// `size` (`server::answer`). News for that connection's loop: the teller toward a departed
    /// author ends once a receipt covers its departure ([`standing`]).
    pub(crate) fn receipt_served(
        self: &Arc<Self>,
        room: Digest32,
        peer: Digest32,
        conn: &VoxConnection,
        size: u64,
    ) {
        let mut peers = lock(&self.peers);
        let Some((entry, _)) = self.entry(&mut peers, room, peer, conn) else {
            return;
        };
        if size > entry.receipt_served {
            entry.receipt_served = size;
            entry.version.send_modify(|at| *at = at.wrapping_add(1));
        }
    }

    /// The holder's own correction, carried in its answer: its Have of that author in place of
    /// the one this node held, except its body runs, which only take away
    /// ([`Self::replace`] with `subtract`). Returns whether it withdrew a body this node knew
    /// the peer held: the one change a correction makes to that knowledge. A correction past
    /// the peer's bound in the room closes this connection, as a Have past it does.
    fn correct(
        &self,
        room: Digest32,
        peer: Digest32,
        conn: &VoxConnection,
        have: &AuthorHave,
    ) -> bool {
        let mut peers = lock(&self.peers);
        let key = (room, peer, conn.serial());
        let others = Self::others(&mut peers, key);
        let Some(entry) = peers.get_mut(&key) else {
            return false;
        };
        Self::replace(entry, others, have, true).unwrap_or_else(|| {
            conn.close(crate::wire::WireError::ProtocolLimits);
            false
        })
    }

    /// The peer's new Have of an author in place of the one held. The last listing taken stays
    /// while the peer lists the same fork and unresolved head (MP-9: asked once per thing
    /// listed). Its body runs replace what the peer told before inside their span only
    /// (`AuthorHave::bodies_span`): an older page changes nothing but its own body runs, and
    /// what no page told again stays as told. The row is kept only if the peer's connections in
    /// the room then fit [`HAVE_KEPT_BYTES`] (`others`: what its other live connections keep);
    /// otherwise neither it nor the row held before is, and `None` says so: the caller closes
    /// this connection.
    ///
    /// `subtract` (an answer's correction, ruling `ruling-body-extents.md`, conditions of A):
    /// inside the span, only the body positions told before AND still listed by the correction
    /// stay; outside it nothing changes. A correction never adds a body: a body it withdrew
    /// comes back only with an ordinary Have that lists it again, so two denied bodies of one
    /// page cannot restore each other in turn.
    ///
    /// Returns whether what this node knows the peer holds of the author changed: for an
    /// ordinary Have, anything it tells differs from the row held (a page told again unchanged
    /// leaves the row as it was, with what was observed of it); for a correction, a body known
    /// before was withdrawn (its other parts are not counted: they may change back and forth,
    /// while the bodies it can withdraw only shrink until an ordinary Have tells them again).
    fn replace(peer: &mut Peer, others: usize, have: &AuthorHave, subtract: bool) -> Option<bool> {
        let (lo, hi) = have.bodies_span;
        let old = peer.authors.remove(&have.author);
        peer.kept -= old.as_ref().map_or(0, PeerAuthor::kept_bytes);
        let (kept, inside): RunSplit = match old.as_ref() {
            Some(old) => {
                let outside = old
                    .bodies
                    .iter()
                    .flat_map(|&(a, b)| {
                        [
                            (a, b.min(lo.saturating_sub(1))),
                            (a.max(hi.saturating_add(1)), b),
                        ]
                    })
                    .filter(|&(a, b)| a <= b)
                    .collect();
                let inside = if subtract {
                    intersect(&old.bodies, &have.bodies, (lo, hi))
                } else {
                    have.bodies.clone()
                };
                (outside, inside)
            }
            None if subtract => (Vec::new(), Vec::new()),
            None => (Vec::new(), have.bodies.clone()),
        };
        // Compared, and kept, by what they cover (`canonical`): a correction that only splits
        // or reorders runs withdraws nothing, and an ordinary Have that does tells nothing new.
        let mut bodies = kept;
        bodies.extend_from_slice(&inside);
        let bodies = canonical(&bodies);
        let fresh = have.is_newest_page().then(|| PeerAuthor::from_have(have));
        let changed = match &old {
            Some(old) if subtract => old.bodies != bodies,
            Some(old) => {
                old.bodies != bodies || fresh.as_ref().is_some_and(|fresh| !old.tells_same(fresh))
            }
            None => !subtract,
        };
        if !subtract && !changed {
            if let Some(old) = old {
                peer.kept += old.kept_bytes();
                peer.authors.insert(have.author, old);
            }
            return Some(false);
        }
        let mut new = match (old, fresh) {
            (Some(old), None) => old,
            (Some(mut old), Some(mut new)) => {
                if old.fork == new.fork && slot_id(old.unresolved) == slot_id(new.unresolved) {
                    new.listed = old.listed.take();
                }
                new
            }
            (None, None) => PeerAuthor::from_have(&AuthorHave {
                author: have.author,
                ..AuthorHave::default()
            }),
            (None, Some(new)) => new,
        };
        new.bodies = bodies;
        let bytes = new.kept_bytes();
        if others + peer.kept + bytes <= HAVE_KEPT_BYTES {
            peer.kept += bytes;
            peer.authors.insert(have.author, new);
            Some(changed)
        } else {
            None
        }
    }

    /// The peer's row of `author` was observed here as `seen` says it read it; `head` is its
    /// committed head, held here; `listing` is what that row makes this node ask it about the
    /// author (MP-9). Marked observed only while the row still says exactly what was read
    /// (`PeerAuthor::says`): a newer Have of the author meanwhile, a replaced fork proof whose
    /// heads did not change included, is observed afresh (`sec-code-4.md` P1).
    #[allow(clippy::too_many_arguments)]
    fn observed(
        &self,
        room: Digest32,
        peer: Digest32,
        serial: u64,
        author: Digest32,
        seen: &Inspected,
        head: Option<Arc<SignedHead>>,
        listing: Option<Listing>,
    ) {
        if let Some(held) = lock(&self.peers)
            .get_mut(&(room, peer, serial))
            .and_then(|entry| entry.authors.get_mut(&author))
            .filter(|held| held.says(seen))
        {
            held.observed = true;
            held.head = head;
            // The step the last listing took is not asked again of this peer.
            held.listing = listing.filter(|listing| held.listed.as_ref() != Some(listing));
        }
    }

    /// MP-9: the first ask the peer's Have makes this node owe it, taken: it is not asked again
    /// while the peer lists the same thing and this node's comparison stands where it was.
    fn take_listing(
        &self,
        room: Digest32,
        peer: Digest32,
        serial: u64,
    ) -> Option<(Digest32, Listing)> {
        lock(&self.peers)
            .get_mut(&(room, peer, serial))?
            .authors
            .iter_mut()
            .find_map(|(author, held)| {
                let listing = held.listing.take()?;
                held.listed = Some(listing.clone());
                Some((*author, listing))
            })
    }

    /// The fork rule's per-connection half ([`FORK_ASKS`]): the identity of the proof the
    /// peer's Have lists for `author` ([`slot_id`] of the `unresolved` slot beside a listed
    /// fork), when its Have lists that fork and this connection has asks left for `author`.
    fn fork_listed(
        &self,
        room: Digest32,
        peer: Digest32,
        serial: u64,
        author: Digest32,
    ) -> Option<Option<Digest32>> {
        let peers = lock(&self.peers);
        let entry = peers.get(&(room, peer, serial))?;
        let held = entry.authors.get(&author).filter(|held| held.fork)?;
        (entry.fork_asks.get(&author).copied().unwrap_or(0) < FORK_ASKS)
            .then_some(slot_id(held.unresolved))
    }

    /// One of this connection's [`FORK_ASKS`] for `author` spent, before the ask is sent;
    /// false when none is left. Never given back.
    fn spend_fork_ask(
        &self,
        room: Digest32,
        peer: Digest32,
        serial: u64,
        author: Digest32,
    ) -> bool {
        let mut peers = lock(&self.peers);
        let Some(entry) = peers.get_mut(&(room, peer, serial)) else {
            return false;
        };
        let spent = entry.fork_asks.entry(author).or_insert(0);
        if *spent >= FORK_ASKS {
            return false;
        }
        *spent += 1;
        true
    }

    /// An answer of this peer saved something about `author`: the next ask reads its Have of
    /// the author again ([`observe`]), so a comparison it moved takes its next step at once.
    fn unobserve(&self, room: Digest32, peer: Digest32, serial: u64, author: Digest32) {
        if let Some(held) = lock(&self.peers)
            .get_mut(&(room, peer, serial))
            .and_then(|entry| entry.authors.get_mut(&author))
        {
            held.observed = false;
        }
    }

    /// A loop starts on connection `serial` for a new room instance or epoch (`run`): what an
    /// earlier loop observed of the peer's Have into this node's record (its heads staged, its
    /// MP-9 listing taken) was observed into that record, not this one. The peer's Have itself
    /// stays (it is the peer's, and the connection's); every author of it is observed again.
    /// What the peer told on its other connections stays theirs: each goes with its own
    /// connection's close ([`Self::entry`]), and a retired one promoted back still has it.
    fn observe_afresh(&self, room: Digest32, peer: Digest32, serial: u64) {
        if let Some(entry) = lock(&self.peers).get_mut(&(room, peer, serial)) {
            for held in entry.authors.values_mut() {
                held.observed = false;
                held.head = None;
                held.listing = None;
                held.listed = None;
            }
            entry.version.send_modify(|at| *at = at.wrapping_add(1));
        }
    }

    fn authors(&self, room: Digest32, peer: Digest32, serial: u64) -> Vec<(Digest32, PeerAuthor)> {
        lock(&self.peers)
            .get(&(room, peer, serial))
            .map(|p| p.authors.iter().map(|(a, h)| (*a, h.clone())).collect())
            .unwrap_or_default()
    }

    /// The highest head of its own feed the peer said it holds, on its latest connection: an
    /// unauthoritative locator, as `vox status` names it.
    pub(crate) fn advertised_through(&self, room: Digest32, peer: Digest32) -> Option<u64> {
        lock(&self.peers)
            .iter()
            .filter(|((r, p, _), _)| *r == room && *p == peer)
            .max_by_key(|((_, _, serial), _)| *serial)?
            .1
            .authors
            .get(&peer)?
            .heads
            .iter()
            .map(|(_, size, _)| *size)
            .max()
    }

    /// Of `haves` (this node's), those that go beyond what the peer's own last Have on
    /// connection `serial` says it holds of that author (all that are not empty when it said
    /// nothing of the author), and those `forced` (this node's row of the peer's own author,
    /// first on the connection and then whenever its role-complete hint changed: the receipt
    /// rule, ADR-054; its heads above the peer's reach it by the ordinary rule).
    fn beyond<'h>(
        &self,
        room: Digest32,
        peer: Digest32,
        serial: u64,
        haves: impl Iterator<Item = &'h AuthorHave>,
        forced: impl Fn(&AuthorHave) -> bool,
    ) -> Vec<AuthorHave> {
        let peers = lock(&self.peers);
        let theirs = peers.get(&(room, peer, serial)).map(|held| &held.authors);
        haves
            .filter(|have| {
                forced(have)
                    || match theirs.and_then(|authors| authors.get(&have.author)) {
                        Some(held) => held.lacks(have),
                        None => {
                            !have.heads.is_empty()
                                || !have.proof.is_empty()
                                || !have.bodies.is_empty()
                                || !have.controls.is_empty()
                                || have.fork
                                || have.unresolved.is_some()
                        }
                    }
            })
            .cloned()
            .collect()
    }

    /// The room's received entries are durable before a changed Holding is told: every receive
    /// debt of the room, each flow's own included (a source whose effect is still owed, a body
    /// refilled before its effect: `Store::received_debts_for_room`), is enumerated afresh each
    /// time (under the store writer, so a commit and its debt registration have finished) and
    /// flushed. A debt a durable commit already covers begins no transaction
    /// (`Store::flush_received_through`): nothing owed, no flush.
    async fn durable(&self, room: Digest32, store: &Arc<Store>) -> Result<()> {
        let store = Arc::clone(store);
        tokio::task::spawn_blocking(move || {
            store.finish_received_replacement()?;
            for debt in store.received_debts_for_room(room) {
                store.flush_received_through(debt)?;
            }
            Ok::<(), Error>(())
        })
        .await
        .map_err(|_| Error::Unreachable("history flush worker stopped"))?
    }

    /// The room generations told since the actor last took them: each is credited to its port.
    pub(crate) fn take_told(&self) -> Vec<((Digest32, Digest32), u64)> {
        lock(&self.told).drain().collect()
    }
}

// ---------------------------------------------------------------------------------------------
// The node's admission frontier.

/// A need the frontier recorded: exactly what an entry it dropped waits for. It is keyed by what
/// it is about, an author's positions, never by the head admission found it missing under: a
/// position is the same entry under every committed head of its author, so any answer that
/// brings it, under whatever committed head, meets it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum Need {
    /// The receipt of `author`'s entry `seq` (header, inclusion, own prefix [1, seq]): met by an
    /// answer that brings it (`Frontier::received`), or by the position's admission here.
    Position { author: Digest32, seq: u64 },
    /// `author`'s control coverage `lo..=hi`: met once its verified coverage from position 1
    /// reaches `hi` (`Frontier::covered`), whatever committed head proved it.
    Controls { author: Digest32, lo: u64, hi: u64 },
    /// A committed head of `author` strictly larger than `size`, which is always the author's
    /// committed size the step saw: a head newer than any this node held then. Raised only when
    /// what the step needs is not under the committed head (`Flow::resolve_need`, the
    /// malformed-root wait); met once this node's committed head of the author passes `size`,
    /// whichever head that is.
    Head { author: Digest32, size: u64 },
    /// Rule F2 E: a fork proof of `author` whose boundary here is at or below `at`: met once one
    /// is recorded (`RoomSnapshot::fork_boundary`). Not a range ask: MP-9's comparisons and fork
    /// listings bring the proof; a peer listing a proof this node lacks is asked for it by the
    /// fork rule ([`FORK_ASKS`]), frozen author or not, whether or not an entry is parked.
    Fork { author: Digest32, at: u64 },
    /// Rule F3: a signed-context coordinate (`author`, `seq`, `hash`) that is not this node's
    /// accepted control and names a certified proved splitter at or after its boundary. Only
    /// that matching entry could meet it, and a frozen author's later entries are never
    /// accepted here: never met and never asked, so its citing entry stays unadmitted, as it was
    /// refused before the rule.
    Unmatched {
        author: Digest32,
        seq: u64,
        hash: Digest32,
    },
}

/// One checked entry waiting for the existing admission path, its body (if any) held in
/// memory for that path only, and counted as its connection's assembly until its last copy
/// goes (`charge`).
#[derive(Clone)]
pub(crate) struct Ready {
    pub(crate) head: Digest32,
    pub(crate) entry: Arc<Entry>,
    /// The live package body debt an explicit Body answer fills: admitted only by the typed
    /// refill, which checks this debt again in its own transaction.
    pub(crate) key_body: Option<super::KeyBodyNeed>,
    charge: Arc<Charge>,
    /// What its last admission operation checked before it stopped (JoinDesign S1), kept with
    /// it across a wait under its own charge: the copies of this entry share it, and the one
    /// that resumes takes it.
    checked: Option<Arc<StdMutex<Option<KeptChecked>>>>,
}

/// What admission checked of one root, kept with it while it waits in the frontier, under its
/// exact size taken out of its admission's headroom ([`CheckedRoom::keep`]); the charge goes
/// back when it is dropped, or into the next admission's headroom that takes the root
/// ([`CheckedRoom::restore`]).
pub(super) struct KeptChecked {
    checked: Option<Box<super::admission::Checked>>,
    _charge: Charge,
}

/// An admission's headroom for what its entries' operations check (JoinDesign S1): one charge
/// to the room's assembly, taken before its root leaves the ready set
/// ([`Frontier::reserve_checked_or_wake`], `admission::Checked::headroom`), held while the
/// admission runs, and the one debit every state it keeps lives under. A state the root waits
/// with in the frontier takes its exact size out of it ([`Self::keep`]) and brings it back
/// when the root is taken again ([`Self::restore`]).
pub(super) struct CheckedRoom(Charge);

impl CheckedRoom {
    /// What it holds.
    pub(super) fn bytes(&self) -> usize {
        self.0.bytes
    }

    /// `other`'s bytes held as this room's.
    pub(super) fn join(&mut self, other: CheckedRoom) {
        self.0.join(other.0);
    }

    /// `checked` as kept with its root in the frontier, under its exact size taken out of this
    /// room; none when the room does not hold that much.
    pub(super) fn keep(&mut self, checked: Box<super::admission::Checked>) -> Option<KeptChecked> {
        let bytes = checked.bytes();
        (bytes <= self.0.bytes).then(|| KeptChecked {
            checked: Some(checked),
            _charge: self.0.split(bytes),
        })
    }

    /// What a root kept, its charge back in this room; beyond `most`, what the room then holds
    /// goes back to the assembly (never less than the state itself). `most` is the base only at
    /// a new root, when no other state lives under the room; a declined wait passes no limit.
    pub(super) fn restore(
        &mut self,
        kept: KeptChecked,
        most: usize,
    ) -> Option<Box<super::admission::Checked>> {
        let KeptChecked {
            checked,
            _charge: charge,
        } = kept;
        self.0.join(charge);
        self.trim(most.max(checked.as_ref().map_or(0, |checked| checked.bytes())));
        checked
    }

    /// What it holds beyond `most` goes back to the assembly.
    pub(super) fn trim(&mut self, most: usize) {
        let over = self.0.bytes.saturating_sub(most);
        drop(self.0.split(over));
    }
}

/// The next release of a charge to the node's assembly ([`Frontier::reserve_checked_or_wake`]).
pub(super) type AssemblyWake = Pin<Box<dyn Future<Output = ()> + Send + Sync>>;

impl Ready {
    /// Keeps what admission checked with this entry, with its charge.
    pub(super) fn keep_checked(&mut self, kept: KeptChecked) {
        self.checked = Some(Arc::new(StdMutex::new(Some(kept))));
    }

    /// What admission checked with this entry, taken by the one admission that resumes it.
    pub(super) fn take_checked(&self) -> Option<KeptChecked> {
        self.checked.as_ref().and_then(|kept| lock(kept).take())
    }
}

/// A sealed key package.
fn is_package(entry: &Entry) -> bool {
    entry
        .skeleton
        .v2
        .as_ref()
        .is_some_and(|v2| v2.kind == SignedEntryKind::KeyPackage)
}

/// A control entry: its authenticated v2 signed kind counts as a control (`is_control`:
/// governance, checkpoints, step policy, floors, private support, key packages, context
/// updates, termination). Read from the header the loop already checked (signature and
/// inclusion) before handing it over; nothing is decrypted to classify it.
fn is_control(entry: &Entry) -> bool {
    entry
        .skeleton
        .v2
        .as_ref()
        .is_some_and(|v2| v2.kind.is_control())
}

/// A post: its authenticated v2 signed kind is Content, which a held control of its own author
/// below it blocks ([`FrontierInner::queue`]).
fn is_post(entry: &Entry) -> bool {
    entry
        .skeleton
        .v2
        .as_ref()
        .is_some_and(|v2| v2.kind == SignedEntryKind::Content)
}

/// One class of a room's ready set: per author, its entries of the class in position order,
/// and the authors that hold one in the order of their turn. A take is one entry of the author
/// whose turn it is, which then goes to the back of the turn if it holds more: its oldest, or,
/// in a class whose takes alternate ([`ReadySet`]'s ordinary class), its newest and its oldest
/// in turn, newest first.
#[derive(Default)]
struct ReadyClass {
    /// Each author holding an entry, with whether its next take is its newest.
    turn: VecDeque<(Digest32, bool)>,
    authors: HashMap<Digest32, BTreeMap<u64, Ready>>,
}

impl ReadyClass {
    fn push(&mut self, item: Ready) {
        let author = item.entry.skeleton.author_id;
        let entries = self.authors.entry(author).or_default();
        if entries.is_empty() {
            self.turn.push_back((author, true));
        }
        entries.insert(item.entry.skeleton.seq, item);
    }

    fn take(&mut self, alternate: bool) -> Option<Ready> {
        let (author, newest) = self.turn.pop_front()?;
        let newest = alternate && newest;
        let entries = self.authors.get_mut(&author)?;
        let (_, item) = if newest {
            entries.pop_last()
        } else {
            entries.pop_first()
        }?;
        if entries.is_empty() {
            self.authors.remove(&author);
        } else {
            self.turn.push_back((author, !newest));
        }
        Some(item)
    }

    /// Takes exactly `(author, seq)` out of the class, if it is there.
    fn remove(&mut self, author: Digest32, seq: u64) -> Option<Ready> {
        let entries = self.authors.get_mut(&author)?;
        let item = entries.remove(&seq)?;
        if entries.is_empty() {
            self.authors.remove(&author);
            self.turn.retain(|(a, _)| *a != author);
        }
        Some(item)
    }

    /// Takes the posts ([`is_post`]) of `author` above `seq` out of the class.
    fn posts_above(&mut self, author: Digest32, seq: u64, out: &mut Vec<Ready>) {
        let Some(entries) = self.authors.get(&author) else {
            return;
        };
        let above: Vec<u64> = entries
            .range(seq.saturating_add(1)..)
            .filter(|(_, item)| is_post(&item.entry))
            .map(|(at, _)| *at)
            .collect();
        out.extend(above.into_iter().filter_map(|at| self.remove(author, at)));
    }

    fn is_empty(&self) -> bool {
        self.turn.is_empty()
    }

    fn into_items(self) -> impl Iterator<Item = Ready> {
        self.authors.into_values().flat_map(BTreeMap::into_values)
    }
}

/// A room's ready set, taken by the room's ONE admission one entry at a time (`take`), from
/// two classes. Urgent: a control entry ([`is_control`]), or a position an admission waiter
/// waits for (`Wait::At`), for as long as one does. Ordinary: everything else that is
/// runnable; a post known to lack a control of its own author below it is not here but waits
/// for it ([`FrontierInner::queue`]). When both hold an entry, takes alternate: one urgent,
/// then one ordinary; when ordinary holds none, urgent takes go on. Within a class, every
/// author that holds an entry of it gets one taken before any author gets a second; an entry
/// given back goes back into its author's place, so a yielded or failed attempt was that
/// author's turn. So controls never drain ahead of runnable posts: with D ordinary authors
/// runnable, an ordinary author's next entry is behind at most D−1 ordinary and D urgent takes,
/// whatever one author's flood of controls. An author's urgent entries are taken oldest first
/// (an entry needs its author's earlier controls admitted); its ordinary ones, its newest and
/// its oldest in turn, newest first: a post needs its predecessor's receipt and its author's
/// earlier controls, never an earlier post, so the newest post an author has ready (what a
/// returning reader asked first, the walk's newest page) never waits behind the backlog that
/// came after it, and the oldest still gets every other turn, as the walk's debt alternates.
#[derive(Default)]
struct ReadySet {
    urgent: ReadyClass,
    ordinary: ReadyClass,
    /// The last take was urgent: with both classes holding an entry, the next is ordinary.
    ordinary_next: bool,
}

impl ReadySet {
    fn push(&mut self, item: Ready, urgent: bool) {
        if urgent {
            self.urgent.push(item);
        } else {
            self.ordinary.push(item);
        }
    }

    fn take(&mut self) -> Option<Ready> {
        let urgent = !self.urgent.is_empty() && (self.ordinary.is_empty() || !self.ordinary_next);
        let item = if urgent {
            self.urgent.take(false)
        } else {
            self.ordinary.take(true)
        }?;
        self.ordinary_next = urgent;
        Some(item)
    }

    /// A waiter now waits for `(author, seq)`: if it is ready as ordinary, it becomes urgent.
    fn promote(&mut self, author: Digest32, seq: u64) {
        if let Some(item) = self.ordinary.remove(author, seq) {
            self.urgent.push(item);
        }
    }

    /// The last waiter for `(author, seq)` is gone: unless it is a control, it is ordinary.
    fn demote(&mut self, author: Digest32, seq: u64) {
        if let Some(item) = self.urgent.remove(author, seq) {
            let control = is_control(&item.entry);
            self.push(item, control);
        }
    }

    /// Takes the queued posts of `author` above `seq` out of both classes.
    fn posts_above(&mut self, author: Digest32, seq: u64) -> Vec<Ready> {
        let mut out = Vec::new();
        self.urgent.posts_above(author, seq, &mut out);
        self.ordinary.posts_above(author, seq, &mut out);
        out
    }

    fn is_empty(&self) -> bool {
        self.urgent.is_empty() && self.ordinary.is_empty()
    }

    fn into_items(self) -> impl Iterator<Item = Ready> {
        self.urgent.into_items().chain(self.ordinary.into_items())
    }
}

/// What a dropped entry waits for: an entry of another position not admitted here yet (that
/// position's admission moves it to the ready set), or a need a loop must fetch (a met need
/// moves it to the ready set).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Wait {
    At(Digest32, u64),
    Need(Need),
}

#[derive(Default)]
struct FrontierInner {
    /// Per room: the needs that dropped entries wait for, each with the head admission named,
    /// read once when it recorded it (none for a head need): asked under only when the peer
    /// serves neither its newer committed head nor this node's.
    needs: BTreeMap<Digest32, BTreeMap<Need, Option<Arc<SignedHead>>>>,
    /// Per room: the ready set, checked entries the room's one admission has not taken yet.
    /// Once handed over, an entry belongs to the room, not to the connection that checked it.
    ready: HashMap<Digest32, ReadySet>,
    /// Per (room, author, seq): ready or in admission, with the connection that checked it
    /// (named in `vox status` last sync once the position publishes).
    admitting: HashMap<(Digest32, Digest32, u64), Digest32>,
    /// Per (room, wait): the entries dropped for it. Each is kept, with its body, by the
    /// connection that checked it, as that connection's assembly ([`Assembly`]): past a bound,
    /// only its place is kept and it is fetched again once the wait is over. No scan and no
    /// network round: the wait's end moves them to the ready set.
    waiting: HashMap<(Digest32, Wait), Vec<Waiter>>,
    /// Per (room, author, seq) of a dropped entry: what it waits for; not owed meanwhile.
    waits_for: HashMap<(Digest32, Digest32, u64), Wait>,
    /// Per (room, author): the positions ready or in admission, as runs: owned by the room's
    /// admission.
    busy: HashMap<(Digest32, Digest32), Runs>,
    /// Per (room, author): the positions waiting (`waits_for`), as runs: not owed as debt, but
    /// a position need naming one is still asked (it can be the evidence that very entry
    /// waits for).
    waits: HashMap<(Digest32, Digest32), Runs>,
    /// Per (room, author): the positions of control entries (their checked signed kind) that
    /// are ready, in admission or waiting here, as runs: held, not admitted yet. A position
    /// leaves it when it is published, or when it leaves the frontier unpublished; either way
    /// its `Wait::At` waiters are released in the same lock hold ([`FrontierInner::release`]).
    controls: HashMap<(Digest32, Digest32), Runs>,
    /// Per (room, peer, connection serial): what that connection's last answer left for the
    /// answer continuing it ([`Kept`]), with its charge, kept here between that connection's
    /// asks so that it can give way ([`Frontier::shed`]) while the connection waits on its
    /// peer. The connection takes it back once the answer continuing it has arrived.
    partials: HashMap<(Digest32, Digest32, u64), (Kept, Charge)>,
    /// Per (room, peer, connection serial): the one request that connection's loop has live,
    /// with its mark's token. Written only by [`Frontier::mark`] and [`Marked`]'s drop: these
    /// are the marks.
    asking: HashMap<(Digest32, Digest32, u64), (u64, Asking)>,
    /// The last mark's token.
    marked: u64,
    /// The saved archive intents this node owes (ADR-054 PL-3, PL-12.1; ruling correction 4),
    /// by request: each from the step that saved or restored it until its fence is retired.
    /// Accepting one never displaces another.
    archive: BTreeMap<super::RequestId, ArchiveOwed>,
    /// Per room: the view loops plan from, built once after a change.
    views: HashMap<Digest32, Arc<View>>,
    /// The rooms whose admission met no news since it began (`Frontier::admission_began`): no
    /// entry was made ready there and the room's private news did not move. A failed
    /// admission of a room still quiet waits for news ([`Frontier::failed_admission_news`]).
    quiet: BTreeSet<Digest32>,
    /// `VOX_TEST_HOLD_INCOMING_CONSENT_FILE`: the consent a proof holds, out of its room's ready
    /// set until the hold file is gone ([`held_consent`]).
    #[cfg(feature = "test-knobs")]
    held_consents: Vec<(Digest32, Ready)>,
    /// Per (room, author, seq) of an entry waiting at a position: the other authors' controls
    /// (author, position) its stop found it lacks too (`settled`). When its wait ends, it waits
    /// for the next of them still held here unadmitted instead of running again
    /// ([`FrontierInner::release`]): one stop per entry, not one per author.
    rest: HashMap<(Digest32, Digest32, u64), Vec<(Digest32, u64)>>,
    /// Per (room, root) of a failed admission: the cause it was last said with in the daemon log
    /// (`Frontier::failed_admission_said`). A root's is kept only while that entry is ready, in
    /// admission or waiting here, and dropped when it leaves (`refresh`): each retained entry
    /// and cause is said once, and this is no larger than what is retained. A failure with no
    /// root keeps one per room.
    said: HashMap<(Digest32, Option<(Digest32, u64)>), String>,
}

impl FrontierInner {
    /// The held consents whose hold is gone go back to their room's ready set; whether any did.
    #[cfg(feature = "test-knobs")]
    fn release_held_consents(&mut self) -> bool {
        let held = std::mem::take(&mut self.held_consents);
        let before = held.len();
        for (room, item) in held {
            if consent_hold(&item.entry).is_some() {
                self.held_consents.push((room, item));
            } else {
                self.ready.entry(room).or_default().push(item, true);
            }
        }
        self.held_consents.len() < before
    }
}

/// `VOX_TEST_HOLD_INCOMING_CONSENT_FILE` (the retained-row journey): while the file names
/// `entry`'s room, author and target, that signed consent stays out of its room's ready set, so
/// it is not admitted while every other entry is (the room's one admission is never held).
/// Returns the file and what it names.
#[cfg(feature = "test-knobs")]
fn consent_hold(entry: &Entry) -> Option<(std::path::PathBuf, String)> {
    let path = std::env::var_os("VOX_TEST_HOLD_INCOMING_CONSENT_FILE")
        .filter(|path| !path.is_empty())
        .map(std::path::PathBuf::from)
        .filter(|path| path.is_file())?;
    let Ok(crate::governance::entry::GovBody::ConsentGrant(consent)) =
        crate::governance::entry::GovEntry::body_bound_to(entry)
    else {
        return None;
    };
    let encode = crate::node::link::b32_encode;
    let scope = format!(
        "{} {} {}",
        encode(&entry.skeleton.channel_id),
        encode(&entry.skeleton.author_id),
        encode(&consent.body.target_id)
    );
    (std::fs::read_to_string(&path).ok().as_deref() == Some(scope.as_str()))
        .then_some((path, scope))
}

/// [`consent_hold`] for an entry the room's admission would take: when held, its `.entered`
/// marker says which consent is held (`room author target hash`), written whole by a rename.
#[cfg(feature = "test-knobs")]
fn held_consent(entry: &Entry) -> bool {
    let Some((path, scope)) = consent_hold(entry) else {
        return false;
    };
    let temporary = path.with_extension(format!("entered.{}.tmp", std::process::id()));
    let marker = format!(
        "{scope} {}",
        crate::node::link::b32_encode(&entry.entry_hash())
    );
    if std::fs::write(&temporary, marker).is_ok() {
        let _ = std::fs::rename(&temporary, path.with_extension("entered"));
    }
    true
}

/// The positions a saved archive intent covers: `lo` to `hi` of `author` in `room`, its original
/// bounds, owed like the walk's debt until the intent's fence is retired (paused, cancelled,
/// retired with its room or node, or complete). What a page brings is admitted like any page;
/// the intent's own bookkeeping reads the record (`actor::history_demand`).
#[derive(Clone)]
pub(crate) struct ArchiveOwed {
    pub(crate) room: Digest32,
    pub(crate) author: Digest32,
    pub(crate) lo: u64,
    pub(crate) hi: u64,
    pub(crate) fence: Arc<Fence>,
}

/// A person's saved private archive request (ruling (b), build order 6), owed only to the
/// connection of its original donor, whose numbering its positions are: its original binding,
/// bounds (the donor incarnation is `bounds.head`) and Drive grant (`plan.grant`), with the
/// plan's progress since it was owed. Another donor's locators are never a substitute. Its
/// pages are admitted under this capability (binding and fence), not under a later copy.
#[derive(Clone)]
pub(crate) struct PrivateOwed {
    pub(crate) room: Digest32,
    pub(crate) donor: Digest32,
    pub(crate) binding: crate::node::history_demand::Binding,
    pub(crate) bounds: crate::node::history_demand::Bounds,
    pub(crate) plan: crate::node::history_demand::PrivatePlan,
    pub(crate) fence: Arc<Fence>,
}

/// The private Session debt the loops ask from: saved private requests, each room's private
/// news (local key, floor, opening and evidence changes that can make old automatic debt
/// runnable while no tip moves) with its permission-change serial (the news that can change
/// what this node may serve a peer), and the requests that ended since the actor last took them.
#[derive(Default)]
struct PrivateDebt {
    owed: BTreeMap<super::RequestId, PrivateOwed>,
    news: HashMap<Digest32, (u64, u64)>,
    settled: Vec<(super::RequestId, std::result::Result<(), String>)>,
}

/// What one live request asks: its author and its want. Whatever head it names, it asks the
/// author's positions.
#[derive(Clone, Copy, Debug)]
struct Asking {
    author: Digest32,
    want: RangeWant,
}

/// What a loop's plan reads of the frontier, taken once per plan: the room's needs, per author
/// the positions ready or in admission and the positions waiting, as runs, and, per author,
/// the positions this node's live requests in the room ask: by entry pages and continuations,
/// and by control intervals.
#[derive(Default)]
struct View {
    needs: Vec<(Need, Option<Arc<SignedHead>>)>,
    busy: HashMap<Digest32, Runs>,
    waits: HashMap<Digest32, Runs>,
    asked: HashMap<Digest32, Runs>,
    controls: HashMap<Digest32, Runs>,
    archive: Vec<ArchiveOwed>,
}

impl View {
    /// Some live request already asks what `ask` asks, under whatever head: a control interval
    /// by live control asks of the author that contain it; an entry page or continuation by any
    /// request for one of its positions.
    fn covered(&self, ask: &Ask) -> bool {
        let (lo, hi) = ask.want.interval();
        if matches!(ask.want, RangeWant::Controls { .. }) {
            return self
                .controls
                .get(&ask.author)
                .is_some_and(|runs| runs.absent_from(lo) > hi);
        }
        self.asked
            .get(&ask.author)
            .is_some_and(|runs| runs.present_from(lo) <= hi)
    }
}

/// This connection's live request, marked in the frontier from before it is written until the
/// guard drops: when its exchange ends, however it ends (completion, failure, cancellation or
/// the connection's end). Replaced by the connection's next mark (a body's continuation).
pub(crate) struct Marked<'a> {
    frontier: &'a Frontier,
    key: (Digest32, Digest32, u64),
    token: u64,
}

impl Drop for Marked<'_> {
    fn drop(&mut self) {
        let mut inner = lock(&self.frontier.inner);
        if inner
            .asking
            .get(&self.key)
            .is_some_and(|(token, _)| *token == self.token)
        {
            inner.asking.remove(&self.key);
            inner.views.remove(&self.key.0);
        }
    }
}

/// An entry waiting: its author and seq, and its kept copy (the connection that checked it,
/// and the entry), unless it gave way ([`Frontier::shed`]).
type Waiter = ((Digest32, u64), Option<(Digest32, Ready)>);

impl FrontierInner {
    /// A position became ready, entered admission, waits, or none of these: its runs follow,
    /// and the room's view is built again on its next read. Returns whether a held control left
    /// the frontier unpublished here (owed again): its waiters must then be released.
    fn refresh(&mut self, room: Digest32, author: Digest32, seq: u64) -> bool {
        let key = (room, author, seq);
        let (admitting, waiting) = (
            self.admitting.contains_key(&key),
            self.waits_for.contains_key(&key),
        );
        for (runs, on) in [(&mut self.busy, admitting), (&mut self.waits, waiting)] {
            let positions = runs.entry((room, author)).or_default();
            positions.set(seq, on);
            if positions.is_empty() {
                runs.remove(&(room, author));
            }
        }
        self.views.remove(&room);
        if !admitting && !waiting {
            self.said.remove(&(room, Some((author, seq))));
        }
        !admitting && !waiting && self.unblock(room, author, seq)
    }

    /// Control `(author, seq)` is no longer held unadmitted here: returns whether it was.
    fn unblock(&mut self, room: Digest32, author: Digest32, seq: u64) -> bool {
        let Some(positions) = self.controls.get_mut(&(room, author)) else {
            return false;
        };
        let held = positions.contains(seq);
        positions.set(seq, false);
        if positions.is_empty() {
            self.controls.remove(&(room, author));
        }
        held
    }

    /// An entry checked by connection `peer` goes to the room's ready set.
    fn make_ready(&mut self, room: Digest32, peer: Digest32, item: Ready) {
        let (author, seq) = (item.entry.skeleton.author_id, item.entry.skeleton.seq);
        self.admitting.insert((room, author, seq), peer);
        self.queue(room, item);
        self.refresh(room, author, seq);
        self.quiet.remove(&room);
        self.rest.remove(&(room, author, seq));
    }

    /// An entry goes into the room's ready set in its class, classified here, at handover:
    /// urgent when its checked header is a control or an admission waiter waits for exactly
    /// its position (`Wait::At`); ordinary otherwise. A post (signed kind Content) is not
    /// runnable while a control of its own author below it is held here unadmitted: admission
    /// requires its predecessor's whole control prefix (`admission::preflight`), so it waits,
    /// with its kept copy, for the highest such control's position (`Wait::At`), and takes no
    /// turn meanwhile. Decided and registered in this one frontier lock hold, as that control's
    /// publication or departure clears it and releases its waiters (`published`, `release`):
    /// none can pass between. This is the one place a post's runnability is decided, both
    /// ways round: a post entering is checked against the controls held, and a control
    /// becoming held sends its author's queued posts above it through here again, so the
    /// ready set never holds a post a held control blocks.
    fn queue(&mut self, room: Digest32, item: Ready) {
        let (author, seq) = (item.entry.skeleton.author_id, item.entry.skeleton.seq);
        let control = is_control(&item.entry);
        if control {
            let held = self.controls.entry((room, author)).or_default();
            if !held.contains(seq) {
                held.set(seq, true);
                let blocked = self
                    .ready
                    .get_mut(&room)
                    .map(|ready| ready.posts_above(author, seq))
                    .unwrap_or_default();
                for post in blocked {
                    self.queue(room, post);
                }
            }
        } else if let Some(below) = self.blocker(room, &item.entry) {
            if let Some(peer) = self.admitting.remove(&(room, author, seq)) {
                self.wait(
                    room,
                    (author, seq),
                    Wait::At(author, below),
                    Some((peer, item)),
                );
                self.refresh(room, author, seq);
                return;
            }
        }
        let urgent = control || self.waiting.contains_key(&(room, Wait::At(author, seq)));
        self.ready.entry(room).or_default().push(item, urgent);
    }

    /// The highest control of a post's own author below it that is held here unadmitted: an
    /// authenticated positional fact (that control's checked header, handed over under a head
    /// committed here), never a claimed context, an advertised head or a later control.
    fn blocker(&self, room: Digest32, entry: &Entry) -> Option<u64> {
        let below = self
            .controls
            .get(&(room, entry.skeleton.author_id))?
            .present_below(entry.skeleton.seq.saturating_sub(1));
        (is_post(entry) && below > 0).then_some(below)
    }

    /// Entry `(author, seq)` waits for `wait`, with its kept copy (if any). The position a
    /// waiter waits for is urgent while one does, including when it is already in the ready
    /// set.
    fn wait(
        &mut self,
        room: Digest32,
        (author, seq): (Digest32, u64),
        wait: Wait,
        kept: Option<(Digest32, Ready)>,
    ) {
        self.waits_for.insert((room, author, seq), wait);
        self.waiting
            .entry((room, wait))
            .or_default()
            .push(((author, seq), kept));
        if let Wait::At(a, s) = wait {
            if let Some(ready) = self.ready.get_mut(&room) {
                ready.promote(a, s);
            }
        }
    }

    /// M13 (`VOX_MUTANT_NEED_SETTLES_EVERY_ROOT`, test-knobs only): when a root of the room's
    /// admission starts to wait (`Frontier::settled` for a need, `Frontier::wait_at_held` at a
    /// held control's position), every entry of the room's ready set, every author's, waits on
    /// that same wait: one author's wait holds the others' posts.
    #[cfg(feature = "test-knobs")]
    fn mutant_settles_every_root(&mut self, room: Digest32, wait: Wait) {
        if !mutant("VOX_MUTANT_NEED_SETTLES_EVERY_ROOT") {
            return;
        }
        for item in self.ready.remove(&room).unwrap_or_default().into_items() {
            let (author, seq) = (item.entry.skeleton.author_id, item.entry.skeleton.seq);
            let peer = self.admitting.remove(&(room, author, seq));
            self.waits_for.insert((room, author, seq), wait);
            let kept = peer.map(|peer| (peer, item));
            self.waiting
                .entry((room, wait))
                .or_default()
                .push(((author, seq), kept));
            self.refresh(room, author, seq);
        }
    }

    /// The entries waiting for `wait` stop waiting: the kept ones go to the ready set (where
    /// `queue` checks them again); the others are owed again. Returns how many went to the
    /// ready set. A position no waiter waits for any more keeps no priority from them. A held
    /// control released without its copy leaves the frontier unpublished, and its own waiters
    /// are released with it, in this loop.
    fn release(&mut self, room: Digest32, wait: Wait) -> usize {
        let mut released = 0;
        let mut ended = vec![wait];
        while let Some(wait) = ended.pop() {
            let Some(waiters) = self.waiting.remove(&(room, wait)) else {
                continue;
            };
            if let Wait::At(author, seq) = wait {
                if let Some(ready) = self.ready.get_mut(&room) {
                    ready.demote(author, seq);
                }
            }
            for ((author, seq), kept) in waiters {
                self.waits_for.remove(&(room, author, seq));
                match kept {
                    Some((peer, ready)) => {
                        if let Some((a, s)) = self.next_rest(room, (author, seq), wait) {
                            self.wait(room, (author, seq), Wait::At(a, s), Some((peer, ready)));
                            continue;
                        }
                        self.make_ready(room, peer, ready);
                        released += 1;
                    }
                    None => {
                        self.rest.remove(&(room, author, seq));
                        if self.refresh(room, author, seq) {
                            ended.push(Wait::At(author, seq));
                        }
                    }
                }
            }
        }
        released
    }

    /// The next control entry `(author, seq)` noted it lacks (`rest`) that is still held here
    /// unadmitted, other than the one whose wait just ended: an authenticated positional fact
    /// whose publication releases its waiters (`Frontier::published`). One not held (admitted
    /// meanwhile, or never handed) is passed over: the entry runs again and its walk decides.
    fn next_rest(
        &mut self,
        room: Digest32,
        (author, seq): (Digest32, u64),
        ended: Wait,
    ) -> Option<(Digest32, u64)> {
        let list = self.rest.get_mut(&(room, author, seq))?;
        while let Some((a, s)) = list.pop() {
            if Wait::At(a, s) != ended
                && self
                    .controls
                    .get(&(room, a))
                    .is_some_and(|held| held.contains(s))
            {
                if list.is_empty() {
                    self.rest.remove(&(room, author, seq));
                }
                return Some((a, s));
            }
        }
        self.rest.remove(&(room, author, seq));
        None
    }
}

/// One connection's assembly bound (C5): one answer and one largest entry (its body and
/// header), what its partial body can grow to.
const KEPT_BYTES: usize =
    crate::log::history::MAX_RESPONSE_BYTES + crate::log::history::MAX_ENTRY_WIRE;

/// The node's bound on all its loops' retained assembly together (answers awaiting their
/// handover, partial bodies, ready entries, entries in admission, kept waiting copies): a full
/// answer from each of 64 connections at once, and one largest entry.
const TOTAL_BYTES: usize =
    64 * crate::log::history::MAX_RESPONSE_BYTES + crate::log::history::MAX_ENTRY_WIRE;

/// The one owner of assembly memory (C5): what the loops hold of the answers they received,
/// counted at the wire bytes each answer arrived in, per connection (room and peer) and for
/// the node, by [`Charge`]s given back when they drop. An answer is charged as it arrives,
/// within [`TOTAL_BYTES`] (`exchange`); its charge then goes, undivided, to what it left: the
/// partial body it cut ([`Charge::split`], kept by the frontier, `Frontier::keep_partial`), and
/// the entries it handed over, which share the rest (headers, bodies and the answer's other
/// objects alike) until the last of them goes. A loop asks its peer only while its
/// connection holds room for one more answer within [`KEPT_BYTES`] (`ask`,
/// [`Connection::assembly_room`]). Short of room, what no admission holds gives way first
/// ([`Frontier::shed`]): the connection's kept waiting copies; for the node's count, every kept
/// copy, every ready entry no admission has taken (owed again) and every partial body (asked
/// again from its start). What is then left counted is held by this node's admission or by
/// answers being checked and handed, so the loop that waits for room waits only on this node,
/// holding no job, no byte admission and no lock: never on a peer. An answer still arriving is
/// not counted: it is within its request's wire credit, one per connection. A complete answer
/// the node's count has no room for is let go at once, before the loop waits (`exchange`).
#[derive(Default)]
struct Assembly {
    held: StdMutex<Held>,
    /// Moves whenever a charge is given back: what a loop short of room waits on.
    released: tokio::sync::watch::Sender<u64>,
}

#[derive(Default)]
struct Held {
    connections: HashMap<(Digest32, Digest32), usize>,
    total: usize,
}

/// Bytes of a connection's assembly, counted for it and for the node: given back when dropped.
/// The copies of an answer's entries (the ready set's, an admission's, a kept waiting one)
/// share its one charge, as they share their bodies.
struct Charge {
    assembly: Arc<Assembly>,
    connection: (Digest32, Digest32),
    bytes: usize,
}

impl Drop for Charge {
    fn drop(&mut self) {
        let mut held = lock(&self.assembly.held);
        if let Some(bytes) = held.connections.get_mut(&self.connection) {
            *bytes = bytes.saturating_sub(self.bytes);
            if *bytes == 0 {
                held.connections.remove(&self.connection);
            }
        }
        held.total = held.total.saturating_sub(self.bytes);
        drop(held);
        self.assembly
            .released
            .send_modify(|at| *at = at.wrapping_add(1));
    }
}

impl Charge {
    /// Up to `bytes` of this charge as a charge of their own: nothing is counted twice.
    fn split(&mut self, bytes: usize) -> Charge {
        let bytes = bytes.min(self.bytes);
        self.bytes -= bytes;
        Charge {
            assembly: Arc::clone(&self.assembly),
            connection: self.connection,
            bytes,
        }
    }

    /// `other`'s bytes counted as this charge's.
    fn join(&mut self, mut other: Charge) {
        self.bytes += std::mem::take(&mut other.bytes);
    }
}

impl Assembly {
    /// What `connection` holds.
    fn held(&self, connection: (Digest32, Digest32)) -> usize {
        lock(&self.held)
            .connections
            .get(&connection)
            .copied()
            .unwrap_or(0)
    }

    /// Whether the node's count has room for `bytes` more now.
    fn has_room(&self, bytes: usize) -> bool {
        lock(&self.held).total + bytes <= TOTAL_BYTES
    }

    /// `bytes` that arrived for `connection`, counted for it and for the node: none when the
    /// node's count would pass [`TOTAL_BYTES`]. A connection's own count is checked before it
    /// asks, not here.
    fn charge(self: &Arc<Self>, connection: (Digest32, Digest32), bytes: usize) -> Option<Charge> {
        let mut held = lock(&self.held);
        if held.total + bytes > TOTAL_BYTES {
            return None;
        }
        held.total += bytes;
        *held.connections.entry(connection).or_default() += bytes;
        Some(Charge {
            assembly: Arc::clone(self),
            connection,
            bytes,
        })
    }
}

/// What one answer leaves for the answer continuing it on the same connection, kept by the
/// frontier between the two asks (`Frontier::keep_partial`): the body it cut, or the contexts
/// it carried that no proof of it used yet (`bundle::Checked::unused`: the holder sends a
/// proof's contexts before the proof, so an answer that stops in between carries them ahead of
/// it). A carried context is never stored; it is handed to the next answer's check, and kept
/// there only if a proof of that answer uses it. `None`: this node stores it already, so only
/// its identity is carried.
pub(crate) struct Kept {
    partial: Option<Partial>,
    contexts: HashMap<Digest32, Option<crate::log::history::ControlContext>>,
}

/// The most contexts an answer may leave for its continuation: what one unfinished proof
/// stage of a Range bundle names, sent before its proof in one go (`server::send_contexts`).
/// An entry's inclusion and own-prefix proofs name the root, its pre-context, at most 48
/// siblings, the prefix and at most 49 consistency nodes (`MAX_TREE_DEPTH` 48): 100; the
/// leading consistency proof 51 and the terminal receipt 50. A control proof is cut by the
/// holder until it fits one whole answer (`server::control_fit`), so only a one-position proof
/// can be unfinished: its root, one collapse per level and its leaf's pre-context, 50.
const CARRIED_CONTEXTS: usize = 2 * crate::log::history::MAX_TREE_DEPTH + 4;

/// The most context identities one continuation holds: the stages an answer may complete
/// without completing anything the request wants, and one unfinished stage. Those are the
/// leading consistency proof (51) and terminal receipt (50), and a page's receipt of `lo - 1`
/// (an entry's proofs, [`CARRIED_CONTEXTS`]), then one unfinished stage (another
/// [`CARRIED_CONTEXTS`]): 301. A continuation ends with the first wanted thing an answer
/// completes (an entry, a body cut, a control proof): the next ask starts from that position
/// afresh.
const CONTINUED_CONTEXTS: usize = (crate::log::history::MAX_TREE_DEPTH + 3)
    + (crate::log::history::MAX_TREE_DEPTH + 2)
    + 2 * CARRIED_CONTEXTS;

// What those carried contexts take is bounded by their number: each is at most
// `MAX_CONTEXT_BYTES` as counted (`context_bytes`, 2048 coordinates at most), and 100 of them
// fit one largest entry, the part of a connection's assembly bound ([`KEPT_BYTES`]) a partial
// body would otherwise take.
const _: () = assert!(
    64 + crate::log::history::MAX_CONTEXT_AUTHORS
        * std::mem::size_of::<crate::log::history::EntryReference>()
        <= crate::log::history::MAX_CONTEXT_BYTES
);
const _: () = assert!(
    CARRIED_CONTEXTS * crate::log::history::MAX_CONTEXT_BYTES
        <= crate::log::history::MAX_ENTRY_WIRE
);

/// What one carried context takes in memory, as its charge counts it.
fn context_bytes(context: &crate::log::history::ControlContext) -> usize {
    64 + context.coordinates.len() * std::mem::size_of::<crate::log::history::EntryReference>()
}

/// A checked exact receipt of this node's own feed from one peer (ruling (d)): the peer's
/// role-complete head of this node, answered to `Query::Head(self)` under Control after the
/// peer flushed, staged here as any own head is. The actor routes it, under the same room
/// instance, epoch, authorization and connection it was checked under, to held-through,
/// settlement and departure.
#[derive(Clone, Copy, Debug)]
pub(crate) struct LoopReceipt {
    pub(crate) room: Digest32,
    pub(crate) peer: Digest32,
    pub(crate) connection: u64,
    pub(crate) head: Digest32,
    pub(crate) size: u64,
    pub(crate) epoch: u64,
    pub(crate) instance: [u8; 16],
    pub(crate) generation: Digest32,
}

/// One admission frontier for the node: per room, one ready set its one admission takes
/// from, and what exact evidence each dropped entry waits for. Woken by verified local changes
/// and by the needs the loops meet, never by a new head.
#[derive(Default)]
pub(crate) struct Frontier {
    inner: StdMutex<FrontierInner>,
    /// What the loops hold of bodies they fetched, per connection and handed (C5).
    assembly: Arc<Assembly>,
    /// Held by a loop's plan from reading the view until its choice is marked, never across
    /// an await: no two loops choose from the same marks.
    planning: StdMutex<()>,
    /// Every change a loop's plan reads (a need recorded, met or narrowed, an admission
    /// ended, a connection's entries dropped): the loops' third input.
    changed: tokio::sync::watch::Sender<u64>,
    /// The node's wake: a room's ready set grew.
    handed: tokio::sync::Notify,
    /// Rooms an admission published into since the actor last took them: whether it rendered
    /// a message and whether it made a governance fold pending.
    advanced: StdMutex<BTreeMap<Digest32, (bool, bool)>>,
    /// Woken when a room is marked advanced; the actor takes the marks when it next runs.
    pub(crate) advanced_wake: tokio::sync::Notify,
    /// (Room, member) pairs whose loop saved history this node did not hold since the actor
    /// last took them (`vox status` last sync); woken by `advanced_wake`.
    brought: StdMutex<BTreeSet<(Digest32, Digest32)>>,
    /// Exact receipts the loops checked since the actor last took them; woken by
    /// `advanced_wake`.
    receipts: StdMutex<Vec<LoopReceipt>>,
    /// Private Session debt (`PrivateDebt`); what ended is woken by `advanced_wake`.
    private: StdMutex<PrivateDebt>,
}

impl Frontier {
    fn change(&self) {
        self.changed.send_modify(|at| *at = at.wrapping_add(1));
    }

    /// Mark `ask` as the one live request of connection `key` (room, peer, serial), replacing
    /// its previous mark. Changes no debt, need, readiness or wake: a mark only orders a plan's
    /// choices.
    fn mark(&self, key: (Digest32, Digest32, u64), ask: &Ask) -> Marked<'_> {
        let asking = Asking {
            author: ask.author,
            want: ask.want,
        };
        let mut inner = lock(&self.inner);
        inner.marked += 1;
        let token = inner.marked;
        inner.asking.insert(key, (token, asking));
        inner.views.remove(&key.0);
        Marked {
            frontier: self,
            key,
            token,
        }
    }

    /// An admission published into `room`: marked for the actor, never waiting for it. The
    /// marks coalesce per room however many publications happen while the actor is busy.
    pub(crate) fn advanced(&self, room: Digest32, rendered: bool, governance: bool) {
        let mut advanced = lock(&self.advanced);
        let mark = advanced.entry(room).or_default();
        mark.0 |= rendered;
        mark.1 |= governance;
        drop(advanced);
        self.advanced_wake.notify_one();
    }

    /// The rooms advanced since the last take (see [`Self::advanced`]).
    pub(crate) fn take_advanced(&self) -> BTreeMap<Digest32, (bool, bool)> {
        std::mem::take(&mut *lock(&self.advanced))
    }

    /// The saved intent `request` is owed `owed`, beside every other owed intent; the loops plan
    /// from it at once.
    pub(crate) fn owe_archive(&self, request: super::RequestId, owed: ArchiveOwed) {
        let mut inner = lock(&self.inner);
        inner.archive.retain(|_, was| !was.fence.is_retired());
        inner.views.remove(&owed.room);
        inner.archive.insert(request, owed);
        drop(inner);
        self.change();
    }

    /// The saved intent `request` is owed no more (its controller retired its fence).
    pub(crate) fn forgive_archive(&self, request: super::RequestId) {
        let mut inner = lock(&self.inner);
        if let Some(was) = inner.archive.remove(&request) {
            inner.views.remove(&was.room);
        }
        drop(inner);
        lock(&self.private).owed.remove(&request);
    }

    /// The saved private request `request` is owed `owed` to its donor's connection, beside
    /// every other owed request; that connection's loop asks it at once.
    pub(crate) fn owe_private(&self, request: super::RequestId, owed: PrivateOwed) {
        let mut private = lock(&self.private);
        private.owed.retain(|_, was| !was.fence.is_retired());
        private.owed.insert(request, owed);
        drop(private);
        self.change();
    }

    /// The first saved private request of `room` owed to `donor`'s connection.
    pub(super) fn private_owed(
        &self,
        room: Digest32,
        donor: Digest32,
    ) -> Option<(super::RequestId, PrivateOwed)> {
        lock(&self.private)
            .owed
            .iter()
            .find(|(_, owed)| owed.room == room && owed.donor == donor && !owed.fence.is_retired())
            .map(|(request, owed)| (*request, owed.clone()))
    }

    /// A private request's page was saved natively: its plan advances; once its inventory is
    /// done and no position remains it is complete, owed no more, and the actor settles it.
    pub(super) fn private_progress(
        &self,
        request: super::RequestId,
        next: crate::node::history_demand::PrivatePlan,
    ) {
        let mut private = lock(&self.private);
        if next.inventory_done && next.positions.is_empty() {
            if private.owed.remove(&request).is_some() {
                private.settled.push((request, Ok(())));
                drop(private);
                self.advanced_wake.notify_one();
            }
        } else if let Some(owed) = private.owed.get_mut(&request) {
            owed.plan = next;
        }
    }

    /// A private request cannot go on as saved (its donor, incarnation, grant or interval no
    /// longer authorize it, or a page failed its native admission): owed no more, and the actor
    /// pauses it with `reason` until the person resumes or cancels it.
    pub(super) fn private_stopped(&self, request: super::RequestId, reason: String) {
        let mut private = lock(&self.private);
        if private.owed.remove(&request).is_some() {
            private.settled.push((request, Err(reason)));
            drop(private);
            self.advanced_wake.notify_one();
        }
    }

    /// The private requests that completed or stopped since the last take.
    pub(crate) fn take_private_settled(
        &self,
    ) -> Vec<(super::RequestId, std::result::Result<(), String>)> {
        std::mem::take(&mut lock(&self.private).settled)
    }

    /// How many times `room`'s private news was raised: a loop that found no private work at
    /// one value looks again only at another, or at a new private tip of its peer.
    pub(super) fn private_news(&self, room: Digest32) -> u64 {
        lock(&self.private)
            .news
            .get(&room)
            .map_or(0, |(news, _)| *news)
    }

    /// How many times `room`'s private news was a change of what this node may serve a peer
    /// (`private_permission`): a connection's teller decides what it tells again at another.
    pub(super) fn private_permission_serial(&self, room: Digest32) -> u64 {
        lock(&self.private)
            .news
            .get(&room)
            .map_or(0, |(_, permission)| *permission)
    }

    /// A local change that can make `room`'s old automatic private debt runnable, or a waiting
    /// private page admissible (a key, floor, opening, projection, trust or governance change):
    /// every loop of the room plans its private debt again.
    pub(crate) fn private_wake(&self, room: Digest32) {
        self.private_news_raise(room, false);
    }

    /// `private_wake`, for a committed change of what this node may serve a peer (membership,
    /// removal or standing, the keyring's Drive holders, Session floors, an author's Session
    /// controls becoming current): its permission-change serial moves too, so every teller of
    /// the room decides again what it tells. Raised only by the step that made the change.
    pub(crate) fn private_permission(&self, room: Digest32) {
        self.private_news_raise(room, true);
    }

    fn private_news_raise(&self, room: Digest32, permission: bool) {
        let mut private = lock(&self.private);
        let (news, serial) = private.news.entry(room).or_default();
        *news = news.wrapping_add(1);
        if permission {
            *serial = serial.wrapping_add(1);
        }
        drop(private);
        lock(&self.inner).quiet.remove(&room);
        self.change();
    }

    /// A connection hands checked entries to the room's ready set. A position already ready,
    /// in admission or waiting is owned by that one admission: a second copy is not admitted.
    /// Every entry is handed under a head committed here (`exchange`). Returns the positions
    /// taken, so the caller judges its answer by what admission actually got.
    fn hand(&self, room: Digest32, peer: Digest32, items: Vec<Ready>) -> Vec<u64> {
        let mut inner = lock(&self.inner);
        let mut taken = Vec::new();
        for item in items {
            let key = (room, item.entry.skeleton.author_id, item.entry.skeleton.seq);
            if !inner.admitting.contains_key(&key) && !inner.waits_for.contains_key(&key) {
                taken.push(key.2);
                inner.make_ready(room, peer, item);
            }
        }
        drop(inner);
        if !taken.is_empty() {
            self.handed.notify_one();
            self.change();
        }
        taken
    }

    /// The next growth of any room's ready set (a stored permit: none is lost). With a consent
    /// a proof holds (`test-knobs`), also its release: it is then ready again.
    pub(crate) async fn handed(&self) {
        #[cfg(feature = "test-knobs")]
        while !lock(&self.inner).held_consents.is_empty() {
            tokio::select! {
                () = self.handed.notified() => return,
                () = tokio::time::sleep(std::time::Duration::from_millis(20)) => {
                    if lock(&self.inner).release_held_consents() {
                        return;
                    }
                }
            }
        }
        self.handed.notified().await;
    }

    /// A room's admission ended: what is ready meanwhile can start.
    pub(crate) fn wake(&self) {
        self.handed.notify_one();
    }

    /// A room's admission begins: the room is quiet until news ([`FrontierInner::quiet`]).
    pub(crate) fn admission_began(&self, room: Digest32) {
        lock(&self.inner).quiet.insert(room);
    }

    /// Say in the daemon log, once per entry and cause, why a room's admission failed and what
    /// it waits for before it tries again (`clears`: a local release, otherwise news).
    pub(crate) fn failed_admission_said(
        &self,
        room: Digest32,
        root: Option<(Digest32, u64)>,
        error: &crate::error::Error,
        clears: bool,
    ) {
        let cause = error.to_string();
        {
            let mut inner = lock(&self.inner);
            if inner.said.get(&(room, root)) == Some(&cause) {
                return;
            }
            let retained = root.is_none_or(|(author, seq)| {
                let key = (room, author, seq);
                inner.admitting.contains_key(&key) || inner.waits_for.contains_key(&key)
            });
            if retained {
                inner.said.insert((room, root), cause.clone());
            }
        }
        let what = match root {
            Some((author, seq)) => format!(
                "entry {seq} of {} is not admitted yet",
                crate::node::network::short_id(author)
            ),
            None => "admission stopped".to_owned(),
        };
        let waits = if clears {
            "it waits for the room's write to be released and is tried again"
        } else {
            "it waits for a change that can admit it (a new entry, key, trust, governance or room change)"
        };
        eprintln!(
            "vox: room {}: {what}: {}; {waits}",
            crate::node::network::short_id(room),
            cause
        );
    }

    /// The one recovery edge of a failed room admission (design simple-sync §3): what can
    /// change its outcome since it began, and nothing else. Returns at the first of:
    /// - its fence retired: its room or the node retired or replaced it (leave, close,
    ///   removal, lock);
    /// - the room's published snapshot revoked (locked, poisoned by a failed save, gone; a
    ///   reopened room publishes a new one) or at another epoch than the admission's;
    /// - news here: an entry made ready in the room (handed by a connection, or released by a
    ///   need met or a position admitted), or the room's private news (a key, floor, opening,
    ///   projection, trust, governance or permission change).
    ///
    /// The failed admission's own cleanup raises none of these: its publication republishes
    /// the same epoch, and its root goes back to the ready set without being made ready again
    /// (`give_back`). A wake that changed none of them waits again: no timer, no count.
    pub(crate) async fn failed_admission_news(
        &self,
        room: Digest32,
        epoch: u64,
        record: &crate::node::channel::RoomSnapshotCell,
        fence: &Fence,
    ) {
        let mut changed = self.changed.subscribe();
        let mut published = record.next_publication();
        loop {
            changed.borrow_and_update();
            published.borrow_and_update();
            if !lock(&self.inner).quiet.contains(&room)
                || record
                    .current()
                    .is_none_or(|snapshot| snapshot.epoch() != epoch)
            {
                return;
            }
            tokio::select! {
                biased;
                () = fence.retired() => return,
                changed = changed.changed() => if changed.is_err() { return },
                published = published.changed() => if published.is_err() { return },
            }
        }
    }

    /// The rooms whose ready set is not empty.
    pub(crate) fn ready_rooms(&self) -> Vec<Digest32> {
        lock(&self.inner)
            .ready
            .iter()
            .filter(|(_, ready)| !ready.is_empty())
            .map(|(room, _)| *room)
            .collect()
    }

    /// Whether the room's ready set holds an entry.
    pub(crate) fn has_ready(&self, room: Digest32) -> bool {
        lock(&self.inner)
            .ready
            .get(&room)
            .is_some_and(|ready| !ready.is_empty())
    }

    /// `bytes` of `connection`'s assembly as an admission's headroom ([`CheckedRoom`]), taken
    /// before its root leaves the ready set (C5, [`Assembly`]): short of room, what no admission
    /// holds gives way first ([`Self::shed`], every room); none when even then the node's count
    /// has no room.
    fn reserve_checked(
        &self,
        connection: (Digest32, Digest32),
        bytes: usize,
    ) -> Option<CheckedRoom> {
        self.assembly
            .charge(connection, bytes)
            .or_else(|| {
                self.shed(None)
                    .then(|| self.assembly.charge(connection, bytes))
                    .flatten()
            })
            .map(CheckedRoom)
    }

    /// [`Self::reserve_checked`], or, while the node's count has no room even then, the wake
    /// of its next release: what is left counted is held by running admissions (each within
    /// its own headroom, which it never waits to grow) and the answers being checked, which
    /// give it back by themselves (C5). The wake is taken before the room is looked for, so no
    /// release between the two is missed.
    pub(super) fn reserve_checked_or_wake(
        &self,
        connection: (Digest32, Digest32),
        bytes: usize,
    ) -> std::result::Result<CheckedRoom, AssemblyWake> {
        let mut released = self.assembly.released.subscribe();
        self.reserve_checked(connection, bytes).ok_or_else(|| {
            Box::pin(async move {
                let _ = released.changed().await;
            }) as AssemblyWake
        })
    }

    /// The room's admission takes ONE entry: urgent and ordinary alternating, each in its
    /// rotation over authors ([`ReadySet`]).
    pub(crate) fn take(&self, room: Digest32) -> Option<Ready> {
        let mut inner = lock(&self.inner);
        #[cfg(feature = "test-knobs")]
        inner.release_held_consents();
        let ready = inner.ready.get_mut(&room)?;
        let item = ready.take();
        // `VOX_TEST_HOLD_INCOMING_CONSENT_FILE`: a held consent leaves the ready set instead of
        // being admitted; the admission takes the next entry (`FrontierInner::held_consents`).
        #[cfg(feature = "test-knobs")]
        let (mut item, mut held) = (item, Vec::new());
        #[cfg(feature = "test-knobs")]
        while let Some(consent) = item.take_if(|item| held_consent(&item.entry)) {
            held.push((room, consent));
            item = ready.take();
        }
        if ready.is_empty() {
            inner.ready.remove(&room);
        }
        #[cfg(feature = "test-knobs")]
        inner.held_consents.extend(held);
        item
    }

    /// An admission that is replaced (its authorization changed) gives its root back to the
    /// ready set, still in admission, in its class: the room's next admission takes it in its
    /// author's turn.
    pub(crate) fn give_back(&self, room: Digest32, item: Ready) {
        lock(&self.inner).queue(room, item);
    }

    /// Admission of this entry ended unpublished: failed, or dropped for `need` (with the head
    /// it names, read once by admission). A dropped entry waits: for position `at` when the need
    /// is an entry of a position not admitted here yet (the need stays only so that a loop
    /// fetches that position if no connection holds it), otherwise for the need itself. A
    /// control owed again (no need) leaves the frontier: what waits for its position is
    /// released and checked again.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn settled(
        &self,
        room: Digest32,
        author: Digest32,
        seq: u64,
        need: Option<(Need, Option<Arc<SignedHead>>)>,
        kept: Option<(Digest32, Ready)>,
        at: Option<(Digest32, u64)>,
        also: Vec<(Digest32, u64)>,
    ) {
        let mut inner = lock(&self.inner);
        inner.admitting.remove(&(room, author, seq));
        if let Some((need, head)) = need {
            inner.needs.entry(room).or_default().insert(need, head);
            let wait = at.map_or(Wait::Need(need), |(a, s)| Wait::At(a, s));
            // The entry stays in its connection's assembly, already counted there
            // (`Ready::charge`), so the wait's end admits it without a second fetch; when
            // assembly is short of room it gives way and only its place is kept
            // ([`Frontier::shed`]).
            // With the other controls it lacks (`also`), it waits for each in turn.
            if kept.is_some() && !also.is_empty() {
                inner.rest.insert((room, author, seq), also);
            }
            inner.wait(room, (author, seq), wait, kept);
            // M13 (`VOX_MUTANT_NEED_SETTLES_EVERY_ROOT`): every entry of the room's ready set,
            // every author's, waits on this one need too.
            #[cfg(feature = "test-knobs")]
            inner.mutant_settles_every_root(room, wait);
        }
        let released = if inner.refresh(room, author, seq) {
            inner.release(room, Wait::At(author, seq))
        } else {
            0
        };
        drop(inner);
        if released > 0 {
            self.handed.notify_one();
        }
        self.change();
    }

    /// Root `(author, seq)` of a room's admission waits for position `(a, s)` if that position
    /// is a control handed here and not admitted yet (`controls`), with its kept copy and the
    /// other controls it lacks (`also`, taken only when it waits). Decided and registered in one
    /// frontier lock hold, so that position's publication (`published`, which unblocks it in the
    /// same lock) either came before and the root does not wait, or comes after and releases
    /// it. Returns whether it waits.
    pub(crate) fn wait_at_held(
        &self,
        room: Digest32,
        (author, seq): (Digest32, u64),
        (a, s): (Digest32, u64),
        kept: (Digest32, Ready),
        also: &mut Vec<(Digest32, u64)>,
    ) -> bool {
        let mut inner = lock(&self.inner);
        if !inner
            .controls
            .get(&(room, a))
            .is_some_and(|held| held.contains(s))
        {
            return false;
        }
        inner.admitting.remove(&(room, author, seq));
        if !also.is_empty() {
            inner.rest.insert((room, author, seq), std::mem::take(also));
        }
        inner.wait(room, (author, seq), Wait::At(a, s), Some(kept));
        // M13: the second place a root waits (at a held control's position) settles every
        // entry of the room's ready set on that wait too, as `settled` does.
        #[cfg(feature = "test-knobs")]
        inner.mutant_settles_every_root(room, Wait::At(a, s));
        let released = if inner.refresh(room, author, seq) {
            inner.release(room, Wait::At(author, seq))
        } else {
            0
        };
        drop(inner);
        if released > 0 {
            self.handed.notify_one();
        }
        self.change();
        true
    }

    /// Position `(author, seq)` was admitted: it is settled, the connection that handed it over
    /// brought history this node did not hold (`vox status` last sync), it blocks no post any
    /// more, and the entries waiting for it go to the ready set (each checked again there),
    /// which the room's admission takes next; those not kept are owed again. This and
    /// [`FrontierInner::release`] are where every `Wait::At` waiter becomes runnable again.
    pub(crate) fn published(&self, room: Digest32, author: Digest32, seq: u64) {
        let (released, peer) = {
            let mut inner = lock(&self.inner);
            let peer = inner.admitting.remove(&(room, author, seq));
            inner.refresh(room, author, seq);
            inner.unblock(room, author, seq);
            (inner.release(room, Wait::At(author, seq)), peer)
        };
        if let Some(peer) = peer {
            self.brought(room, peer);
        }
        if released > 0 {
            self.handed.notify_one();
        }
        self.change();
    }

    /// A connection's loop saved history this node did not hold, from `peer`: marked for the
    /// actor's one `last sync` rule, never waited for.
    fn brought(&self, room: Digest32, peer: Digest32) {
        lock(&self.brought).insert((room, peer));
        self.advanced_wake.notify_one();
    }

    /// The (room, member) pairs marked [`Self::brought`] since the last take.
    pub(crate) fn take_brought(&self) -> BTreeSet<(Digest32, Digest32)> {
        std::mem::take(&mut *lock(&self.brought))
    }

    /// A loop checked an exact receipt of this node's feed: for the actor.
    fn receipt(&self, receipt: LoopReceipt) {
        lock(&self.receipts).push(receipt);
        self.advanced_wake.notify_one();
    }

    /// The receipts checked since the last take (see [`Self::receipt`]).
    pub(crate) fn take_receipts(&self) -> Vec<LoopReceipt> {
        std::mem::take(&mut *lock(&self.receipts))
    }

    /// A loop checked an answer that brought `need`, or found every position it named admitted
    /// (`at`, the last of them): every entry waiting for it is owed again, and the kept ones go
    /// to the ready set.
    fn met(&self, room: Digest32, need: &Need, at: Option<(Digest32, u64)>) {
        let mut inner = lock(&self.inner);
        if let Some(needs) = inner.needs.get_mut(&room) {
            needs.remove(need);
        }
        inner.views.remove(&room);
        inner.release(room, Wait::Need(*need));
        if let Some((author, seq)) = at {
            inner.release(room, Wait::At(author, seq));
        }
        drop(inner);
        self.handed.notify_one();
        self.change();
    }

    /// An answer brought the receipts of `positions` of `author` (header, inclusion and own
    /// prefix), under whatever head: every position need of that author naming one of them is
    /// met.
    fn received(&self, room: Digest32, author: Digest32, positions: &[u64]) {
        self.meet(room, |need| {
            matches!(need, Need::Position { author: a, seq } if a == author && positions.contains(&seq))
        });
    }

    /// The author's verified control coverage runs from position 1 through `through`, whatever
    /// committed head proved it: every coverage need of that author it reaches is met.
    fn covered(&self, room: Digest32, author: Digest32, through: u64) {
        self.meet(room, |need| {
            matches!(need, Need::Controls { author: a, hi, .. } if a == author && hi <= through)
        });
    }

    fn meet(&self, room: Digest32, met: impl Fn(Need) -> bool) {
        let met: Vec<Need> = lock(&self.inner)
            .needs
            .get(&room)
            .into_iter()
            .flat_map(BTreeMap::keys)
            .copied()
            .filter(|need| met(*need))
            .collect();
        for need in &met {
            self.met(room, need, None);
        }
    }

    /// The connection ended: only its private assembly goes, the copies it kept of waiting
    /// entries (each keeps its place) and the body it was assembling. What it handed over is
    /// the room's.
    fn forget(&self, room: Digest32, peer: Digest32) {
        let mut inner = lock(&self.inner);
        for ((r, _), waiters) in &mut inner.waiting {
            if *r == room {
                for (_, kept) in waiters.iter_mut() {
                    if kept.as_ref().is_some_and(|(p, _)| *p == peer) {
                        *kept = None;
                    }
                }
            }
        }
        inner
            .partials
            .retain(|(r, p, _), _| !(*r == room && *p == peer));
        drop(inner);
        self.change();
    }

    /// Assembly short of room gives way where nothing is lost (C5, [`Assembly`]): the copies
    /// of waiting entries that connection `only` (room, peer) checked, or, with none, every
    /// kept copy, every ready entry no admission has taken and every partial body, in every
    /// room. A copy's entry keeps its place and is fetched again once its wait is over; a ready
    /// entry is owed again (a ready control's waiters with it); a partial body is asked again
    /// from its start. What an admission holds is never let go. Returns whether anything was.
    fn shed(&self, only: Option<(Digest32, Digest32)>) -> bool {
        let mut guard = lock(&self.inner);
        let inner = &mut *guard;
        let mut any = false;
        for waiters in inner.waiting.values_mut() {
            for (_, kept) in waiters.iter_mut() {
                if kept
                    .as_ref()
                    .is_some_and(|(_, ready)| only.is_none_or(|key| ready.charge.connection == key))
                {
                    *kept = None;
                    any = true;
                }
            }
        }
        if only.is_none() {
            for (room, ready) in std::mem::take(&mut inner.ready) {
                for item in ready.into_items() {
                    let (author, seq) = (item.entry.skeleton.author_id, item.entry.skeleton.seq);
                    inner.admitting.remove(&(room, author, seq));
                    if inner.refresh(room, author, seq) {
                        inner.release(room, Wait::At(author, seq));
                    }
                    any = true;
                }
            }
            if !inner.partials.is_empty() {
                inner.partials.clear();
                any = true;
            }
        }
        drop(guard);
        if any {
            self.change();
        }
        any
    }

    /// Connection `key` (room, peer, serial) keeps what its answer left for the next (the body
    /// it cut, or the contexts it carried that no proof used yet), with its charge, until its
    /// next ask continues it ([`Self::take_partial`]), or it gives way.
    fn keep_partial(&self, key: (Digest32, Digest32, u64), kept: Kept, charge: Charge) {
        lock(&self.inner).partials.insert(key, (kept, charge));
    }

    /// What connection `key` kept for its continuation, if it did not give way meanwhile.
    fn take_partial(&self, key: (Digest32, Digest32, u64)) -> Option<(Kept, Charge)> {
        lock(&self.inner).partials.remove(&key)
    }

    /// The room's view for one plan, under one lock: built again only after a change.
    fn view(&self, room: Digest32) -> Arc<View> {
        let mut inner = lock(&self.inner);
        if let Some(view) = inner.views.get(&room) {
            return Arc::clone(view);
        }
        // The marks' coverage is derived from the live requests alone, so one request's end
        // never clears another's overlap.
        let mut asked: HashMap<Digest32, Runs> = HashMap::new();
        let mut controls: HashMap<Digest32, Runs> = HashMap::new();
        for (_, live) in inner.asking.iter().filter(|((r, _, _), _)| *r == room) {
            let (lo, hi) = live.1.want.interval();
            let runs = if matches!(live.1.want, RangeWant::Controls { .. }) {
                &mut controls
            } else {
                &mut asked
            };
            runs.entry(live.1.author).or_default().insert(lo, hi);
        }
        let view = Arc::new(View {
            needs: inner
                .needs
                .get(&room)
                .map(|needs| {
                    needs
                        .iter()
                        .map(|(need, head)| (*need, head.clone()))
                        .collect()
                })
                .unwrap_or_default(),
            busy: inner
                .busy
                .iter()
                .filter(|((r, _), _)| *r == room)
                .map(|((_, author), runs)| (*author, runs.clone()))
                .collect(),
            waits: inner
                .waits
                .iter()
                .filter(|((r, _), _)| *r == room)
                .map(|((_, author), runs)| (*author, runs.clone()))
                .collect(),
            asked,
            controls,
            archive: inner
                .archive
                .values()
                .filter(|owed| owed.room == room && !owed.fence.is_retired())
                .cloned()
                .collect(),
        });
        inner.views.insert(room, Arc::clone(&view));
        view
    }

    /// A need answered in part: what remains of it, from the holder's explicit next position.
    fn narrow(&self, room: Digest32, need: &Need, rest: Need) {
        let mut inner = lock(&self.inner);
        if let Some(needs) = inner.needs.get_mut(&room) {
            if let Some(head) = needs.remove(need) {
                needs.insert(rest, head);
            }
        }
        inner.views.remove(&room);
        if let Some(waiters) = inner.waiting.remove(&(room, Wait::Need(*need))) {
            for ((author, seq), _) in &waiters {
                inner
                    .waits_for
                    .insert((room, *author, *seq), Wait::Need(rest));
            }
            inner
                .waiting
                .entry((room, Wait::Need(rest)))
                .or_default()
                .extend(waiters);
        }
        drop(inner);
        self.change();
    }
}

/// Positions a plan may ask: neither walked here nor ready, in admission or waiting, nor (in a
/// plan's first pass of a class) asked by a live request. Each query moves by runs.
struct Owed<'a> {
    runs: [Option<&'a Runs>; 4],
}

impl Owed<'_> {
    fn runs(&self) -> impl Iterator<Item = &Runs> {
        self.runs.iter().flatten().copied()
    }

    /// The lowest owed position from `seq` up.
    fn from(&self, mut seq: u64) -> u64 {
        loop {
            let next = self.runs().fold(seq, |seq, runs| runs.absent_from(seq));
            if next == seq {
                return seq;
            }
            seq = next;
        }
    }

    /// The highest owed position from `seq` down (0 when none is).
    fn below(&self, mut seq: u64) -> u64 {
        loop {
            let next = self.runs().fold(seq, |seq, runs| runs.absent_below(seq));
            if next == seq || next == 0 {
                return next;
            }
            seq = next;
        }
    }

    /// The end of the run of owed positions starting at owed `seq`, at most `hi`.
    fn run_end(&self, seq: u64, hi: u64) -> u64 {
        let next = self
            .runs()
            .map(|runs| runs.present_from(seq))
            .min()
            .unwrap_or(u64::MAX);
        hi.min(next.saturating_sub(1))
    }

    /// The start of the run of owed positions ending at owed `seq`, at least `lo`.
    fn run_start(&self, seq: u64, lo: u64) -> u64 {
        let previous = self
            .runs()
            .map(|runs| runs.present_below(seq))
            .max()
            .unwrap_or(0);
        lo.max(previous + 1)
    }
}

// ---------------------------------------------------------------------------------------------
// One connection.

/// Everything one connection's loop uses. The loop is registered for the life of its connection
/// in its room (ruling correction 3): the fence ends with the connection, the room instance or
/// epoch, or the peer's membership, never with a refusal.
pub(crate) struct Connection {
    pub(crate) room: Digest32,
    pub(crate) peer: Digest32,
    pub(crate) node: Digest32,
    pub(crate) epoch: u64,
    pub(crate) shared: Arc<crate::node::channel::RoomLock>,
    /// The room's published snapshot: this node's own standing in the room, read for news.
    pub(crate) cell: Arc<RoomSnapshotCell>,
    pub(crate) store: Arc<Store>,
    pub(crate) conn: Arc<VoxConnection>,
    pub(crate) budget: Arc<Budget>,
    pub(crate) holdings: Arc<Holdings>,
    pub(crate) frontier: Arc<Frontier>,
    pub(crate) fence: Arc<Fence>,
    /// This node's own board records for the room, put on the peer's board before the first
    /// stream of this connection for the room (ADR-054 PL-1, ledger 91).
    pub(crate) introduction: Arc<[Vec<u8>]>,
    /// `vox status` per room and peer: this loop's exchanges and failures.
    pub(crate) book: crate::node::status::SharedSyncBook,
    /// While set, nothing is sent to the peer for this room: an exchange was refused or failed,
    /// and this is the news that exchange had seen before it began. Only later news clears it
    /// ([`Connection::until_news`]).
    pub(crate) parked: StdMutex<Option<News>>,
    /// While parked on a cause here rather than at the peer, the local edge the park waits on
    /// besides news ([`Connection::until_news`]).
    pub(crate) local: StdMutex<Option<LocalWait>>,
    /// The peer's last role-complete head of this node that this connection asked the exact
    /// receipt for: asked once per head the peer's Have names (no retry).
    pub(crate) receipt: StdMutex<Option<Digest32>>,
    /// Where this connection's private Session pages go for native admission (the actor's
    /// private save, `actor::private_save`): the loop asks, the native owner admits.
    pub(crate) private: super::private::PrivateSink,
    /// What this node serves, as the actor publishes it: whom its keyring trusts with Drive.
    pub(crate) serving: Arc<super::Serving>,
    /// This connection's member-board exchange (`Node::read_member_board`): at most one runs
    /// and at most one more is owed, however many times it is asked for.
    pub(crate) board: StdMutex<BoardTurn>,
}

/// Whether a connection's board exchange is running, and whether another is owed after it. The
/// owed one reads the boards as they are when it runs, so many growths are one exchange.
#[derive(Default)]
pub(crate) struct BoardTurn {
    pub(crate) running: bool,
    pub(crate) owed: bool,
}

/// The local edge a connection parked on a local failure waits for: this node's byte budget
/// releasing what the exchange lacked, or the room's next publication (a local store or room
/// state fault). Neither is the peer's news, and neither is a timer.
pub(crate) enum LocalWait {
    Bytes(crate::node::history_budget::BytePressure),
    Room,
}

/// What a parked connection waits to change: the version of the peer's Have on this connection,
/// raised only by what changes what this node knows the peer holds (a Have page or private
/// section, [`Holdings::merge`]; a page told again unchanged raises nothing),
/// and this node's own standing in the room as published (its epoch, whether it is an author,
/// whether it has left, its recovery standing). Unrelated local publications change neither.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct News {
    have: u64,
    standing: Option<(u64, bool, bool, bool)>,
}

fn gone() -> Error {
    Error::Unreachable("connection ended")
}

/// A holder's refusal (it declined, or its reply gave this node nothing while the record of the
/// author stood: the no-progress rule in `exchange`), as the error its connection parks on
/// ([`Connection::refused`]): sent nothing more until the peer's news, and named as the peer's
/// last failure in `vox status`.
fn refusal(status: Status) -> Error {
    match status {
        Status::Busy => Error::PeerRefused(crate::wire::WireError::SessionBusy),
        _ => Error::Unreachable("the peer answered without what it was asked"),
    }
}

/// The loop's standing ended: the room's epoch moved on, or the peer is no longer a member (or
/// its removal was applied here).
const NOT_MEMBER: &str = "connection's peer is no longer a member";

impl Connection {
    /// One bounded local step under the room's lock, off the async runtime.
    async fn with_room<T: Send + 'static>(
        &self,
        work: impl FnOnce(&mut ChannelState, &Store, &PendingHistoryRead) -> Result<T> + Send + 'static,
    ) -> Result<T> {
        // The room's own save holds its history writes: wait for its release edge (local work,
        // this connection only), never answer it as an error.
        let room = loop {
            let room = tokio::select! {
                biased;
                () = self.fence.retired() => return Err(gone()),
                room = Arc::clone(&self.shared).lock_owned() => room,
            };
            if !room.post_pending() && !room.history_publication_busy(&self.store)? {
                break room;
            }
            let wake = room.history_publication_wake();
            drop(room);
            tokio::select! {
                biased;
                () = self.fence.retired() => return Err(gone()),
                () = wake => {}
            }
        };
        let mut room = room;
        let store = Arc::clone(&self.store);
        let (epoch, peer) = (self.epoch, self.peer);
        tokio::task::spawn_blocking(move || {
            if room.epoch() != epoch
                || room.standing(&store, &peer)?.is_none()
                || room.peer_removal_applied(&store, &peer)?
            {
                return Err(Error::Unreachable(NOT_MEMBER));
            }
            // Readers' view is pinned before the step and published again after it, as the
            // source writer does: readers are answered from the pinned view meanwhile, so no
            // commit of the step refuses a read. The step writes history only through the pin
            // (`PinnedHistory`).
            let mut pin = room.pin_history_read(Arc::clone(&store))?;
            let result = work(&mut room, &store, &pin);
            if let Err(error) = room.publish_history_read(Arc::clone(&store)) {
                pin.retain_saved_read();
                return Err(error);
            }
            drop(pin);
            result
        })
        .await
        .map_err(|_| Error::Unreachable("history loop worker stopped"))?
    }

    fn preamble(&self, purpose: Purpose) -> Result<Preamble> {
        Ok(Preamble {
            room: self.room,
            epoch: self.epoch,
            purpose,
            request: crate::identity::rng::random_array::<16>()?,
        })
    }

    pub(super) async fn job(&self) -> Result<crate::node::history_budget::Job> {
        tokio::select! {
            biased;
            () = self.fence.retired() => Err(gone()),
            job = self.budget.admit_job(self.node, Lane::Live) => Ok(job),
        }
    }

    /// An exchange this node asked of the peer ended without error: a round of this node's in
    /// `vox status`, which also ends a standing failure (#1401). `brought`: it saved history
    /// this node did not hold (`last sync`).
    pub(super) fn answered(&self, reason: crate::node::status::RoundReason, brought: bool) {
        // The peer answered a version-3 request: the exchange the room's keys need (R10). The
        // connection's evidence of another version is retired: a later failure is its own.
        self.holdings
            .exchanged(self.room, self.peer, &self.conn, self.epoch);
        self.conn.retire_other_version();
        crate::node::status::SyncBook::with(&self.book, self.room, self.peer, |counts| {
            counts.note_fetched(reason, brought);
            if brought {
                counts.history_fetched += 1;
            }
        });
        if brought {
            self.frontier.brought(self.room, self.peer);
        }
    }

    /// The peer's last failure, with the product's sentence, shown while it stands; `counted`:
    /// the loop ended with it, one `failed`. With a computer of another Vox version, any failed
    /// exchange is that (R10, R11): it opened here with another version's preamble, or it refused
    /// this node's.
    fn failure(&self, error: &Error, counted: bool) {
        let why = if self.conn.other_version()
            || matches!(
                error,
                Error::PeerRefused(crate::wire::WireError::ProtocolVersionUnsupported)
            ) {
            super::OTHER_VERSION.to_owned()
        } else {
            error.to_string()
        };
        crate::node::status::SyncBook::with(&self.book, self.room, self.peer, |counts| {
            if counted {
                counts.failed += 1;
            }
            counts.note_failure(why);
        });
    }

    /// PL-1: this node's board records go to the peer's board before the first stream of this
    /// connection for the room, and again, after news, when the peer answered it as a stranger.
    /// No deadline: the connection's end ends it.
    async fn introduce(&self) {
        if !self.conn.introduced(&self.room) {
            let far = tokio::time::Instant::now() + std::time::Duration::from_secs(365 * 24 * 3600);
            super::driver::introduce(&self.conn, &self.introduction, &self.fence, far).await;
            self.conn.note_introduced(self.room, true);
        }
    }

    /// The news as it stands now; read before an exchange, it is what a refusal of that
    /// exchange parks at, so news arriving during the exchange is never missed.
    fn news(&self) -> News {
        News {
            have: self
                .holdings
                .version(self.room, self.peer, self.conn.serial()),
            standing: self.cell.current().map(|snapshot| {
                let me = snapshot.me();
                (
                    snapshot.epoch(),
                    snapshot.is_author(&me),
                    snapshot.has_left(&me),
                    snapshot.recovery_standing(&me),
                )
            }),
        }
    }

    /// Send nothing more to the peer for this room until news later than `at`. Of two refused
    /// exchanges the one that had seen more of the peer's Haves keeps its mark.
    fn park(&self, at: News) {
        let mut parked = lock(&self.parked);
        if parked.is_none_or(|was| at.have >= was.have) {
            *parked = Some(at);
        }
    }

    /// C5: wait until `take` finds room in this node's assembly ([`Assembly`]). Short of room,
    /// what no admission holds gives way first ([`Frontier::shed`], of connection `only`, or of
    /// every room with none); then the loop waits for a charge to be given back, which only
    /// this node's admission still does. No job, byte admission or lock is held meanwhile; the
    /// connection's end ends the wait.
    async fn assembly_room<T>(
        &self,
        only: Option<(Digest32, Digest32)>,
        mut take: impl FnMut() -> Option<T>,
    ) -> Result<T> {
        loop {
            let mut released = self.frontier.assembly.released.subscribe();
            if let Some(taken) = take() {
                return Ok(taken);
            }
            if self.frontier.shed(only) {
                continue;
            }
            tokio::select! {
                biased;
                () = self.fence.retired() => return Err(gone()),
                changed = released.changed() => changed.map_err(|_| gone())?,
            }
        }
    }

    /// Wait, sending nothing, while the connection is parked and nothing is news: the peer's
    /// next Have on this connection, or a change of this node's own standing in the room; for a
    /// park on a local cause, the local edge it waits on instead ([`LocalWait`]). Then clear the
    /// park and introduce this node again if the peer had answered it as a stranger. Haves keep
    /// arriving meanwhile (the server merges them); only sending waits.
    async fn until_news(&self) -> Result<()> {
        if self.fence.is_retired() {
            return Err(gone());
        }
        let mut have = self.holdings.open(self.room, self.peer, &self.conn);
        let mut published = self.cell.next_publication();
        let local = lock(&self.local).take();
        let room_local = matches!(local, Some(LocalWait::Room));
        let mut bytes = match local {
            Some(LocalWait::Bytes(pressure)) => Some(Box::pin(pressure.released())),
            _ => None,
        };
        loop {
            have.borrow_and_update();
            published.borrow_and_update();
            let Some(at) = *lock(&self.parked) else {
                return Ok(());
            };
            let mut local_edge = false;
            if at == self.news() {
                tokio::select! {
                    biased;
                    () = self.fence.retired() => return Err(gone()),
                    changed = have.changed() => changed.map_err(|_| gone())?,
                    changed = published.changed() => {
                        changed.map_err(|_| gone())?;
                        local_edge = room_local;
                    }
                    () = async {
                        match bytes.as_mut() {
                            Some(released) => released.await,
                            None => std::future::pending().await,
                        }
                    } => {
                        bytes = None;
                        local_edge = true;
                    }
                }
                if !local_edge {
                    continue;
                }
            }
            {
                let mut parked = lock(&self.parked);
                if *parked == Some(at) {
                    *parked = None;
                }
            }
            self.frontier.wake();
            self.introduce().await;
        }
    }

    /// A half's exchange failed, `before` being the news it had seen when it began (ruling
    /// correction 3). Whatever the peer said, or whatever failed here, the connection sends
    /// nothing more for the room until news ([`Self::until_news`]); the failure is the peer's
    /// last failure in `vox status` while it stands. A refusal as a stranger is the
    /// introduction at work, not a counted failure, and is introduced again after the news.
    /// The loop ends only when the connection or its standing ended (the fence retired, the
    /// room's epoch moved on, the peer is no longer a member), or when the reply failed its
    /// check (malformed or too large: `run` closes the connection).
    fn refused(&self, error: Error, before: News) -> Result<()> {
        if self.fence.is_retired() {
            return Err(gone());
        }
        if current(self, &self.cell).is_err()
            || matches!(error, Error::Unreachable(why) if why == NOT_MEMBER)
            || matches!(
                error,
                Error::MalformedBundle(_) | Error::SizeLimitExceeded(_)
            )
        {
            return Err(error);
        }
        let stranger = matches!(
            error,
            Error::PeerRefused(
                crate::wire::WireError::NotYetMember | crate::wire::WireError::AuthenticatorInvalid
            )
        );
        // A cause here, not at the peer, waits on its own edge, not on the peer's news: this
        // node's byte budget, or the room's next publication (a local store or room state
        // fault is the room's, not the peer's, and is not counted against the peer).
        let local = match &error {
            Error::HistoryCapacity(_) => None,
            Error::MalformedAtRest(_)
            | Error::AtRestLocked
            | Error::Profile(_)
            | Error::ProfileBusy => Some(LocalWait::Room),
            _ => None,
        };
        let bytes = matches!(error, Error::HistoryCapacity(_));
        self.failure(&error, !stranger && local.is_none() && !bytes);
        if stranger {
            self.conn.note_introduced(self.room, false);
        }
        self.park(before);
        let local = match error {
            Error::HistoryCapacity(pressure) => Some(LocalWait::Bytes(*pressure)),
            _ => local,
        };
        *lock(&self.local) = local;
        Ok(())
    }
}

/// Whether a connection's loop keeps talking to `peer`, and how: the room's one standing rule
/// (`channel::room_snapshot::standing`, the same the history server serves by), the peer's
/// applied removal ending it, and, for a departed author, the receipt this node owes it. A
/// departed author is told its own row (and nothing else, `tell`) until this node has served
/// it, on this connection, the receipt of its own feed through its departure; then its loop
/// ends. A new connection starts it again until the same. Used by the loop's `current` and by
/// the actor's `start_pull_loops` and `retire_departed_port`, so they cannot disagree.
pub(crate) fn standing(
    snapshot: &RoomSnapshot,
    holdings: &Holdings,
    store: &Store,
    peer: Digest32,
    serial: u64,
) -> Result<Option<crate::node::channel::Standing>> {
    use crate::node::channel::Standing;
    let Some(standing) = snapshot.standing(&peer) else {
        return Ok(None);
    };
    if snapshot.peer_removal_applied(store, &peer)? {
        return Ok(None);
    }
    if standing == Standing::Departed {
        // A departed author holds nothing of the room: its leave removed the room there. What it
        // told on this connection that it held is no longer so, and a Have of its next instance
        // (a return) lists only what that one holds, so a row it no longer lists would stay
        // "held" and never be told to it again (a returner whose own entries cite a member that
        // stays offline then never admits them, and its own-history recovery never completes).
        let served = match lock(&holdings.peers).get_mut(&(snapshot.room(), peer, serial)) {
            Some(held) => {
                held.authors.clear();
                held.kept = RECORD_KEPT_BYTES;
                held.receipt_served
            }
            None => 0,
        };
        if snapshot.left_at(&peer).is_some_and(|at| served >= at) {
            return Ok(None);
        }
    }
    Ok(Some(standing))
}

/// The room's published snapshot, while the connection's peer has standing for this loop
/// ([`standing`]): a member of its epoch; or a departed author, returning or not, told only its
/// own row and asked nothing.
fn current(c: &Connection, cell: &RoomSnapshotCell) -> Result<Arc<RoomSnapshot>> {
    match cell.current() {
        Some(snapshot) if snapshot.epoch() == c.epoch => {
            if standing(&snapshot, &c.holdings, &c.store, c.peer, c.conn.serial())?.is_some() {
                Ok(snapshot)
            } else {
                Err(Error::Unreachable(NOT_MEMBER))
            }
        }
        Some(_) => Err(Error::Unreachable(NOT_MEMBER)),
        None => Err(gone()),
    }
}

/// Run one connection's two halves until it ends: telling its peer this node's Have, and
/// asking its peer for what this node owes.
pub(crate) async fn run(connection: Arc<Connection>) {
    // This loop's record is a new room instance or epoch: the peer's Have, kept for the
    // connection, is observed into it afresh (a node that left and joined again holds none of
    // what its earlier instance staged).
    connection
        .holdings
        .observe_afresh(connection.room, connection.peer, connection.conn.serial());
    let closed = {
        let conn = Arc::clone(&connection.conn);
        let fence = Arc::clone(&connection.fence);
        tokio::spawn(async move {
            let _ = conn.quinn().closed().await;
            fence.retire();
        })
    };
    let serial = connection.conn.serial();
    // Either half's end ends both, and only the end of the connection or of this loop's
    // standing ends a half (`Connection::refused`): a refused or failed exchange parks the
    // connection until news instead. The actor never starts a loop again on the same
    // connection for the same room instance and epoch (`start_pull_loops`).
    let ended = |result: Result<()>| {
        // The first half to end with an error ends the loop with it: the peer's failure. The
        // other half then ends only because the loop did, as both do when the connection does.
        if let Err(error) = &result {
            if !connection.fence.is_retired() {
                connection.failure(error, true);
            }
        }
        connection.fence.retire();
        result
    };
    // Before either half opens a stream.
    connection.introduce().await;
    let (tell, ask) = tokio::join!(async { ended(tell(&connection).await) }, async {
        ended(ask(&connection).await)
    });
    for result in [tell, ask] {
        if let Err(error) = result {
            if matches!(
                error,
                Error::MalformedBundle(_) | Error::SizeLimitExceeded(_)
            ) {
                // A reply that failed its check ends this connection, and nothing else.
                connection
                    .conn
                    .close(crate::wire::WireError::ProtocolLimits);
            }
        }
    }
    connection.fence.retire();
    closed.abort();
    // The body this loop was assembling goes with the loop, whatever ended it.
    drop(
        connection
            .frontier
            .take_partial((connection.room, connection.peer, serial)),
    );
    // What the peer said and what this connection kept go only with the connection itself: a
    // loop started on the same connection for a new room instance or epoch takes them up. The
    // peer's Have record goes by its own registration at the connection's close
    // (`Holdings::entry`).
    if connection.conn.quinn().close_reason().is_some() {
        connection.frontier.forget(connection.room, connection.peer);
    }
}

/// Tell the peer what this node holds beyond what the peer's own last Have on this connection
/// says it holds, and has not told it yet: at once on connect, then on each publication that
/// changed the record of what this node holds and on each Have of the peer. What the peer holds
/// itself is never told back to it; a Have of the peer that shrank (a body's lifetime ended
/// there, PL-2) makes what it now lacks news again, told at once. What this node told stays the
/// peer's knowledge of it: a shrink of this node's own holdings is not told (an answer corrects
/// the peer, as before).
async fn tell(c: &Connection) -> Result<()> {
    let (cell, mut tip) = {
        let room = c.shared.lock().await;
        (room.room_snapshot(), room.private_tip())
    };
    // This node's private Sessions as this peer may be told them (`private::Telling`): a
    // bounded, resumable discovery walk and what it last told; no permission result is kept.
    let mut telling = super::private::Telling::default();
    // Permission news of the room (`Frontier::private_permission`), subscribed before the
    // first look.
    let mut frontier = c.frontier.changed.subscribe();
    let mut published = cell.next_publication();
    let mut peer_have = c.holdings.open(c.room, c.peer, &c.conn);
    // What was told, per author and page (the start of its body span).
    let mut told: BTreeMap<(Digest32, u64), AuthorHave> = BTreeMap::new();
    // The record and the peer's Have version last compared: neither changed, nothing to tell.
    let mut compared: Option<(Arc<HeldHistory>, u64)> = None;
    loop {
        c.until_news().await?;
        let before = c.news();
        published.borrow_and_update();
        frontier.borrow_and_update();
        let version = *peer_have.borrow_and_update();
        let snapshot = current(c, &cell)?;
        // A peer that is not a member is told only its own row. What it was told of other
        // authors while it was one went with its leave; it is told them afresh when it is a
        // member again.
        if !snapshot.is_member(&c.peer) {
            let was = told.len();
            told.retain(|(author, _), _| *author == c.peer);
            if told.len() != was {
                compared = None;
            }
        }
        // The private section goes only to a peer the room's last publication counts eligible
        // for its private Sessions, and only once a native discovery quantum found a retained,
        // unexpired record the serve's own per-record check would give it: the newest such
        // position, with this node's donor incarnation. A peer permitted nothing is told
        // nothing. Its write is fenced on the authority that decision ran under. While the room
        // cannot decide (its governance refreshing, its Session upgrade work running), the walk
        // keeps its progress and what it told, takes no step and tells nothing, and resumes
        // once at the first publication that can decide.
        let tip_now = tip.borrow_and_update().clone();
        let deciding = if c.serving.private().is_some() {
            let serial = (
                c.frontier.private_permission_serial(c.room),
                snapshot.private_permission(),
            );
            match snapshot.private_peer(&c.peer) {
                Some(true) => {
                    telling.news(&tip_now, serial, &snapshot);
                    telling.advance(c).await?;
                    true
                }
                None => {
                    telling.undecided(serial, &snapshot);
                    false
                }
                Some(false) => {
                    telling.reset();
                    true
                }
            }
        } else {
            telling.reset();
            true
        };
        let held = snapshot
            .history()
            .filter(|now| {
                !compared
                    .as_ref()
                    .is_some_and(|(record, at)| Arc::ptr_eq(record, now) && *at == version)
            })
            .cloned();
        if let Some(held) = held {
            // A returning author that is not a member is told only this node's row of its own
            // author: its own public history, nothing else of the room.
            let member = snapshot.is_member(&c.peer);
            let news = c.holdings.beyond(
                c.room,
                c.peer,
                c.conn.serial(),
                held.haves().filter(|have| {
                    (member || have.author == c.peer)
                        && told.get(&(have.author, have.bodies_span.0)) != Some(*have)
                }),
                // The peer's own row is news to it once, then only when the role-complete hint
                // in it changed; a change of its runs alone is told only if the peer lacks it.
                |have| {
                    have.author == c.peer
                        && have.is_newest_page()
                        && told
                            .get(&(have.author, have.bodies_span.0))
                            .map(|told| told.role)
                            != Some(have.role)
                },
            );
            if !news.is_empty() {
                // What is told must be durable: received entries reach the disk first, the
                // room's debts enumerated afresh for this Holding.
                if let Err(error) = c.holdings.durable(c.room, &c.store).await {
                    c.refused(error, before)?;
                    continue;
                }
                // One HOLDING frame per stream; each within the frame bound.
                let sent: Result<()> = async {
                    let mut page: Vec<AuthorHave> = Vec::new();
                    let mut bytes = 0;
                    for have in &news {
                        let size = have.heads.iter().map(Vec::len).sum::<usize>()
                            + 40 * (have.proof.len() + have.bodies.len())
                            + 128;
                        if !page.is_empty()
                            && bytes + size > crate::log::history::MAX_FRAME_BYTES / 2
                        {
                            send_have(c, Frame::Holding(std::mem::take(&mut page)), None).await?;
                            bytes = 0;
                        }
                        bytes += size;
                        page.push(have.clone());
                    }
                    if !page.is_empty() {
                        send_have(c, Frame::Holding(page), None).await?;
                    }
                    Ok(())
                }
                .await;
                if let Err(error) = sent {
                    // After the news the whole Have is compared again.
                    c.refused(error, before)?;
                    told.clear();
                    compared = None;
                    continue;
                }
                told.extend(
                    news.into_iter()
                        .map(|have| ((have.author, have.bodies_span.0), have)),
                );
            }
            compared = Some((held, version));
            // The peer now knows, or holds itself, all this node held at the publication's
            // generation: its port is credited with it (not a returning author told only its
            // own row).
            let generation = snapshot.generation();
            let credited = member && {
                let mut credits = lock(&c.holdings.told);
                let at = credits.entry((c.room, c.peer)).or_default();
                let raised = generation > *at;
                *at = (*at).max(generation);
                raised
            };
            if credited {
                c.frontier.handed.notify_one();
            }
        }
        // Nothing is written while the room cannot decide: an unwritten anchor stays unsent.
        if let Some(tell) = deciding.then(|| telling.take()).flatten() {
            let have = Frame::PrivateHolding(Vec::new(), tell.anchor.clone());
            if let Err(error) = send_have(c, have, Some(tell.authority)).await {
                // Not written: told again when the connection may write (`until_news`).
                telling.unsent(tell);
                c.refused(error, before)?;
                continue;
            }
            telling.told(tell);
        }
        tokio::select! {
            biased;
            () = c.fence.retired() => return Ok(()),
            changed = published.changed() => if changed.is_err() { return Ok(()) },
            changed = peer_have.changed() => if changed.is_err() { return Ok(()) },
            changed = tip.changed() => if changed.is_err() { return Ok(()) },
            changed = frontier.changed() => if changed.is_err() { return Ok(()) },
            () = telling.ready() => {}
        }
    }
}

/// Send one Have page: a HOLDING or a private section. It is
/// built from the in-memory record and is this connection's private assembly: no job and no
/// shared byte admission while the peer reads it. A private section (`authority`) is written
/// only while what decided it still holds (`sessionstream::Authority::write`).
async fn send_have(
    c: &Connection,
    have: Frame<'static>,
    authority: Option<crate::node::sessionstream::Authority>,
) -> Result<()> {
    use crate::transport::streams::{open_typed, StreamKind};
    let preamble = c.preamble(Purpose::Control)?;
    let streams = tokio::select! {
        biased;
        () = c.fence.retired() => return Err(gone()),
        result = open_typed(&c.conn, StreamKind::Sync) => result?,
    };
    let mut io = Private::new(streams.0, streams.1, Arc::clone(&c.fence));
    io.write(&preamble.encode()).await?;
    for frame in [
        Frame::Hello(crate::wire::SYNC_MODE_BOUNDED_HISTORY),
        Frame::Want {
            request: preamble.request,
            query: Query::Have,
            target: None,
        },
    ] {
        io.write(&frame.encode_private()?).await?;
    }
    let have = have.encode_private()?;
    match authority {
        Some(authority) => authority.write(&c.store, &c.room, io.write(&have)).await?,
        None => io.write(&have).await?,
    }
    match io
        .read(super::MAX_HELLO_FRAME_BYTES + 4, Some(&[0x01]))
        .await?
    {
        Read::Frame(frame) if matches!(frame.frame()?, Frame::Hello(mode) if mode == crate::wire::SYNC_MODE_BOUNDED_HISTORY) =>
            {}
        _ => return Err(Error::Unreachable("have answered without HELLO")),
    }
    match io.read(super::DONE_RESERVE + 4, None).await? {
        Read::Frame(frame) if matches!(frame.frame()?, Frame::Done { .. }) => {
            c.answered(crate::node::status::RoundReason::Announce, false);
            Ok(())
        }
        _ => Err(Error::Unreachable("have answered without DONE")),
    }
}

/// One ask this loop chose.
#[derive(Clone)]
struct Ask {
    author: Digest32,
    head: Arc<SignedHead>,
    anchor: u64,
    want: RangeWant,
    need: Option<Need>,
}

/// The peer's signed heads this node does not hold are observed here, as a Head answer is,
/// once per Have of each author: a local step under the room's lock only when the Have names a
/// head the record lacks at or above this node's committed size (a lower one neither promotes
/// nor contradicts it), or when MP-9 has something to ask this peer about the author (a fork
/// it lists, an unresolved head it lists, its committed head of this node's committed size
/// with another id, or this node's own unresolved head of the author). The peer's committed
/// head is then held for its promotion ask. A frozen author's later history is refused, so
/// its heads are not observed again (MP-9); a fork it lists is still read, for the fork rule
/// ([`FORK_ASKS`]).
async fn observe(c: &Connection, snapshot: &RoomSnapshot) -> Result<()> {
    let history = snapshot.history();
    let held_here = |id: &Digest32| history.and_then(|history| history.head(id)).cloned();
    let mut stage = Vec::new();
    for (author, mut held) in c.holdings.authors(c.room, c.peer, c.conn.serial()) {
        // This node's own author is observed like any other: a higher own head a peer holds is
        // staged and made durable as a Head answer is (`admission::stage`), which fences writes.
        if held.observed || !snapshot.is_author(&author) {
            continue;
        }
        let seen = held.inspected();
        let row = history.and_then(|history| history.author(&author));
        let base = row.map_or(0, HeldAuthor::committed_size);
        let frozen = snapshot.is_frozen(&author);
        // MP-9: the peer serves under another author's head of the accepted size with another
        // root (staged as an equal rival, `admission::stage`). It is never promoted ([`newer`]
        // wants a larger one): it is compared, by asking this peer to open it (`listing_step`).
        let rival = held.committed.filter(|(id, size)| {
            author != c.node
                && row
                    .and_then(|row| row.committed.as_ref())
                    .is_some_and(|ours| *size == ours.root.leaves && *id != ours.id())
        });
        let compare = held.fork
            || (!frozen
                && (held.unresolved.is_some()
                    || rival.is_some()
                    || row.is_some_and(|row| row.have.unresolved.is_some())));
        held.heads
            .retain(|(id, size, _)| !frozen && *size >= base && held_here(id).is_none());
        if held.heads.is_empty() && !compare {
            let head = held.committed.and_then(|(id, _)| held_here(&id));
            c.holdings
                .observed(c.room, c.peer, c.conn.serial(), author, &seen, head, None);
        } else {
            stage.push((author, seen, held, compare, rival));
        }
    }
    if stage.is_empty() {
        return Ok(());
    }
    let own = c.node;
    let (observed, own_observed) = c
        .with_room(move |room, store, pin| {
            let mut own_observed = false;
            let mut out = Vec::new();
            for (author, seen, held, compare, rival) in stage {
                for (id, _, wire) in &held.heads {
                    if room.history_read(store)?.history_head(id)?.is_none() {
                        let committed = std::sync::atomic::AtomicBool::new(false);
                        let observed = std::sync::atomic::AtomicBool::new(false);
                        // A conflicting pair is retained and refused there, as before (MP-9).
                        let _ = super::admission::stage(
                            &PinnedHistory::new(room, pin),
                            store,
                            (&committed, &observed),
                            [0; 16],
                            [0; 32],
                            &Query::Head(author),
                            super::Object::Head(wire),
                        );
                        own_observed |=
                            author == own && observed.load(std::sync::atomic::Ordering::Acquire);
                    }
                }
                let head = match held.committed {
                    Some((id, _)) => room.history_read(store)?.history_head(&id)?.map(Arc::new),
                    None => None,
                };
                let listing = if compare {
                    listing_step(room, store, author, &held, rival)?
                } else {
                    None
                };
                out.push((author, seen, head, listing));
            }
            Ok((out, own_observed))
        })
        .await?;
    // A newly observed own head wakes the native recovery stages (the governance turn's Fence
    // … Complete, `actor/recovery_save.rs`) through the room's advance.
    if own_observed {
        c.frontier.advanced(c.room, false, true);
    }
    for (author, seen, head, listing) in observed {
        c.holdings.observed(
            c.room,
            c.peer,
            c.conn.serial(),
            author,
            &seen,
            head,
            listing,
        );
    }
    Ok(())
}

/// Rule F3's fork rule (sec-2 condition 1 as amended here; `sec-code-1.md` finding 3,
/// `sec-code-2.md` P2, `sec-code-3.md` P1 and P2): what a fork proof does to a member's
/// boundary, and when this node asks a peer for one.
///
/// - **Boundary, two steps at most** (`facts::Write::record_fork_boundary`, its only writer):
///   the first proof of a member sets its boundary by rule A (the proof's position when its two
///   entries share a predecessor that is this node's own accepted entry of that member; else
///   1). Any later proof that would lower it sets it to 1: two different splits of one member
///   leave no prefix of it trusted. A proof that would lower nothing is dropped by that same
///   rule A before any signature is verified (`record_history_fork`). At 1 nothing more is
///   asked or taken.
/// - **Asking, a constant allowance.** This node asks a connection for `author`'s proof
///   (`Query::Fork`) only when (a) the peer's Have lists a fork of `author`, (b) this node's
///   boundary for `author` is not 1, (c) the identity of the proof that Have lists (the digest
///   in its `unresolved` slot, [`slot_id`]) is not that of the proof this node holds, and
///   (d) the connection has asked for `author` fewer than `FORK_ASKS` times. The ask spends one
///   before it is sent, whatever comes back: a proof lowering or not, unavailable, Busy,
///   Cancelled, an error, nothing. Nothing the peer says gives one back. (b) and (c) are read
///   under the room when the Have is observed (`listing_step`) and again just before the ask
///   (`listed_object`); the Have's proof identity is unauthenticated and only spares an ask,
///   never grants one; its advertised position gates nothing. A Have saying the same again is
///   not asked again (`PeerAuthor::listed`), so an honest peer's allowance goes to new proofs.
///
/// So a peer, honest or not, costs at most `FORK_ASKS` asks per connection and author, and a
/// member's boundary is lowered (and its governance replayed) at most twice in this node's
/// life, however many valid proofs the splitter mints. Three asks cover a first proof, one
/// answer that lowers nothing, and the replacement that lowers to 1.
const FORK_ASKS: u8 = 3;

/// The fork rule's conditions read from the room ([`FORK_ASKS`] (b), (c)): `author` is a
/// member whose key this node holds, its boundary here is not 1, and `listed`, the identity of
/// the proof the peer's Have lists ([`slot_id`]), is not that of the proof this node holds
/// (with none held, any listed fork is wanted).
fn fork_ask_wanted(
    room: &ChannelState,
    store: &Store,
    author: Digest32,
    listed: Option<Digest32>,
) -> Result<bool> {
    Ok(room.is_author(&author)
        && room.history_splits(store)?.boundary(&author) != Some(1)
        && room
            .history_fork_listing(&author)
            .is_none_or(|(held, _)| listed != Some(held)))
}

/// MP-9: what the peer's Have of `author` makes this node ask that peer next, under the room:
/// the fork proof it lists, when the fork rule wants it ([`FORK_ASKS`]; a listing alone
/// records nothing); else, for an author not frozen here (rule 6), the unresolved head it
/// lists, by its id when not held here, or the next step comparing it with the accepted head;
/// else the next step comparing `rival`, the head of the accepted size with another root it
/// serves under (observed above), with the accepted head; else the next step of this node's
/// own kept unresolved comparison of the author. A comparison whose held openings already
/// prove a fork records it here, as one found by an answer is.
fn listing_step(
    room: &mut ChannelState,
    store: &Store,
    author: Digest32,
    held: &PeerAuthor,
    rival: Option<(Digest32, u64)>,
) -> Result<Option<Listing>> {
    let wanted = room.history_fork_wanted(&[author]).is_some();
    let step = if held.fork && fork_ask_wanted(room, store, author, slot_id(held.unresolved))? {
        Some(super::admission::Advanced::Need(Query::Fork(author)))
    } else {
        let read = room.history_read(store)?;
        // The peer's listed unresolved head first; whenever it gives no step (already accepted
        // here, or its comparison has nothing left to ask), the rival it serves under.
        let listed = match held.unresolved.filter(|_| wanted) {
            Some((id, _)) if read.history_head(&id)?.is_none() => {
                Some(super::admission::Advanced::Need(Query::HeadById(id)))
            }
            Some((id, _)) => super::admission::comparison_step(&read, &author, id)?,
            None => None,
        };
        let listed = match (listed, rival.filter(|_| wanted)) {
            (None, Some((id, _))) => super::admission::comparison_step(&read, &author, id)?,
            (listed, _) => listed,
        };
        match listed {
            Some(step) => Some(step),
            None if !room.history_author_frozen(&author) => {
                super::admission::unresolved_step(&read, &author)?
            }
            None => None,
        }
    };
    let read = room.history_read(store)?;
    let listing = match step {
        Some(super::admission::Advanced::Need(query @ (Query::Fork(_) | Query::HeadById(_)))) => {
            Some(Listing::Object(query))
        }
        // An opening under a head: its entry's receipt, as a Range of that one position.
        Some(super::admission::Advanced::Need(Query::Header { head, seq })) => {
            read.history_head(&head)?.map(|signed| Listing::Range {
                anchor: signed.root.leaves,
                head: Arc::new(signed),
                want: RangeWant::Entries { lo: seq, hi: seq },
            })
        }
        // A consistency proof under a head: a Range anchored at its `from` size, which brings
        // it with the head's newest position.
        Some(super::admission::Advanced::Need(Query::Proof {
            head,
            kind: super::ProofKind::Consistency,
            from,
            to,
        })) => read.history_head(&head)?.map(|signed| Listing::Range {
            anchor: from,
            head: Arc::new(signed),
            want: RangeWant::Entries { lo: to, hi: to },
        }),
        Some(super::admission::Advanced::Fork(pair)) => {
            drop(read);
            // Held openings already prove it: recorded as any found fork.
            let (existing, conflicting) = *pair;
            if room.record_history_fork(store, existing, conflicting)? {
                room.publish_room_snapshot(store);
            }
            None
        }
        _ => None,
    };
    #[cfg(feature = "test-knobs")]
    if held.fork || held.unresolved.is_some() || listing.is_some() {
        eprintln!(
            "history inventory listed forks={} unresolved={} fork_asked={} ask={listing:?}",
            u8::from(held.fork),
            u8::from(held.unresolved.is_some()),
            matches!(listing, Some(Listing::Object(Query::Fork(_))))
        );
    }
    Ok(listing)
}

/// Ask the peer, one bundle at a time, for what this node owes inside the peer's last Have,
/// minus what it has checked. With nothing to ask, wait for the peer's next Have, a change of
/// the record of what this node holds or of the frontier, or the end; an input that did not
/// change plans nothing.
async fn ask(c: &Connection) -> Result<()> {
    let mut peer_have = c.holdings.open(c.room, c.peer, &c.conn);
    let cell = c.shared.lock().await.room_snapshot();
    let mut published = cell.next_publication();
    let mut frontier = c.frontier.changed.subscribe();
    let mut debt = DebtTurn::default();
    // The ask this connection continues next, with the identities of the contexts it already
    // received of it (their number is `Query::Range`'s `skip`): a body's continuation, whose cut
    // the frontier keeps (`Frontier::keep_partial`), or the same ask, when its answer stopped on
    // contexts.
    let mut continued: Option<(Ask, BTreeSet<Digest32>, Marked<'_>)> = None;
    let mut private = super::private::Asking::default();
    loop {
        if lock(&c.parked).is_some() {
            // A parked connection keeps no request marked: another connection may ask it.
            continued = None;
            drop(c.frontier.take_partial((c.room, c.peer, c.conn.serial())));
        }
        c.until_news().await?;
        let before = c.news();
        peer_have.borrow_and_update();
        published.borrow_and_update();
        frontier.borrow_and_update();
        let snapshot = current(c, &cell)?;
        // Nothing is asked of an author that is not a member (returning, or departed and owed
        // its receipt): its loop only tells it. When membership ends between quanta, the
        // continuation, its mark and this connection's partial assembly go here, before any
        // path below could ask: the work stays owed to the other holders.
        let member = snapshot.is_member(&c.peer);
        if !member {
            continued = None;
            drop(c.frontier.take_partial((c.room, c.peer, c.conn.serial())));
        }
        if member {
            if let Err(error) = observe(c, &snapshot).await {
                c.refused(error, before)?;
                continue;
            }
        }
        let history = snapshot.history().cloned().filter(|_| member);
        // A receipt owed by the peer's Have: its role-complete head of this node's feed, above
        // what this node noted it holds (ADR-028 R-6, and a leave's departure), asked once.
        if member && continued.is_none() {
            match receipt(c).await {
                Ok(false) => {}
                Ok(true) => continue,
                Err(error) => {
                    c.refused(error, before)?;
                    continue;
                }
            }
        }
        // Private Sessions (ruling correction 2): one exchange of a saved private request owed
        // to this donor, of the old automatic private debt, or of the peer's newer private tip.
        // After one, the next turn goes to the public plan first (`Asking::yielded`).
        let skipped = std::mem::take(&mut private.yielded);
        if member && continued.is_none() && !skipped {
            match super::private::ask(c, &mut private).await {
                Ok(false) => {}
                Ok(true) => {
                    private.yielded = true;
                    continue;
                }
                Err(error) => {
                    c.refused(error, before)?;
                    continue;
                }
            }
        }
        // C5: nothing is asked until this connection's assembly has room for one more answer
        // ([`Assembly`]); what holds it then is this node's admission, never a peer.
        let key = (c.room, c.peer);
        c.assembly_room(Some(key), || {
            (c.frontier.assembly.held(key) + crate::log::history::MAX_RESPONSE_BYTES <= KEPT_BYTES)
                .then_some(())
        })
        .await?;
        // Handing a page over and asking the next thing are independent: entries this
        // connection handed over that are still ready, in admission or waiting gate nothing but
        // the bytes above; the plan passes over only their positions.
        let next = match continued.take() {
            Some(next) => Some(next),
            None if !member => None,
            // MP-9: what the peer's Have makes this node ask that peer comes before any plan.
            None => match c.holdings.take_listing(c.room, c.peer, c.conn.serial()) {
                Some((author, Listing::Object(query))) => {
                    if let Err(error) = listed_object(c, author, query).await {
                        c.refused(error, before)?;
                    }
                    continue;
                }
                Some((author, Listing::Range { head, anchor, want })) => {
                    let ask = Ask {
                        author,
                        head,
                        anchor,
                        want,
                        need: None,
                    };
                    let mark = c.frontier.mark((c.room, c.peer, c.conn.serial()), &ask);
                    Some((ask, BTreeSet::new(), mark))
                }
                None => history
                    .as_deref()
                    .and_then(|history| {
                        let authors = c.holdings.authors(c.room, c.peer, c.conn.serial());
                        plan(&snapshot, history, c, &authors, &mut debt)
                    })
                    .map(|(ask, mark)| (ask, BTreeSet::new(), mark)),
            },
        };
        let Some((ask, received, mark)) = next else {
            if skipped {
                // The public plan had nothing: the private debt's turn.
                continue;
            }
            loop {
                tokio::select! {
                    biased;
                    () = c.fence.retired() => return Ok(()),
                    changed = peer_have.changed() => match changed {
                        Ok(()) => break,
                        Err(_) => return Ok(()),
                    },
                    changed = frontier.changed() => match changed {
                        Ok(()) => break,
                        Err(_) => return Ok(()),
                    },
                    changed = published.changed() => {
                        if changed.is_err() {
                            return Ok(());
                        }
                        // A publication that left the record and the peer's standing as they
                        // were plans nothing, unless the last private look could not decide:
                        // the room decides at a publication.
                        let now = cell.current();
                        let same = now.as_ref().is_some_and(|now| {
                            now.epoch() == c.epoch
                                && now.is_member(&c.peer)
                                && now.history().map(Arc::as_ptr) == history.as_ref().map(Arc::as_ptr)
                        });
                        if !same || private.undecided() {
                            break;
                        }
                    }
                }
            }
            continue;
        };
        #[cfg(feature = "test-knobs")]
        let _one = if mutant("VOX_MUTANT_ONE_ASK_PER_NODE") {
            Some(ONE_ASK.lock().await)
        } else {
            None
        };
        continued = match exchange(c, ask, received, mark, history.as_deref()).await {
            Ok(next) => next,
            Err(error) => {
                c.refused(error, before)?;
                None
            }
        };
    }
}

/// MP-9: ask the listing peer for one object its Have names (a fork proof, or an unresolved
/// head by its id) and keep what checks out: the fork recorded from its two signed headers,
/// each verified with the author's key; the head observed as a Head answer is
/// (`admission::stage`), then compared at the next step. Not served, it records nothing and
/// fails nothing: the peer's next Have of the author may name it again.
///
/// A fork proof is asked only as the fork rule says ([`FORK_ASKS`]): its conditions read again
/// now, under the room (a published snapshot can be older), and one of this connection's asks
/// for the author spent before the ask is sent, whatever comes back.
async fn listed_object(c: &Connection, author: Digest32, query: Query) -> Result<()> {
    if let Query::Fork(asked) = query {
        let serial = c.conn.serial();
        let Some(listed) = c.holdings.fork_listed(c.room, c.peer, serial, asked) else {
            return Ok(());
        };
        let wanted = c
            .with_room(move |room, store, _| fork_ask_wanted(room, store, asked, listed))
            .await?;
        if !wanted || !c.holdings.spend_fork_ask(c.room, c.peer, serial, asked) {
            return Ok(());
        }
    }
    let preamble = c.preamble(Purpose::Control)?;
    let reply = bundle::ask(
        &c.conn,
        c.node,
        preamble,
        query.clone(),
        None,
        Arc::clone(&c.fence),
    )
    .await?;
    // A refusal parks the connection (`Connection::refused`), as every refused exchange does.
    if matches!(reply.status, Status::Busy | Status::Cancelled) {
        return Err(refusal(reply.status));
    }
    if reply.status != Status::Complete {
        #[cfg(feature = "test-knobs")]
        eprintln!("history evidence unavailable query={query:?}");
        c.answered(crate::node::status::RoundReason::Hint, false);
        return Ok(());
    }
    let fork = reply.answer.fork.clone();
    let head = reply.answer.head().map(SignedHead::to_wire);
    let brought = c
        .with_room(move |room, store, pin| match query {
            Query::Fork(asked) => {
                let (existing, conflicting) =
                    fork.ok_or(Error::MalformedBundle("fork response kind"))?;
                let existing = Entry::from_wire(&existing)?;
                let conflicting = Entry::from_wire(&conflicting)?;
                if existing.payload.is_some()
                    || conflicting.payload.is_some()
                    || existing.skeleton.author_id != asked
                    || conflicting.skeleton.author_id != asked
                {
                    return Err(Error::MalformedBundle("fork response differs from request"));
                }
                let recorded = room.record_history_fork(store, existing, conflicting)?;
                if recorded {
                    room.publish_room_snapshot(store);
                }
                Ok(recorded)
            }
            Query::HeadById(id) => {
                let wire = head.ok_or(Error::MalformedBundle("head response kind"))?;
                let held = room.history_read(store)?.history_head(&id)?.is_some();
                let committed = std::sync::atomic::AtomicBool::new(false);
                let observed = std::sync::atomic::AtomicBool::new(false);
                super::admission::stage(
                    &PinnedHistory::new(room, pin),
                    store,
                    (&committed, &observed),
                    [0; 16],
                    [0; 32],
                    &Query::HeadById(id),
                    super::Object::Head(&wire),
                )?;
                Ok(!held)
            }
            _ => Err(Error::Profile("a listing asks only a fork or a head")),
        })
        .await?;
    c.answered(crate::node::status::RoundReason::Hint, brought);
    if brought {
        c.holdings
            .unobserve(c.room, c.peer, c.conn.serial(), author);
    }
    Ok(())
}

/// Ask the peer the exact receipt of this node's feed when its Have names a role-complete head
/// of this node above what this node noted it holds: `Query::Head(self)` under Control, which
/// the peer answers with `history_role_head` after flushing (`server.rs`). The answer is staged
/// as an own head (`admission::stage`: signature, binding, durable own-head fence) and handed
/// to the actor with its provenance. Asked once per named head on this connection; an answer
/// without a head is not asked again until the peer names another. `true`: an exchange ran.
async fn receipt(c: &Connection) -> Result<bool> {
    let Some((named, size)) = c
        .holdings
        .authors(c.room, c.peer, c.conn.serial())
        .into_iter()
        .find(|(author, _)| *author == c.node)
        .and_then(|(_, held)| held.role)
    else {
        return Ok(false);
    };
    if *lock(&c.receipt) == Some(named) {
        return Ok(false);
    }
    // Owed while the peer's noted held-through is below the named size, and always while this
    // node has left: its leave completes only on the exact receipt of its terminal head.
    let peer = c.peer;
    let owed = c
        .with_room(move |room, _, _| {
            let me = room.me();
            Ok(room.has_left(&me)
                || room.private_support_discovery_pending()
                || room.held_through(&peer).is_none_or(|held| held < size))
        })
        .await?;
    *lock(&c.receipt) = Some(named);
    if !owed {
        return Ok(false);
    }
    let preamble = c.preamble(Purpose::Control)?;
    let reply = bundle::ask(
        &c.conn,
        c.node,
        preamble,
        Query::Head(c.node),
        None,
        Arc::clone(&c.fence),
    )
    .await?;
    // A refusal parks the connection (`Connection::refused`), as every refused exchange does.
    if matches!(reply.status, Status::Busy | Status::Cancelled) {
        return Err(refusal(reply.status));
    }
    let Some(wire) = reply
        .answer
        .head()
        .map(SignedHead::to_wire)
        .filter(|_| reply.status == Status::Complete)
    else {
        c.answered(crate::node::status::RoundReason::Hint, false);
        return Ok(true);
    };
    let (me, epoch) = (c.node, c.epoch);
    let (head, size, instance, generation, own_observed) = c
        .with_room(move |room, store, pin| {
            let committed = std::sync::atomic::AtomicBool::new(false);
            let observed = std::sync::atomic::AtomicBool::new(false);
            let super::admission::Staged::Head {
                head, author, tail, ..
            } = super::admission::stage(
                &PinnedHistory::new(room, pin),
                store,
                (&committed, &observed),
                [0; 16],
                [0; 32],
                &Query::Head(me),
                super::Object::Head(&wire),
            )?
            else {
                return Err(Error::MalformedBundle("receipt response kind"));
            };
            if author != me {
                return Err(Error::MalformedBundle("receipt names another author"));
            }
            let instance = room.history_instance(store)?;
            let generation =
                super::authorization_generation(store, me, room.channel_id(), instance, epoch)?;
            Ok((
                head,
                tail,
                instance,
                generation,
                observed.load(std::sync::atomic::Ordering::Acquire),
            ))
        })
        .await?;
    if own_observed {
        // A higher own head a receipt names fences writes and wakes recovery, as from a Have.
        c.frontier.advanced(c.room, false, true);
    }
    c.frontier.receipt(LoopReceipt {
        room: c.room,
        peer: c.peer,
        connection: c.conn.serial(),
        head,
        size,
        epoch,
        instance,
        generation,
    });
    c.answered(crate::node::status::RoundReason::Hint, false);
    Ok(true)
}

/// What stands between this node and an author's posts, read from the record, never found by
/// an admission failing (the validator's order: a post waits for every earlier control of its
/// author, governance/sparse.rs): for an author of whom nothing is admitted here, the control
/// coverage of its history; then each control that coverage enumerated and that is neither
/// admitted nor ready, in admission or waiting, as a page of its one position (the receipt of
/// its predecessor leads it), one no live request asks (`asked`) first. Controls of different
/// authors then wait for one another here, in the frontier. Asked of this peer under the head
/// [`under`] names.
fn controls_first(
    row: &HeldAuthor,
    owed: &Owed<'_>,
    author: Digest32,
    held: &PeerAuthor,
    asked: Option<&Runs>,
) -> Option<Ask> {
    let (head, anchor) = under(held, row)?;
    let size = head.root.leaves;
    let covered = row.controls_covered();
    // Coverage through `size - 1` is what a post at `size` waits for.
    let want = if row.walked_runs().is_empty() && covered + 1 < size {
        covers(&held.controls, covered + 1, size).then_some(RangeWant::Controls {
            lo: covered + 1,
            hi: size,
        })?
    } else {
        let mut eligible = row.control_positions().iter().copied().filter(|&seq| {
            seq <= size
                && owed.from(seq) == seq
                && run_of(&held.bodies, seq).is_some()
                && covers(&held.proof, seq, seq)
        });
        let first = eligible.next()?;
        let seq = std::iter::once(first)
            .chain(eligible)
            .find(|&seq| !asked.is_some_and(|runs| runs.contains(seq)))
            .unwrap_or(first);
        RangeWant::Entries { lo: seq, hi: seq }
    };
    Some(Ask {
        author,
        head,
        anchor,
        want,
        need: None,
    })
}

/// The head of the author this peer committed, held here and above this node's committed one,
/// when it can be promoted: not the author's kept unresolved head (MP-9: compared, never
/// promoted again, `listing_step`), no fork, and its newest position inside the peer's proof
/// runs.
fn newer<'h>(held: &'h PeerAuthor, row: &HeldAuthor) -> Option<&'h Arc<SignedHead>> {
    let head = held
        .head
        .as_ref()
        .filter(|head| head.root.leaves > row.committed_size())?;
    let size = head.root.leaves;
    (!row.conflict
        && row.have.unresolved.is_none_or(|(id, _)| id != head.id())
        && covers(&held.proof, size, size))
    .then_some(head)
}

/// The head this node asks the peer for the author's positions under, with its anchor: the
/// head the peer committed, when [`newer`], anchored at this node's committed size (the answer
/// carries the consistency proof and that head's terminal receipt, server.rs `range`, so the
/// head is committed here before anything the answer brings is handed over); else this node's
/// committed head, when the peer serves it.
fn under(held: &PeerAuthor, row: &HeldAuthor) -> Option<(Arc<SignedHead>, u64)> {
    if let Some(head) = newer(held, row) {
        return Some((Arc::clone(head), row.committed_size()));
    }
    row.committed
        .as_ref()
        .filter(|head| !row.conflict && held.serves_under(head))
        .map(|head| (Arc::clone(head), head.root.leaves))
}

/// The promotion of the head of `author` this peer committed ([`newer`]): its newest position
/// under it, anchored at this node's committed size (the consistency proof comes with it).
/// Asked for a head need (step 1), and for itself only when nothing else is owed from the peer
/// (step 5): every other ask is made under that head already ([`under`]).
fn promotion(author: Digest32, held: &PeerAuthor, row: &HeldAuthor) -> Option<Ask> {
    // M3 (`VOX_MUTANT_NO_PROMOTION`): no head the peer committed is ever promoted here.
    #[cfg(feature = "test-knobs")]
    if mutant("VOX_MUTANT_NO_PROMOTION") {
        return None;
    }
    let head = newer(held, row)?;
    let size = head.root.leaves;
    Some(Ask {
        author,
        head: Arc::clone(head),
        anchor: row.committed_size(),
        want: RangeWant::Entries { lo: size, hi: size },
        need: None,
    })
}

/// This connection's turn over authors in the walk's debt (step 3 of [`choose`]): the author
/// its last debt ask was for, after whom the next plan's walk starts, so that one author whose
/// history keeps growing cannot take every debt selection; and the authors whose next debt page
/// is their oldest rather than their newest (each serviced author alternates). Only the debt it
/// was asked of this peer moves it; it holds nothing in the frontier.
#[derive(Default)]
struct DebtTurn {
    last: Option<Digest32>,
    oldest: BTreeSet<Digest32>,
}

/// Choose one ask and mark it as this connection's live request, under the frontier's planning
/// lock: no other loop of this node chooses between this choice and its mark. The mark lasts
/// until the returned guard drops, when the exchange ends however it ends.
fn plan<'a>(
    snapshot: &RoomSnapshot,
    history: &HeldHistory,
    c: &'a Connection,
    authors: &[(Digest32, PeerAuthor)],
    debt: &mut DebtTurn,
) -> Option<(Ask, Marked<'a>)> {
    let _planning = lock(&c.frontier.planning);
    let view = c.frontier.view(c.room);
    let ask = choose(snapshot, history, c, &view, authors, debt)?;
    let mark = c.frontier.mark((c.room, c.peer, c.conn.serial()), &ask);
    Some((ask, mark))
}

/// Choose one ask from the peer's last Have, the record of what this node holds and the
/// frontier's view, each read once, by class: the frontier's exact needs, whatever they name (a
/// position as that one position, after what stands before its author's posts; a newer head as
/// the promotion of the head this peer committed; control coverage as itself), then what stands
/// before an author's posts, then the package bodies owed, then the newest or the oldest page of
/// the walk's debt, inside the peer's Have, each under the head [`under`] names; and only when
/// nothing else is owed from the peer, the promotion of a newer head it committed. Entries this
/// connection handed over that are still ready, in admission or waiting hold back nothing but
/// their own positions. Authors are visited starting after the last one this connection asked
/// debt of ([`DebtTurn`]). Within each class, work no live request of this node covers comes
/// first; when every eligible ask of the class is covered, a covered one is asked at once (a mark
/// is a preference, not a reservation). Every search moves by runs; nothing here locks or reads
/// per position.
fn choose(
    snapshot: &RoomSnapshot,
    history: &HeldHistory,
    c: &Connection,
    view: &View,
    authors: &[(Digest32, PeerAuthor)],
    debt: &mut DebtTurn,
) -> Option<Ask> {
    let (room_id, frontier) = (c.room, &c.frontier);
    // With `prefer`, positions a live request asks are not owed for this pass.
    let owed = |author: &Digest32, prefer: bool| Owed {
        runs: [
            history.author(author).map(HeldAuthor::walked_runs),
            view.busy.get(author),
            view.waits.get(author),
            view.asked.get(author).filter(|_| prefer),
        ],
    };
    // The first pass of a class passes over an ask a live request covers.
    let pass = |prefer: bool, ask: Ask| (!prefer || !view.covered(&ask)).then_some(ask);
    // 1. The frontier's exact needs, each asked of this peer if it holds the positions.
    let mut met = Vec::new();
    let mut chosen = None;
    'needs: for prefer in [true, false] {
        for (need, named) in &view.needs {
            let (author, hi, controls) = match *need {
                Need::Head { author, size } => {
                    // Met once this node's committed head of the author passed `size`, whichever
                    // head that is; until then asked as the promotion of the head this peer
                    // committed, if it is newer.
                    let row = history.author(&author);
                    if row.is_some_and(|row| row.committed_size() > size) {
                        if prefer {
                            met.push((*need, None));
                        }
                        continue;
                    }
                    let ask = row
                        .filter(|_| snapshot.is_author(&author))
                        .zip(authors.iter().find(|(a, _)| *a == author))
                        .and_then(|(row, (_, held))| promotion(author, held, row));
                    if let Some(ask) = ask.and_then(|ask| pass(prefer, ask)) {
                        chosen = Some(ask);
                        break 'needs;
                    }
                    continue;
                }
                Need::Fork { author, at } => {
                    if prefer
                        && snapshot
                            .fork_boundary(&author)
                            .is_some_and(|boundary| boundary <= at)
                    {
                        met.push((*need, None));
                    }
                    continue;
                }
                // Only the splitter's matching entry could meet it; none is ever accepted here.
                Need::Unmatched { .. } => continue,
                Need::Position { author, seq } => (author, seq, None),
                Need::Controls { author, lo, hi } => (author, hi, Some(lo)),
            };
            let row = history.author(&author);
            let held = authors
                .iter()
                .find(|(a, _)| *a == author)
                .map(|(_, held)| held);
            if controls.is_some() {
                // Met once the author's coverage from 1 reaches `hi`, whatever head proved it
                // (the record's coverage is never above the store's; `Frontier::covered` meets
                // it from the store after each answer).
                if row.is_some_and(|row| row.controls_covered() >= hi) {
                    if prefer {
                        met.push((*need, None));
                    }
                    continue;
                }
            } else {
                // A position need is for that position's receipt. An answer that brings it
                // meets it (`Frontier::received`); once the position is admitted here, it is met
                // here: admitted (`walked`) is published, and a published position is what
                // admission itself takes as that position's evidence (`admission::parent_evidence`),
                // so a need this meets is never unmet for admission. Only a position ready or in
                // admission is passed over: a waiting one is asked, since what it waits for can be
                // this very receipt (an answer overtaken by a newer committed head: admission
                // found its inclusion under neither head).
                let owing = Owed {
                    runs: [
                        row.map(HeldAuthor::walked_runs),
                        view.busy.get(&author),
                        None,
                        view.asked.get(&author).filter(|_| prefer),
                    ],
                };
                if owing.from(hi) != hi {
                    if prefer && row.is_some_and(|row| row.walked(hi)) {
                        met.push((*need, Some((author, hi))));
                    }
                    continue;
                }
            }
            let Some(held) = held else {
                continue;
            };
            // What stands before the author's posts is asked before any position of them.
            if controls.is_none() {
                let before = row.and_then(|row| {
                    controls_first(
                        row,
                        &owed(&author, false),
                        author,
                        held,
                        view.asked.get(&author),
                    )
                });
                if let Some(ask) = before {
                    match pass(prefer, ask) {
                        Some(ask) => {
                            chosen = Some(ask);
                            break 'needs;
                        }
                        None => continue,
                    }
                }
            }
            // The head the peer is asked under: its newer committed head or this node's
            // ([`under`]), when it reaches the position; else the head admission named, when
            // the peer serves it. What the answer brings is kept by author and position.
            let Some((head, anchor)) = row
                .and_then(|row| under(held, row))
                .filter(|(head, _)| head.root.leaves >= hi)
                .or_else(|| {
                    named
                        .as_ref()
                        .filter(|head| head.root.leaves >= hi && held.serves_under(head))
                        .map(|head| (Arc::clone(head), head.root.leaves))
                })
            else {
                continue;
            };
            let size = head.root.leaves;
            let want = match controls {
                // Coverage is asked once up to the head it is asked under, where the peer's told
                // coverage reaches, so the author's later entries do not each record their own
                // (journey-4, y1: 6fxxej/1081 to /1212, one ask per position).
                Some(lo) if size > hi && covers(&held.controls, lo, size) => {
                    RangeWant::Controls { lo, hi: size }
                }
                Some(lo) if covers(&held.controls, lo, hi) => RangeWant::Controls { lo, hi },
                Some(_) => continue,
                // Exactly the position: its entry, and the receipt of the position below it
                // that leads every Range answer (server.rs), which is all a need for it is.
                // Pages are for the walk's debt (step 3).
                None if covers(&held.proof, hi, hi) => RangeWant::Entries { lo: hi, hi },
                None => continue,
            };
            let ask = Ask {
                author,
                head,
                anchor,
                want,
                need: Some(*need),
            };
            if let Some(ask) = pass(prefer, ask) {
                chosen = Some(ask);
                break 'needs;
            }
        }
    }
    for (need, at) in &met {
        frontier.met(room_id, need, *at);
    }
    if chosen.is_some() {
        return chosen;
    }
    // The peer's authors (in id order), starting after the one this connection last asked debt
    // of, round to it.
    let start = debt.last.map_or(0, |last| {
        authors.partition_point(|(author, _)| *author <= last)
    });
    let rows = || {
        authors[start..]
            .iter()
            .chain(&authors[..start])
            .filter_map(|(author, held)| {
                // A frozen author's later history is refused: nothing of it is fetched (MP-9).
                if !snapshot.is_author(author) || snapshot.is_frozen(author) {
                    return None;
                }
                Some((*author, held, history.author(author)?))
            })
    };
    // 2. What stands before an author's posts (`controls_first`).
    for prefer in [true, false] {
        for (author, held, row) in rows() {
            let before = controls_first(
                row,
                &owed(&author, false),
                author,
                held,
                view.asked.get(&author),
            );
            if let Some(ask) = before.and_then(|ask| pass(prefer, ask)) {
                return Some(ask);
            }
        }
    }
    // 2b. The package bodies this node owes (`HeldAuthor::owed_bodies`, its durable body
    // debts), whatever its walk completed: each asked explicitly, `Body{seq, 0}`, under this
    // node's committed head when the peer serves under it and its Have pages list the body. The
    // answer is the opaque body for a package of another member, matched to the debt and
    // admitted by the typed refill only (`exchange`).
    for prefer in [true, false] {
        for (author, held, row) in rows() {
            let Some(head) = row
                .committed
                .as_ref()
                .filter(|head| !row.conflict && held.serves_under(head))
            else {
                continue;
            };
            let size = head.root.leaves;
            // The lowest position from `seq` that no live request of this node works on.
            let free = |mut seq: u64| loop {
                let next = [
                    view.busy.get(&author),
                    view.waits.get(&author),
                    view.asked.get(&author).filter(|_| prefer),
                ]
                .into_iter()
                .flatten()
                .fold(seq, |at, runs| runs.absent_from(at));
                if next == seq {
                    return seq;
                }
                seq = next;
            };
            for (a, b) in row.owed_bodies().iter() {
                for &(c_lo, c_hi) in &held.bodies {
                    let (lo, hi) = (a.max(c_lo), b.min(c_hi).min(size));
                    if lo > hi {
                        continue;
                    }
                    let seq = free(lo);
                    if seq > hi {
                        continue;
                    }
                    let ask = Ask {
                        author,
                        head: Arc::clone(head),
                        anchor: size,
                        want: RangeWant::Body { seq, offset: 0 },
                        need: None,
                    };
                    if let Some(ask) = pass(prefer, ask) {
                        return Some(ask);
                    }
                }
            }
        }
    }
    // 3. What this node owes of an author's positions: the walk's window, and the positions the
    // node's saved archive intents cover (PL-3: owed like any others), less what admission
    // completed or is working on, inside the peer's body runs; each author's newest or oldest
    // page in turn, under the head [`under`] names. (No author has anything standing before its
    // posts here: step 2 would have asked it.)
    for prefer in [true, false] {
        for (author, held, row) in rows() {
            // This node's own missing prefix is walked oldest first: own recovery settles the
            // next contiguous own position before later sender generations
            // (`require_own_recovery_complete`).
            let newest = !debt.oldest.contains(&author) && author != c.node;
            let Some((head, anchor)) = under(held, row) else {
                continue;
            };
            let mut debts: Vec<(u64, u64)> = row.window().into_iter().collect();
            if !row.conflict {
                for owed in view
                    .archive
                    .iter()
                    .filter(|owed| owed.author == author && !owed.fence.is_retired())
                {
                    let (lo, hi) = (owed.lo.max(1), owed.hi.min(head.root.leaves));
                    if lo <= hi {
                        debts.push((lo, hi));
                    }
                }
            }
            debts.sort_unstable();
            if newest {
                debts.reverse();
            }
            let owed = owed(&author, prefer);
            // A position the peer serves: inside its body runs and its proof runs.
            let pick =
                |seq: u64| run_of(&held.bodies, seq).filter(|_| covers(&held.proof, seq, seq));
            let span = MAX_PAGE_ENTRIES as u64 - 1;
            for (from, to) in debts {
                let page = if newest {
                    let mut found = None;
                    let mut seq = owed.below(to);
                    while seq >= from && seq > 0 {
                        match pick(seq) {
                            Some((a, _)) => {
                                // The run of consecutive owed positions ending here, within one
                                // page.
                                let floor = seq.saturating_sub(span).max(from).max(a).max(1);
                                found = Some((owed.run_start(seq, floor), seq));
                                break;
                            }
                            None => {
                                seq = held
                                    .bodies
                                    .iter()
                                    .rev()
                                    .find(|&&(_, b)| b < seq)
                                    .map_or(0, |&(_, b)| owed.below(b));
                            }
                        }
                    }
                    found
                } else {
                    let mut found = None;
                    let mut seq = owed.from(from);
                    while seq <= to {
                        match pick(seq) {
                            Some((_, b)) => {
                                // The run of consecutive owed positions starting here, within
                                // one page.
                                let ceiling = (seq + span).min(to).min(b);
                                found = Some((seq, owed.run_end(seq, ceiling)));
                                break;
                            }
                            None => {
                                seq = held
                                    .bodies
                                    .iter()
                                    .find(|&&(a, _)| a > seq)
                                    .map_or(u64::MAX, |&(a, _)| owed.from(a));
                            }
                        }
                    }
                    found
                };
                let Some((lo, hi)) = page else {
                    continue;
                };
                let ask = Ask {
                    author,
                    head: Arc::clone(&head),
                    anchor,
                    want: RangeWant::Entries { lo, hi },
                    need: None,
                };
                if let Some(ask) = pass(prefer, ask) {
                    // Asked: the next debt selection starts after this author, whose next page
                    // is from the other end.
                    debt.last = Some(author);
                    if newest {
                        debt.oldest.insert(author);
                    } else {
                        debt.oldest.remove(&author);
                    }
                    return Some(ask);
                }
            }
        }
    }
    // 4. Only when no need, prerequisite, body or debt above is eligible from the peer: a newer
    // head it committed, held here, above this node's committed one. Every ask above is made
    // under such a head already, and its answer commits it.
    for prefer in [true, false] {
        for (author, held, row) in rows() {
            if let Some(ask) = promotion(author, held, row).and_then(|ask| pass(prefer, ask)) {
                return Some(ask);
            }
        }
    }
    None
}

/// Ask one bundle, check it, keep what it proved and hand its checked entries to admission.
/// Returns the ask this connection continues next, with the identities of the contexts already
/// received of it: the body this answer cut (kept by the frontier, `Frontier::keep_partial`), or
/// the same ask when this answer stopped on contexts that did not fit, which the next answer goes
/// on from. The request is this connection's live one (`mark`) until this returns, an error and
/// a drop of the future included. `planned` is the room's record the ask was planned from. A
/// refusal (the loop's one no-progress rule, below) is returned as an error, after what the same
/// answer proved is kept and handed over: the caller parks the connection on it
/// ([`Connection::refused`]).
async fn exchange<'a>(
    c: &'a Connection,
    ask: Ask,
    mut received: BTreeSet<Digest32>,
    mark: Marked<'a>,
    planned: Option<&HeldHistory>,
) -> Result<Option<(Ask, BTreeSet<Digest32>, Marked<'a>)>> {
    let preamble = c.preamble(Purpose::Live)?;
    let head_id = ask.head.id();
    let query = Query::Range {
        head: head_id,
        anchor: ask.anchor,
        want: ask.want,
        skip: received.len() as u64,
    };
    // No job and no shared byte admission while the peer answers (ADR-054 PL-6, C5): the
    // answer's frames are this connection's private assembly.
    let reply = bundle::ask(
        &c.conn,
        c.node,
        preamble,
        query,
        Some(ask.head.target()),
        Arc::clone(&c.fence),
    )
    .await?;
    let bundle::Reply {
        status,
        continuation,
        mut answer,
    } = reply;
    let corrected = std::mem::take(&mut answer.corrected);
    let (anchor, want, author, binding) = (ask.anchor, ask.want, ask.author, ask.head.binding);
    let room_id = c.room;
    let (room, peer, serial) = (c.room, c.peer, c.conn.serial());
    // The contexts this answer carried that this continuation had not received: only these
    // advance it. A context received again (a holder replaying one) is no progress.
    let fresh: Vec<Digest32> = answer
        .context_ids()
        .filter(|id| !received.contains(*id))
        .copied()
        .collect();
    // What the last answer left for this one (the body it cut, or the contexts it carried
    // ahead of the proof using them, [`Kept`]), unless it gave way meanwhile
    // ([`Frontier::shed`]): then this answer has nothing to go on from, and the next plan asks
    // again from the start.
    let continuing =
        !received.is_empty() || matches!(want, RangeWant::Body { offset, .. } if offset > 0);
    let kept = match continuing {
        true => match c.frontier.take_partial((room, peer, serial)) {
            Some(kept) => Some(kept),
            None => return Ok(None),
        },
        false => None,
    };
    // C5: the answer is counted from its arrival, at the wire bytes it came in, for this
    // connection and the node ([`Assembly`]); the cut it continues is counted with it. Past the
    // node's total it is let go at once, with that cut, before anything waits: nothing
    // uncounted is held while room is waited for. Room is then waited for one whole answer,
    // which only this node's admission gives back, and the same ask is made again (a body's
    // continuation, whose cut went, is asked again from its start by the next plan).
    let assembly = &c.frontier.assembly;
    let Some(mut charge) = assembly.charge((room, peer), answer.bytes()) else {
        drop((answer, corrected, kept));
        c.assembly_room(None, || {
            assembly
                .has_room(crate::log::history::MAX_RESPONSE_BYTES)
                .then_some(())
        })
        .await?;
        return Ok(match want {
            RangeWant::Body { offset, .. } if offset > 0 => None,
            _ => Some((ask, received, mark)),
        });
    };
    let (cut, pending) = match kept {
        Some((kept, kept_charge)) => {
            charge.join(kept_charge);
            (kept.partial, kept.contexts)
        }
        None => (None, HashMap::new()),
    };
    // The local work, checking the answer and handing its entries over, takes the job; it is
    // given back before the next request is written.
    let job = c.job().await?;
    let (checked, walked_now, hand_head, covered, debt) = c
        .with_room(move |room, store, pin| {
            let committed = std::sync::atomic::AtomicBool::new(false);
            let observed = std::sync::atomic::AtomicBool::new(false);
            let mut checked = bundle::check(
                &PinnedHistory::new(room, pin),
                store,
                &committed,
                &observed,
                head_id,
                anchor,
                want,
                answer,
                cut,
                pending,
            )?;
            // MP-9: the answer proved two signed entries of the author at one position: the
            // fork is recorded, and nothing under that head is admitted.
            if let Some(pair) = checked.fork.take() {
                let (existing, conflicting) = *pair;
                if room.record_history_fork(store, existing, conflicting)? {
                    room.publish_room_snapshot(store);
                }
                checked.brought = true;
                checked.entries.clear();
                checked.partial = None;
            }
            // Positions admission already completed are not handed over again.
            let read = room.history_read(store)?;
            let mut walked_now = BTreeSet::new();
            for entry in &checked.entries {
                let seq = entry.skeleton.seq;
                if held_history::walked(room, &read, &author, seq)? {
                    walked_now.insert(seq);
                }
            }
            // An entry is handed over only under a head committed here: the one predicate
            // its admission checks (`history_head_committed`, in `admission::start_entry` and
            // the validator), true for good once true. An answer under an older prefix of the
            // author's committed head (a promotion another connection's answer overtook) is
            // handed under that committed head, which extends it (`history_head_accepted`: the
            // consistency chain proves it); under any other head nothing is handed over, and
            // its positions stay owed.
            let hand_head = if read.history_head_committed(&head_id, binding)? {
                Some(head_id)
            } else if read.history_head_accepted(&head_id, binding)? {
                read.sparse_author(&author, binding.scope)?
                    .and_then(|state| state.committed)
            } else {
                None
            };
            // The author's coverage from 1, whatever head proved it: what meets its coverage
            // needs, whichever answer brought it.
            let covered = read.history_controls_covered(&author)?;
            // An explicit body answer of a package (step 4): the live debt it fills, matched to
            // the admitted author, position and entry hash; the typed refill checks that debt
            // again in its own transaction. A package body nothing owes here is not handed over.
            // A body asked that no debt owes here any more (another connection's refill stored
            // it, or the debt expired, since the ask was planned) is met: `met`.
            let (debt, met) = match want {
                RangeWant::Body { seq, .. } => {
                    let owed = read.history_key_body_owed_at(&author, seq)?;
                    let debt = checked
                        .entries
                        .iter()
                        .find(|entry| entry.skeleton.seq == seq && entry.payload.is_some())
                        .filter(|entry| is_package(entry))
                        .and_then(|entry| {
                            let hash = entry.entry_hash();
                            owed.as_ref()
                                .filter(|(_, header)| header.entry_hash() == hash)
                                .map(|(head, _)| super::KeyBodyNeed {
                                    head: *head,
                                    author,
                                    seq,
                                    hash,
                                })
                        });
                    (debt, owed.is_none().then_some(seq))
                }
                _ => (None, None),
            };
            drop(read);
            // Positions the published record still owes but the store no longer does are read
            // again, so no plan asks them twice: admission completed them (a body's lifetime
            // ended since the record read them), or the package body debt asked was met.
            let record = room.room_snapshot().current();
            let row = record
                .as_ref()
                .and_then(|s| s.history())
                .and_then(|h| h.author(&author));
            let stale: BTreeSet<u64> = walked_now
                .iter()
                .copied()
                .filter(|seq| !row.is_some_and(|row| row.walked(*seq)))
                .chain(met.filter(|seq| row.is_some_and(|row| row.owed_bodies().contains(*seq))))
                .collect();
            if !stale.is_empty() {
                store.touch_history(room_id, author, stale);
                room.publish_room_snapshot(store);
            }
            Ok((checked, walked_now, hand_head, covered, debt))
        })
        .await
        .map_err(|error| match error {
            // What the holder sends of the same request changed since its last answer (it holds
            // more now), so this one does not go on where that one stopped: not a malformed
            // answer, a refusal to park on; the next ask starts again from nothing skipped.
            Error::MalformedBundle(_) if !received.is_empty() => {
                Error::Unreachable("the peer's answer did not continue where its last one stopped")
            }
            error => error,
        })?;
    c.answered(crate::node::status::RoundReason::Hint, checked.brought);
    // What the answer saved may move a comparison of the author's heads (MP-9): the peer's
    // Have of the author is read again before the next ask.
    if checked.brought {
        c.holdings
            .unobserve(c.room, c.peer, c.conn.serial(), author);
    }
    // The contexts this answer (and those carried into it) left that no proof of it used:
    // never stored (`bundle::check` keeps only what a proof used), carried on to the answer
    // that brings the proof, within [`CARRIED_CONTEXTS`].
    let carried = checked.unused;
    let carried_bytes: usize = carried.values().flatten().map(context_bytes).sum();
    // The answer stopped inside one proof stage (its contexts did not fit), before anything the
    // request wants was completed (no entry, no body cut, no control proof), and carried
    // contexts this continuation had not received: the same ask goes on next, skipping all it
    // has received. Anything completed ends the continuation instead: the next ask starts from
    // the next position afresh (a control interval after its covered part, as an entry page
    // after its entries), and nothing of what came before is remembered. Replayed contexts are
    // not progress (an answer carrying only those takes the refusal below), and neither is more
    // than one unfinished stage: past [`CARRIED_CONTEXTS`] carried, or [`CONTINUED_CONTEXTS`]
    // received, the answer is refused too.
    let stopped_early = status == Status::More
        && checked.partial.is_none()
        && checked.entries.is_empty()
        && checked.controls == 0
        && !fresh.is_empty();
    let resume = stopped_early
        && carried.len() <= CARRIED_CONTEXTS
        && received.len() + fresh.len() <= CONTINUED_CONTEXTS;
    // A holder that answered without what it was asked sends its corrected Have pages of the
    // author, which take the place of what this node held there; `withdrew`: one of them took
    // away a body this node knew the peer held, the one change a correction makes to that
    // knowledge (an identical correction changes nothing).
    let mut withdrew = false;
    for have in corrected.iter().filter(|have| have.author == ask.author) {
        withdrew |= c.holdings.correct(room, peer, &c.conn, have);
    }
    let mut handing = Vec::new();
    for entry in checked.entries {
        let Some(head) = hand_head else {
            break;
        };
        if let Some(need) = debt.filter(|need| need.seq == entry.skeleton.seq) {
            handing.push((head, entry, Some(need)));
            continue;
        }
        // A package body asked explicitly goes only to the typed refill of its debt.
        if matches!(want, RangeWant::Body { .. }) && is_package(&entry) && entry.payload.is_some() {
            continue;
        }
        if walked_now.contains(&entry.skeleton.seq) {
            continue;
        }
        let header_only_role = entry.skeleton.v2.as_ref().is_some_and(|v2| {
            v2.kind == SignedEntryKind::KeyPackage && v2.recipient != Some(c.node)
        });
        // A post whose header and inclusion this answer proved and whose holder said it does
        // not hold its body (`BodyNotHeld`: its corrected Have lacks that body) is admitted
        // without it, shown as "(not received yet)" in its place; its body stays owed and is
        // asked of every peer whose Have says it holds it. An answer that only stopped after a
        // header is not this: its corrected Have, if any, still lists the body, and the
        // position is asked again.
        let body_not_held = entry.payload.is_none()
            && entry
                .skeleton
                .v2
                .as_ref()
                .is_some_and(|v2| v2.kind == SignedEntryKind::Content)
            && corrected.iter().any(|have| {
                let seq = entry.skeleton.seq;
                have.author == author
                    && have.bodies_span.0 <= seq
                    && seq <= have.bodies_span.1
                    && !covers(&have.bodies, seq, seq)
            });
        if entry.payload.is_some()
            || entry.skeleton.payload_len == 0
            || header_only_role
            || body_not_held
        {
            handing.push((head, entry, None));
        }
    }
    // Every position need whose receipt this answer brought is met at once, whatever ask
    // brought it and under whatever head; every coverage need the author's coverage now
    // reaches, likewise.
    c.frontier.received(room, author, &checked.receipts);
    c.frontier.covered(room, author, covered);
    // A coverage need answered in part: what remains of it, from the holder's explicit next
    // position.
    if let (Some(need @ Need::Controls { author, lo, hi }), Status::More, Some(next)) =
        (ask.need, status, continuation.as_ref())
    {
        if checked.partial.is_none() && lo < next.next_seq && next.next_seq <= hi && covered < hi {
            c.frontier.narrow(
                room,
                &need,
                Need::Controls {
                    author,
                    lo: next.next_seq,
                    hi,
                },
            );
        }
    }
    // The answer's charge goes to what it left: its partial body (its bytes and a header), the
    // contexts it carries on, and, undivided, the entries it hands over, until the last of them
    // goes ([`Assembly`]).
    let partial_charge = checked
        .partial
        .as_ref()
        .map(|partial| charge.split(partial.bytes.len() + crate::log::history::MAX_HEADER_BYTES));
    let carried_charge = charge.split(carried_bytes);
    let shared = Arc::new(charge);
    drop(job);
    // What the room's ready set took of the entries handed over: a position another admission
    // already owns (ready, in admission, or waiting for a need such as its own prefix) is not
    // taken again, so an answer that brings only such entries handed nothing over. `owned`: this
    // answer brought the asked package body for its live debt (checked above), and another
    // admission already owns that position (an earlier valid copy queued for its refill): the
    // work is under way elsewhere, and its busy position keeps the plan from choosing it again.
    let offered = handing.iter().any(|(_, _, key_body)| key_body.is_some());
    let handing = if handing.is_empty() {
        Vec::new()
    } else {
        let ready = handing
            .into_iter()
            .map(|(head, entry, key_body)| Ready {
                head,
                entry: Arc::new(entry),
                key_body,
                charge: Arc::clone(&shared),
                checked: None,
            })
            .collect();
        c.frontier.hand(room, peer, ready)
    };
    drop(shared);
    let owned = offered && handing.is_empty();
    // The loop's one no-progress rule (ruling correction 3). A reply is a refusal when the
    // holder declined (Busy, Cancelled, or more unfinished proof stages than one), or when it
    // gave this node nothing (no entry taken by admission, no object saved, no receipt, no
    // partial body, no stage to go on from, no withdrawn body) while this node's record of the
    // author stood as the ask was planned from: nothing the plan reads of the author moved, so
    // the connection parks until news from the peer, and with it everything else that peer could
    // still give (`Connection::until_news`:
    // a Have that changes what this node knows it holds, or this node's own standing). Whatever
    // the status: an empty `Complete` is no exception. Nothing is blamed, and the loop plans
    // again from the record as it is now, when what was asked is met or under way elsewhere:
    // the record of the author moved meanwhile (another connection's refill of the same package
    // committed, an admission of the same positions; the record read again above when it still
    // owed what the store no longer does), or the asked body is `owned` by another admission,
    // or the coverage need asked for is `met` by what the store already held (`covered`): the
    // record stops reading an author's coverage once it has admitted positions
    // (`held_history`), so a need registered after the answer that met it is planned once
    // more; `Frontier::covered` above met it, and no plan asks it again.
    let gave = resume
        || !handing.is_empty()
        || checked.brought
        || !checked.receipts.is_empty()
        || checked.partial.is_some()
        || withdrew;
    let now = c.cell.current();
    let stood = {
        let then = planned.and_then(|history| history.author(&author));
        let now = now
            .as_ref()
            .and_then(|s| s.history())
            .and_then(|h| h.author(&author));
        match (then, now) {
            (Some(then), Some(now)) => std::ptr::eq(then, now),
            (None, None) => true,
            _ => false,
        }
    };
    drop(now);
    let met = matches!(ask.need, Some(Need::Controls { hi, .. }) if hi <= covered);
    let refused = matches!(status, Status::Busy | Status::Cancelled)
        || (stopped_early && !resume)
        || (!gave && stood && !owned && !met);
    // Parked on (`Connection::refused`), with all the same answer proved kept above. A partial
    // body goes with the park, as every live request of a parked connection does.
    if refused {
        return Err(refusal(status));
    }
    if resume {
        received.extend(fresh);
        let kept = Kept {
            partial: None,
            contexts: carried,
        };
        c.frontier
            .keep_partial((room, peer, serial), kept, carried_charge);
        return Ok(Some((ask, received, mark)));
    }
    let (Some(partial), Some(partial_charge)) = (checked.partial, partial_charge) else {
        return Ok(None);
    };
    let offset = partial.bytes.len() as u64;
    let seq = partial.header.skeleton.seq;
    let anchor = ask.head.root.leaves;
    let next = Ask {
        author: ask.author,
        head: ask.head,
        anchor,
        want: RangeWant::Body { seq, offset },
        need: ask.need,
    };
    let kept = Kept {
        partial: Some(partial),
        contexts: HashMap::new(),
    };
    c.frontier
        .keep_partial((room, peer, serial), kept, partial_charge);
    // The continuation is marked before this exchange's mark goes, so its position stays
    // marked throughout.
    let next_mark = c.frontier.mark((c.room, c.peer, c.conn.serial()), &next);
    drop(mark);
    Ok(Some((next, BTreeSet::new(), next_mark)))
}
