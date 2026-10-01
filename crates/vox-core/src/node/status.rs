//! ADR-025 S0b — **simple sync counters**, per `(room, peer)`, behind `vox status --json`.
//!
//! The decider's decision 3 (2026-09-26): the proofs assert what a person sees — above all how
//! long a post takes to become readable — and use a handful of counters only for what a person
//! cannot see directly: that nothing was refused, skipped or left stale. There is deliberately no
//! session journal.
//!
//! The counters live in a [`SyncBook`] shared between the actor (the only writer) and every
//! [`crate::node::actor::NodeHandle`] (readers), behind a plain mutex held for a few map updates
//! at a time, so `vox status` answers even while the actor is busy.
//!
//! ## The request
//!
//! `vox status --json` asks the running node over its control socket with the request
//! `[2301]`, and the node answers `[2302, json]`. The tags are the ones PRD-001 R35's fuller
//! `vox status` uses on the v0.3.0 line, so that report can fold this one in: the JSON is an
//! object whose `"sync"` key holds the per-`(room, peer)` rows, and other sections can be added
//! beside it without changing this one.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError};

use tokio::net::UnixStream;

use crate::cbor::{Decoder, Encoder};
use crate::error::{Error, Result};
use crate::hash::Digest32;
use crate::node::ipc::{read_frame, write_frame, Frame, PROTOCOL_VERSION};
use crate::node::link::b32_encode;

/// The kinds of backoff a port can be in (ADR-025 D5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackoffKind {
    /// A transport or stream-open failure.
    Unreachable,
    /// The peer refused with `SessionBusy` (only past its inbound limit), or has not yet admitted
    /// this just-joined member.
    Busy,
    /// A session that left requested positions unfilled and made no progress, or a protocol
    /// violation.
    NoProgress,
    /// The peer refuses by policy: another epoch, not a member, the room not held.
    Policy,
}

impl BackoffKind {
    /// The name `vox status --json` prints.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Unreachable => "unreachable",
            Self::Busy => "busy",
            Self::NoProgress => "no_progress",
            Self::Policy => "policy",
        }
    }
}

/// One `(room, peer)`'s counters.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PortCounters {
    /// Outbound sessions this node opened.
    pub opened: u64,
    /// Inbound sessions this node admitted.
    pub admitted: u64,
    /// Inbound sessions this node refused with `SessionBusy`.
    pub busy_refused: u64,
    /// Sessions (either direction) that completed with every requested entry received.
    pub completed: u64,
    /// Sessions that ended without error but left requested entries unreceived (a bounded serve).
    pub partial: u64,
    /// Sessions that failed.
    pub failed: u64,
    /// The last failure's reason.
    pub last_failure: Option<String>,
    /// Results that arrived for an attempt already retired (ADR-025 D1a).
    pub stale: u64,
    /// Entries this peer served that were refused rather than held (V210-74): without their
    /// payload, past a position not held, or signed but unclassifiable.
    pub refused: u64,
    /// Sessions that were due but skipped because every outbound slot was taken.
    pub skipped_at_cap: u64,
    /// Times a port waited in the outbound queue for a slot (ADR-025 D6).
    pub queued: u64,
    /// The backoff the port is in now, and its consecutive failures.
    pub backoff: Option<(BackoffKind, u32)>,
}

/// Why a publish round started (V210-68): one round per `(room, board)`, counted by what asked
/// for it, so a count of rounds can be accounted for in full.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PublishCause {
    /// The scheduled renewal of the room's own records.
    Renewal,
    /// An anchor connected (or came back): it holds none of this node's records yet.
    AnchorReturned,
    /// A board passed on news of a record, which this node's anchors are given too.
    BoardNews,
    /// This node learned its public addresses, which its records must name.
    Addresses,
    /// A board asked for this node's records again.
    AskedAgain,
    /// A publish asked for while a round to the same board was in flight, run once it ended.
    Again,
    /// A round that failed, retried.
    Retry,
    /// A sync that brought governance, which changes the records.
    Governance,
    /// A join, on either side.
    Join,
    /// The room was created, opened, reopened or served.
    Opened,
}

impl PublishCause {
    /// Every cause, in the order `vox status --json` lists them.
    pub const ALL: [PublishCause; 10] = [
        Self::Renewal,
        Self::AnchorReturned,
        Self::BoardNews,
        Self::Addresses,
        Self::AskedAgain,
        Self::Again,
        Self::Retry,
        Self::Governance,
        Self::Join,
        Self::Opened,
    ];

    /// The name `vox status --json` uses.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Renewal => "renewal",
            Self::AnchorReturned => "anchor_returned",
            Self::BoardNews => "board_news",
            Self::Addresses => "addresses",
            Self::AskedAgain => "asked_again",
            Self::Again => "again",
            Self::Retry => "retry",
            Self::Governance => "governance",
            Self::Join => "join",
            Self::Opened => "opened",
        }
    }
}

/// Every `(room, peer)`'s counters.
#[derive(Debug, Default)]
pub struct SyncBook {
    ports: BTreeMap<(Digest32, Digest32), PortCounters>,
    /// How many reachability ladders this node has run to each peer (`NodeNet::reach`): one per
    /// dial that found no connection to reuse and no other reach to the same peer under way to
    /// wait on (V210-53, #232). What no person can see directly — two dials where one would do.
    ladders: BTreeMap<Digest32, u64>,
    /// Publish rounds this node started (one per `(room, board)` round that went out): what no
    /// person can see directly, and what a storm of rounds looks like (#179).
    publish_rounds: u64,
    /// The same rounds by what asked for each (V210-68).
    publish_by_cause: BTreeMap<PublishCause, u64>,
    /// Scheduled renewals of a room's own records (V210-68): one per room per half of the
    /// records' lifetime, whatever the traffic and however many boards the round then reaches.
    renewals: u64,
    /// Records by others that taught this node's board something and were passed on
    /// (`NetEvent::BoardGrew`, #179): a member's routine refresh is not one.
    board_news: u64,
    /// The prekey ring as the running node last maintained it (V210-77), or `None` while it
    /// holds no ring.
    prekeys: Option<PrekeyCounts>,
    /// Each open room's stored entries set aside when it opened (V210-74), as `author#seq: why`.
    set_aside: BTreeMap<Digest32, Vec<String>>,
}

/// What the prekey ring holds, and what keeping it up has done since the node started.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PrekeyCounts {
    /// One-time prekeys left to offer.
    pub one_time: usize,
    /// Consumed one-time prekeys still retained for a concurrent duplicate use.
    pub consumed: usize,
    /// The id of the signed prekey offered now.
    pub signed_prekey: u64,
    /// Signed-prekey rotations the running node made.
    pub rotated: u64,
    /// One-time prekeys the running node added.
    pub refilled: u64,
    /// Sessions the running node set up with its previous signed prekey: started just before a
    /// rotation, completed after it.
    pub previous_used: u64,
}

/// The book as the actor and the handles share it.
pub type SharedSyncBook = Arc<Mutex<SyncBook>>;

impl SyncBook {
    /// A new shared, empty book.
    #[must_use]
    pub fn shared() -> SharedSyncBook {
        Arc::new(Mutex::new(Self::default()))
    }

    /// Update one port's counters.
    pub fn with(
        book: &SharedSyncBook,
        room: Digest32,
        peer: Digest32,
        f: impl FnOnce(&mut PortCounters),
    ) {
        let mut b = book.lock().unwrap_or_else(PoisonError::into_inner);
        f(b.ports.entry((room, peer)).or_default());
    }

    /// Count one scheduled renewal of a room's own records (V210-68).
    pub fn note_renewal(book: &SharedSyncBook) {
        book.lock().unwrap_or_else(PoisonError::into_inner).renewals += 1;
    }

    /// Count one publish round started, and what asked for it.
    pub fn note_publish_round(book: &SharedSyncBook, cause: PublishCause) {
        let mut b = book.lock().unwrap_or_else(PoisonError::into_inner);
        b.publish_rounds += 1;
        *b.publish_by_cause.entry(cause).or_default() += 1;
    }

    /// What `room` set aside when it opened (V210-74); nothing, and the room is not listed.
    pub fn note_set_aside(book: &SharedSyncBook, room: Digest32, entries: &[String]) {
        let mut b = book.lock().unwrap_or_else(PoisonError::into_inner);
        if entries.is_empty() {
            b.set_aside.remove(&room);
        } else {
            b.set_aside.insert(room, entries.to_vec());
        }
    }

    /// Count one record of news on this node's board, passed on.
    pub fn note_board_news(book: &SharedSyncBook) {
        book.lock()
            .unwrap_or_else(PoisonError::into_inner)
            .board_news += 1;
    }

    /// Record the ring as it stands after a maintenance that `rotated` and added `added`, and
    /// how many sessions it has set up with its previous signed prekey.
    pub fn note_prekeys(
        book: &SharedSyncBook,
        one_time: usize,
        consumed: usize,
        signed_prekey: u64,
        rotated: bool,
        added: usize,
        previous_used: u64,
    ) {
        let mut b = book.lock().unwrap_or_else(PoisonError::into_inner);
        let c = b.prekeys.get_or_insert_with(PrekeyCounts::default);
        c.one_time = one_time;
        c.consumed = consumed;
        c.signed_prekey = signed_prekey;
        c.rotated += u64::from(rotated);
        c.refilled += u64::try_from(added).unwrap_or(u64::MAX);
        c.previous_used = previous_used;
    }

    /// Count one reachability ladder run to `peer`.
    pub fn note_ladder(book: &SharedSyncBook, peer: Digest32) {
        let mut b = book.lock().unwrap_or_else(PoisonError::into_inner);
        *b.ladders.entry(peer).or_default() += 1;
    }

    /// The counters as `vox status --json` prints them, with the rooms' equivocations
    /// (`(room, author, position)`, V210-63).
    #[must_use]
    pub fn to_json(book: &SharedSyncBook, equivocations: &[(Digest32, Digest32, u64)]) -> String {
        let b = book.lock().unwrap_or_else(PoisonError::into_inner);
        let mut s = String::from("{\"sync\":[");
        for (i, ((room, peer), c)) in b.ports.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            let _ = write!(
                s,
                "{{\"room\":\"{}\",\"peer\":\"{}\",\"opened\":{},\"admitted\":{},\"busy_refused\":{},\
                 \"completed\":{},\"partial\":{},\"failed\":{},\"last_failure\":{},\"stale\":{},\
                 \"refused\":{},\"skipped_at_cap\":{},\"queued\":{},\"backoff\":{}}}",
                b32_encode(room),
                b32_encode(peer),
                c.opened,
                c.admitted,
                c.busy_refused,
                c.completed,
                c.partial,
                c.failed,
                c.last_failure
                    .as_deref()
                    .map_or_else(|| "null".to_owned(), json_string),
                c.stale,
                c.refused,
                c.skipped_at_cap,
                c.queued,
                c.backoff.map_or_else(
                    || "null".to_owned(),
                    |(k, n)| format!("{{\"kind\":\"{}\",\"failures\":{n}}}", k.name())
                ),
            );
        }
        s.push_str("],\"reach\":[");
        // Ladders from this book; circuits counted where every outbound circuit is asked for
        // (`circuitstream::connect_through`). Every peer either names, in one row.
        let circuits = crate::node::circuitstream::outbound_circuits();
        let peers: std::collections::BTreeSet<&Digest32> =
            b.ladders.keys().chain(circuits.keys()).collect();
        for (i, peer) in peers.into_iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            let _ = write!(
                s,
                "{{\"peer\":\"{}\",\"ladders\":{},\"circuits\":{}}}",
                b32_encode(peer),
                b.ladders.get(peer).copied().unwrap_or(0),
                circuits.get(peer).copied().unwrap_or(0)
            );
        }
        // **Who this node holds back for equivocating, and where** (V210-63): each an author seen
        // signing two different messages at one position in a room. For agents, as full ids; a
        // person reads it in `vox room read`.
        s.push_str("],\"equivocations\":[");
        for (i, (room, author, position)) in equivocations.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            let _ = write!(
                s,
                "{{\"room\":\"{}\",\"author\":\"{}\",\"position\":{position}}}",
                b32_encode(room),
                b32_encode(author),
            );
        }
        let _ = write!(
            s,
            "],\"publish\":{{\"rounds\":{},\"by_cause\":{{",
            b.publish_rounds
        );
        for (i, cause) in PublishCause::ALL.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            let n = b.publish_by_cause.get(cause).copied().unwrap_or(0);
            let _ = write!(s, "\"{}\":{n}", cause.name());
        }
        let _ = write!(
            s,
            "}},\"renewals\":{},\"board_news\":{}}},\"prekeys\":",
            b.renewals, b.board_news
        );
        match b.prekeys {
            Some(p) => {
                let _ = write!(
                    s,
                    "{{\"one_time\":{},\"consumed\":{},\"signed_prekey\":{},\"rotated\":{},\
                     \"refilled\":{},\"previous_used\":{}}}",
                    p.one_time, p.consumed, p.signed_prekey, p.rotated, p.refilled, p.previous_used
                );
            }
            None => s.push_str("null"),
        }
        s.push_str(",\"set_aside\":[");
        for (i, (room, entries)) in b.set_aside.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            let list: Vec<String> = entries.iter().map(|e| json_string(e)).collect();
            let _ = write!(
                s,
                "{{\"room\":\"{}\",\"entries\":[{}]}}",
                b32_encode(room),
                list.join(",")
            );
        }
        s.push_str("]}");
        s
    }
}

/// `text` as a JSON string literal.
fn json_string(text: &str) -> String {
    let mut s = String::with_capacity(text.len() + 2);
    s.push('"');
    for c in text.chars() {
        match c {
            '"' => s.push_str("\\\""),
            '\\' => s.push_str("\\\\"),
            '\n' => s.push_str("\\n"),
            '\r' => s.push_str("\\r"),
            '\t' => s.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(s, "\\u{:04x}", c as u32);
            }
            c => s.push(c),
        }
    }
    s.push('"');
    s
}

// ---- IPC -------------------------------------------------------------------
// Additive to the control protocol, away from the sequential tags, as PRD-001 R35's are.

const T_STATUS: u64 = 2301;
const T_STATUS_REPORT: u64 = 2302;

/// Whether `body` is a status request.
#[must_use]
pub fn is_request(body: &[u8]) -> bool {
    let mut d = Decoder::new(body);
    matches!((d.array(), d.uint()), (Ok(1), Ok(T_STATUS)))
}

/// Answer a status request on the control socket.
///
/// # Errors
/// If the reply cannot be written.
pub async fn serve(
    stream: &mut UnixStream,
    book: &SharedSyncBook,
    equivocations: &[(Digest32, Digest32, u64)],
) -> Result<()> {
    let mut e = Encoder::new();
    e.array(2)
        .uint(T_STATUS_REPORT)
        .text(&SyncBook::to_json(book, equivocations));
    write_frame(stream, &e.finish()).await
}

/// Ask the node listening on `path` for its status, as JSON.
///
/// # Errors
/// If the node cannot be reached or answers something else.
pub async fn request(path: &Path) -> Result<String> {
    let mut stream = crate::node::ipc::connect_own(path).await?;
    let Some(hello) = read_frame(&mut stream).await? else {
        return Err(Error::MalformedBundle("ipc closed before hello"));
    };
    match Frame::from_bytes(&hello)? {
        Frame::Hello { protocol, .. } if protocol == PROTOCOL_VERSION => {}
        _ => return Err(Error::MalformedBundle("ipc protocol version")),
    }
    let mut e = Encoder::new();
    e.array(1).uint(T_STATUS);
    write_frame(&mut stream, &e.finish()).await?;
    let Some(body) = read_frame(&mut stream).await? else {
        return Err(Error::MalformedBundle("ipc closed before reply"));
    };
    let mut d = Decoder::new(&body);
    if let (Ok(2), Ok(T_STATUS_REPORT)) = (d.array(), d.uint()) {
        return d
            .text()
            .map(str::to_owned)
            .map_err(|_| Error::MalformedBundle("ipc status reply"));
    }
    match Frame::from_bytes(&body)? {
        Frame::Error { reason } => Err(Error::Path {
            op: "vox status",
            detail: reason,
        }),
        _ => Err(Error::MalformedBundle("ipc status reply")),
    }
}
