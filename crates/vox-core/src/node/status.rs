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
    /// Records by others that taught this node's board something and were passed on
    /// (`NetEvent::BoardGrew`, #179): a member's routine refresh is not one.
    board_news: u64,
    /// Each open room's stored entries set aside when it opened (V210-74), as `author#seq: why`.
    set_aside: BTreeMap<Digest32, Vec<String>>,
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

    /// Count one publish round started.
    pub fn note_publish_round(book: &SharedSyncBook) {
        book.lock()
            .unwrap_or_else(PoisonError::into_inner)
            .publish_rounds += 1;
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
            "],\"publish\":{{\"rounds\":{},\"board_news\":{}}},\"set_aside\":[",
            b.publish_rounds, b.board_news
        );
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
    let mut stream = UnixStream::connect(path).await.map_err(|e| Error::Path {
        op: "connect control socket",
        detail: format!("{}: {e}", path.display()),
    })?;
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
