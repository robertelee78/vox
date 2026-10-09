//! ADR-020 §7 — the node's local control socket: the seam that carries
//! [`NodeEvent`]s to **out-of-process** clients.
//!
//! Agent comms puts several agent sessions on one harness node (ADR-020 §2: one
//! node per `(host, harness)`, many sessions). M19.1a made the in-process
//! fan-out safe — emission never blocks and a lagging subscriber is told so.
//! This module carries that same stream across a process boundary, preserving
//! the same property: **no client can stall the node, and no client can disturb
//! another.**
//!
//! ## What this is not
//!
//! It is deliberately **not** a mirror of [`NodeCommand`](super::api::NodeCommand). That enum carries
//! [`Secret`](super::api::Secret) — passphrases — and reaches `CreateIdentity` and
//! `Revoke`. An agent session runs model-authored code and
//! has no business issuing any of those, so the socket speaks its own narrow
//! vocabulary and this milestone carries **events only**. Requests that let a
//! client *act* arrive with the agent-comms protocol (ADR-020 §4), scoped to what
//! an app legitimately needs.
//!
//! Being honest about what that buys: the socket is `0600`, so only this uid can
//! open it — and that uid can already read `vault.cbor` in the same directory.
//! The narrow surface is therefore **accident prevention, not a security
//! boundary**, and must not be described as one. The boundary is the file mode.
//!
//! ## Wire
//!
//! Frames are length-delimited exactly as [`crate::transport::framing`] does it
//! on QUIC — a 4-byte big-endian length, then that many bytes — with a cap so a
//! client cannot announce a huge length to force an allocation. Each frame body
//! is canonical fixed-arity CBOR (ADR-008's house encoding, via
//! [`crate::cbor`]), a `[tag, ..fields]` array. No domain-separation label: these
//! frames are neither signed nor authenticated, because the file mode is what
//! authorises the peer.
//!
//! ## Lifecycle facts, measured rather than assumed (M19.1b spike)
//!
//! - `UnixListener::bind` yields a **0755** socket (the mode comes from the
//!   umask), so the explicit `chmod` to `0600` is REQUIRED, not belt-and-braces. It is
//!   done under a staging name before the socket is renamed into place, so the path a
//!   client connects to is never there at any other mode (V210-72).
//! - A leftover socket file from a process that died makes `bind` fail with
//!   `AddrInUse` (errno 48), so the stale file is unlinked first — deliberately,
//!   rather than inheriting a confusing "address in use".
//! - A client that dies reads as a clean EOF and writing to it fails with
//!   `BrokenPipe`; both are isolated to that connection.

use std::path::{Path, PathBuf};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};

use crate::cbor::{Decoder, Encoder};
use crate::error::{Error, IpcHandshake, Result};
use crate::hash::Digest32;
use crate::node::actor::{EventStream, EventStreamItem, NodeHandle};
use crate::node::api::{MessageRow, NodeEvent};

/// The protocol this build speaks. Bumped when a frame's shape changes in a way
/// an older client would misread; a client that sees a version it does not know
/// MUST disconnect rather than guess.
///
/// 6: the app API (`node::appipc`, ADR-022 M22.5). 7: a row carries where it arrived
/// and whether it arrived late, and `Order` asks for the room's whole order (ADR-023
/// decision 1). Both 6s were bumped on separate branches; the merged build is 7.
///
/// v0.2.10's changes are carried at 7 without a bump, as v0.2.10 carried them at 5: `Rooms` is
/// paged (an unpaged request is still read as the first page), and its new events
/// (`SyncFailed`, `RoomNotRemembered`) are additive tags.
///
/// 8: a row says whether its body is **not received yet** (V030-10, [`MessageRow::owed`]).
///
/// 9: one daemon serves every node of a data root on one socket (ADR-026 §4). A connection opens
/// with the daemon's hello and the client's `Use` or daemon request
/// ([`crate::node::daemonipc`]); a request in flight when its node detaches is answered
/// [`Frame::NodeDetached`].
pub const PROTOCOL_VERSION: u64 = 9;

/// Largest frame accepted in either direction.
///
/// Comfortably above the largest event — `InviteLink`'s URL and a `NewEntry`'s
/// text are the only unbounded-ish fields, and message text is already capped at
/// [`crate::node::content::MAX_TEXT_LEN`] (64 KiB).
pub const MAX_FRAME: usize = 256 * 1024;

/// What one `Rows` reply may carry, counted as text plus [`ROW_OVERHEAD`] per row.
/// Half a frame, so an estimate that ran short would still fit.
pub const ROWS_BUDGET: usize = MAX_FRAME / 2;

/// The environment variable [`frame_limit`] reads. **Test-only.**
#[cfg(feature = "test-knobs")]
pub const TEST_MAX_FRAME_ENV: &str = "VOX_TEST_MAX_FRAME";

/// The smallest frame `VOX_TEST_MAX_FRAME` may set: half of it still carries the largest room
/// or trusted-identity entry, so a listing still pages.
pub const MIN_TEST_FRAME: usize = 4 * 1024;

/// The largest frame accepted in force: [`MAX_FRAME`], or **lower**, read once from
/// [`TEST_MAX_FRAME_ENV`]. **Test-only: for proofs; nothing in a real deployment sets it.**
///
/// #189's proof shows that `vox room list` and `vox trust list` name every entry past one frame,
/// through the shipped binary. At the real 256 KiB frame that takes about 1,540 rooms, each
/// sealed with production Argon2id, which does not fit a watchdog; the decider puts a node's
/// realistic ceiling at a couple of hundred rooms. With a smaller frame, a couple of hundred
/// rooms outgrow one, so a reply that is not paged fails exactly as the defect did ("ipc frame
/// length"), and a paged one crosses several pages. It only ever lowers the limit, clamped to
/// [`MIN_TEST_FRAME`]..=[`MAX_FRAME`]; unset, empty or unparsable is [`MAX_FRAME`]. Under it, a
/// single row larger than half the frame (a long message) is refused, so a proof that sets it
/// keeps its rows small.
#[cfg(feature = "test-knobs")]
#[must_use]
pub fn frame_limit() -> usize {
    static LIMIT: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *LIMIT.get_or_init(|| {
        std::env::var(TEST_MAX_FRAME_ENV)
            .ok()
            .and_then(|v| v.trim().parse::<usize>().ok())
            .map_or(MAX_FRAME, |n| n.clamp(MIN_TEST_FRAME, MAX_FRAME))
    })
}

/// The largest frame accepted: [`MAX_FRAME`]. The proof-only lower limit is not compiled in
/// without the `test-knobs` feature (V210-105).
#[cfg(not(feature = "test-knobs"))]
#[must_use]
pub const fn frame_limit() -> usize {
    MAX_FRAME
}

/// What one reply may carry in force: half of [`frame_limit`] ([`ROWS_BUDGET`] unless a proof
/// lowered the frame).
#[must_use]
pub fn rows_budget() -> usize {
    frame_limit() / 2
}

/// Everything a row carries besides its text — two 32-byte hashes, a timestamp and the
/// CBOR around them — rounded up.
pub const ROW_OVERHEAD: usize = 128;

/// At most this many entries in one page of a `Rooms` or `Trusted` reply. Bytes bound
/// a page too ([`ROWS_BUDGET`]); the count keeps pages small enough that a proof can
/// show paging with a hundred entries rather than thousands.
pub const PAGE_ENTRIES: usize = 64;

/// Everything a `Rooms` or `Trusted` entry carries besides its name — a 32-byte id,
/// a flag and the CBOR around them — rounded up.
pub const ENTRY_OVERHEAD: usize = 64;

// A page always carries at least one entry, so the largest entry must fit by itself.
const _: () = assert!(
    crate::node::channel::MAX_LOCAL_NAME_LEN + ENTRY_OVERHEAD <= ROWS_BUDGET
        && crate::node::trust::MAX_PETNAME + ENTRY_OVERHEAD <= ROWS_BUDGET
);

// A reply always carries at least one row, so the largest row must fit a frame by itself.
const _: () = assert!(crate::node::content::MAX_TEXT_LEN + ROW_OVERHEAD <= ROWS_BUDGET);

// ---- frame tags ------------------------------------------------------------
// Node → client.
const T_HELLO: u64 = 1;
const T_LAGGED: u64 = 2;
const T_NEW_ENTRY: u64 = 10;
// 11 and 12 were `Unlocked` and `Locked`: there is no lock (ADR-026 N-2). Never reuse them.
const T_CHANNEL_OPENED: u64 = 13;
const T_CHANNEL_CLOSED: u64 = 14;
const T_PEER_JOINED: u64 = 15;
/// `[2525, fingerprint, drive]` — [`NodeEvent::CapabilityChanged`] (ADR-028 K-14).
const T_CAPABILITY_CHANGED: u64 = 2525;
/// `[2526, channel_id, session_id]` — [`NodeEvent::SessionEntry`] (ADR-029 CL-2).
const T_SESSION_ENTRY: u64 = 2526;
const T_SENDER_KEY: u64 = 16;
const T_FORWARDING: u64 = 17;
const T_INVITE_LINK: u64 = 18;
const T_JOINED: u64 = 19;
const T_CONSENTED: u64 = 20;
const T_REVOKED: u64 = 21;
const T_TUNNEL_SERVED: u64 = 22;
const T_PROXY_UP: u64 = 23;
const T_SYNCED: u64 = 24;
const T_SHUTDOWN: u64 = 25;
/// Deliberately **not** the next number in the sequence: 1711 is the milestone this event
/// belongs to (ADR-017 M17.11), and taking a number far from the sequential range keeps
/// this additive tag from colliding with one a concurrently-developed branch assigns. The
/// tag space is sparse and `u64`; there is nothing to save by packing it.
const T_REACH_WITHDRAWN: u64 = 1711;
/// Additive, and deliberately away from the sequential range (see above).
const T_PROXY_REFUSED: u64 = 1712;
/// Additive, and deliberately away from the sequential range (see above).
const T_STILL_RELAYED: u64 = 1713;
/// `NodeEvent::TunnelClosed` (V030-11). Additive, numbered for the item.
const T_TUNNEL_CLOSED: u64 = 3011;
/// Additive, and deliberately away from the sequential range (see above).
const T_JOIN_FAILED: u64 = 1714;
/// Additive, and deliberately away from the sequential range (see above).
const T_STALLED: u64 = 1715;

/// `NodeEvent::PeerUnreachable`.
const T_PEER_UNREACHABLE: u64 = 1716;
/// `NodeEvent::PublishRefused`. Additive, and deliberately away from the sequential range.
const T_PUBLISH_REFUSED: u64 = 1717;
/// `NodeEvent::PublishCured` (V210-51). Additive, away from both the sequential range and the tags
/// the v0.3.0 line uses.
const T_PUBLISH_CURED: u64 = 2091;
/// `NodeEvent::ConnectionNote` (#229's diagnostics). Additive, beside `T_PUBLISH_CURED`.
const T_CONNECTION_NOTE: u64 = 2092;
/// `NodeEvent::NodeNote` (V210-167). Additive, away from the tags beside it.
const T_NODE_NOTE: u64 = 2392;
/// `NodeEvent::NetworkChanged` (ADR-012 N-52). Additive, away from the tags beside it.
const T_NETWORK_CHANGED: u64 = 3149;
/// `NodeEvent::HandshakesQueued` (V210-86). Additive, away from the tags beside it.
const T_HANDSHAKES_QUEUED: u64 = 2186;
/// `NodeEvent::AddressWithheld` (V210-96). Additive, away from the sequential range and the tags
/// other lines use.
const T_ADDRESS_WITHHELD: u64 = 2296;
/// `NodeEvent::AddressNote` (V210-96). Additive, beside `T_ADDRESS_WITHHELD`.
const T_ADDRESS_NOTE: u64 = 2297;
/// [`NodeEvent::JoinSteps`]: where a join's time went.
const T_JOIN_STEPS: u64 = 1718;
/// [`NodeEvent::JoinStep`] (V210-85): the step a join is in now. Additive, away from the other
/// additive tags.
const T_JOIN_STEP: u64 = 2285;
/// `NodeEvent::KeyNotTaken`.
const T_KEY_NOT_TAKEN: u64 = 1719;
/// `NodeEvent::WaitingForProfile` (V210-100). Additive, away from the sequential range and from
/// the tags the v0.3.0 line uses.
const T_WAITING_FOR_PROFILE: u64 = 2100;
/// A sync session with a peer did not complete, and why (#202).
const T_SYNC_FAILED: u64 = 1720;
/// [`NodeEvent::RoomNotRemembered`] (#208). Additive, and far from the other additive tags so a
/// concurrently-developed branch that takes 1721 does not collide with it.
const T_ROOM_NOT_REMEMBERED: u64 = 2081;
/// `NodeEvent::RetentionAboveRoom` (V030-32): a node file value above the room's, ignored.
const T_RETENTION_ABOVE_ROOM: u64 = 3803;
const T_OK: u64 = 3;
const T_ERROR: u64 = 4;
const T_ROWS: u64 = 5;
const T_MEMBERS: u64 = 6;
/// [`Frame::Consents`] (V030-17).
const T_CONSENTS: u64 = 3271;
const T_ROOMS: u64 = 7;

const T_BOUND: u64 = 8;
/// `Frame::OwnRetention` (V030-32).
const T_OWN_RETENTION: u64 = 3802;
const T_LINK: u64 = 9;
/// Protocol 5. 8 and 9 were taken (`T_BOUND`, `T_LINK`), which a first attempt at this
/// collided with — the decoder then read a trusted list as a bound address and said
/// "malformed identity bundle", three layers from the cause.
const T_TRUSTED: u64 = 26;
/// Protocol 6: the room's whole order, as `(entry hash, clock)` pairs.
const T_ORDER_ROWS: u64 = 27;
/// The services a [`Request::Services`] asked for (V030-24).
const T_SERVICES: u64 = 28;
// Client → node.
const T_SUBSCRIBE: u64 = 1;
const T_POST: u64 = 2;
const T_READ: u64 = 3;
const T_ROSTER: u64 = 4;
/// [`Request::Consents`] (V030-17).
const T_CONSENTS_REQ: u64 = 3270;
const T_ROOMS_REQ: u64 = 5;
// Protocol 3 — the service verbs an agent needs for file exchange (ADR-020 §11).
// They exist on this socket, rather than as one-shot verbs that open the profile,
// because redb is single-writer: a verb that started its own node could not run
// while `vox daemon` held the profile, which is exactly when an agent needs it.
const T_ADD_SERVICE: u64 = 6;
const T_REMOVE_SERVICE: u64 = 7;
const T_FORWARD: u64 = 8;
const T_STOP_FORWARD: u64 = 9;
// 10 was `T_GRANT`, the withdrawn `dial:`/`bind:` grant (ADR-017 decision 3). Never reuse it.
// Protocol 4 — joining and creating a room over the socket (ADR-020 §12).
// Without these, a room can only be created or joined from the TUI, so an agent on
// a host with no terminal has a daemon that can *hold* rooms and no way to ever
// get one onto it. `vox daemon` made the feature runnable headless; these make it
// reachable headless.
const T_JOIN: u64 = 11;
const T_CREATE: u64 = 12;
const T_INVITE: u64 = 13;
// Protocol 5 — the trust keyring, **gated on the identity passphrase** (ADR-020 §3, §7).
//
// §7 keeps keyring edits off this socket because an agent session runs model-authored
// code, and that reasoning stands. But the consequence was that `vox trust add` — the
// act that decides who may read you, and therefore unavoidable — could not be run at all
// while a `vox daemon` held the profile, which is the documented way to run agent comms.
// A person setting up two agents hit "Database already open. Cannot acquire lock." on the
// one command they could not skip.
//
// So the keyring is reachable here. The socket's file mode is the boundary: whoever runs as
// this user is this user. A change needs the identity passphrase once 30 minutes have passed
// since it was last entered, which the node decides for every client alike (V210-159); a read
// needs none (V210-165).
const T_TRUST: u64 = 14;
const T_UNTRUST: u64 = 15;
const T_TRUST_LIST: u64 = 16;
// Setting a room's retention deletes what is already stored (ADR-023 decision 2), so it is an
// operator decision like the keyring and carries the identity passphrase the same way.
const T_RETENTION: u64 = 23;
// Protocol 6 — every entry the node holds for a room, in the room's one order
// (PRD-001 R13), readable or not. What "the same order on every node" is checked
// against, because a node's timeline shows only the rows it holds keys for.
const T_ORDER: u64 = 24;
// Renaming a trusted identity keeps its history grant (PRD-001 R12, R20's `vox name`).
const T_RENAME: u64 = 25;
/// `[525, target, drive, identity_passphrase]` — [`Request::SetCapability`] (ADR-028 K-14).
const T_SET_CAPABILITY: u64 = 525;
// **Liveness** (V210-83). Answered by the actor and changes nothing, so a client waiting on a long
// request can tell a node at work from a suspended or stuck one. Not a protocol bump: a node that
// does not know it answers with an error, and any answer is proof of life.
const T_PING: u64 = 17;
// V210-120: a room's structured posts by `type`, and rows by entry hash, so a client that needs a
// room's coordination posts, or one row, does not read the whole room for them. Numbered far from
// the others so a concurrently-developed branch taking 18 does not collide.
const T_STRUCTURED: u64 = 120;
const T_FIND: u64 = 121;
const T_COUNT_REQ: u64 = 122;
// ADR-028 RR-1: entries shown or drained, for a read record. Numbered by its story (#503).
const T_MARK_READ: u64 = 503;
// V210-164: leaving a room over the socket, as joining and creating one are. Numbered by its item,
// far from the others, like V210-120's.
const T_LEAVE: u64 = 164;
/// ADR-026 C-7: open and close a room over the socket (protocol 9).
const T_OPEN_ROOM: u64 = 4400;
const T_CLOSE_ROOM: u64 = 4401;
/// [`Frame::Count`] (V210-120), in the frame and event tag space, far from the others.
const T_COUNT: u64 = 1200;
// What this node's person has not read in a room, for a client starting (ADR-028 R-8): answered
// with [`Frame::Rows`]. Numbered by the unread levels' item (#484), far from the others.
const T_UNREAD_REQ: u64 = 2484;
// The services a room offers (V030-24): `vox service list` with a daemon running. `add` and
// `remove` reached the daemon (V030-06) while `list` still opened the profile, which the daemon
// holds, so a service just added could not be listed. Not a protocol bump: additive, and a node
// that does not know it answers with an error.
const T_SERVICES_REQ: u64 = 18;
// V210-168: ask every member whether it holds a claim this node posted.
const T_AGREE: u64 = 123;
/// [`Frame::Agreement`] (V210-168).
const T_AGREEMENT: u64 = 1201;
// A room's lifecycle (V030-08): end, admins and the creator's idle end; a leave is `T_LEAVE`.
// Not gated on the identity passphrase: tearing down a room the work is done in is an agent's
// call to make. 31 was `vox room forget`, removed (the decider, 2026-10-03): reserved.
const T_END: u64 = 32;
const T_IDLE_END: u64 = 33;
const T_SET_ADMIN: u64 = 34;
const T_ADMINS: u64 = 35;
/// `[36, channel_id, name]` — [`Request::RenameRoom`] (ADR-028 R-1).
const T_RENAME_ROOM: u64 = 36;
/// `NodeEvent::RoomEnded` and `NodeEvent::RoomRemoved` (V030-08). Additive.
const T_ROOM_ENDED: u64 = 2440;
const T_ROOM_REMOVED: u64 = 2441;
// File shares the daemon serves (ADR-028 F-1, F-2). Additive.
const T_SHARE: u64 = 4930;
const T_SHARE_STOP: u64 = 4931;
const T_SHARE_LIST: u64 = 4932;
/// [`Frame::Shares`].
const T_SHARES: u64 = 4933;
// Session entries, sealed to members with drive (ADR-029 SC-1, SC-2). Additive.
/// `[5430, channel_id, session_id, body]` — [`Request::AppendSession`].
const T_SESSION_APPEND: u64 = 5430;
/// `[5431, channel_id]` — [`Request::SessionEntries`].
const T_SESSION_ENTRIES: u64 = 5431;
/// [`Frame::SessionEntries`].
const T_SESSION_ROWS: u64 = 5432;
const T_SESSIONS_REQ: u64 = 4940;
const T_SESSIONS: u64 = 4941;
/// `[5450, limit]` — [`Request::Decisions`] (#563).
const T_DECISIONS_REQ: u64 = 5450;
/// [`Frame::Decisions`].
const T_DECISIONS: u64 = 5451;
/// [`Frame::Appended`].
const T_APPENDED: u64 = 5433;
/// `[5434, channel_id, path, envelope, to]` — [`Request::SessionShare`]; `to` is `[0, session
/// id]` out of a Session, `[1, node]` into one (ADR-029 DR-1, #546).
const T_SESSION_SHARE: u64 = 5434;

/// Which way a file goes through a Session (ADR-029 DR-1; #546).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionTo {
    /// Out of this node's Session with this harness session id, to its members with drive.
    Session(String),
    /// Into a Session on this node: the Session's node.
    Node(Digest32),
}
const T_OFFERS_REQ: u64 = 4950;
const T_DISMISS_OFFER: u64 = 4951;
const T_OFFERS: u64 = 4952;

/// What a client sends.
///
/// Deliberately narrow (ADR-020 §7): an app client posts, reads and looks at the
/// roster. It cannot create an identity, unlock, revoke, or edit the trust
/// keyring — those carry passphrases or are operator decisions, and an agent
/// session runs model-authored code. The file mode is the actual boundary; this
/// is accident prevention on top of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    /// Begin streaming events. Everything emitted from this point reaches this
    /// client; nothing before it does. **Terminal** — the connection becomes a
    /// stream and serves no further requests.
    Subscribe,
    /// Entries of a room shown to this node's person or drained into its agent's turn (ADR-028
    /// RR-1): the node posts a read record for them, batched (RR-2). At most
    /// [`crate::node::content::MAX_READ_HASHES`]; a client with more sends more requests.
    MarkRead {
        /// The room.
        channel_id: Digest32,
        /// The entries shown.
        entries: Vec<Digest32>,
    },
    /// Append a message to a room.
    Post {
        /// The room.
        channel_id: Digest32,
        /// The message text (an agent-comms envelope is JSON in here).
        text: String,
        /// Whether the node fetches a link card for its first URL (ADR-028 F-10): `vox room post
        /// --no-card` says not to.
        card: bool,
    },
    /// Read a room's rendered timeline, optionally only what follows a cursor.
    Read {
        /// The room.
        channel_id: Digest32,
        /// Return only entries **after** this one. Absent reads from the start.
        since: Option<Digest32>,
        /// Continue a read that has no cursor after this row, in the room's order: the page
        /// mark of a read that came in pages. It is not `since`, which is a feed by arrival
        /// (see the server): paging the room by `since` would skip every late arrival that
        /// landed above the page boundary. Only with no `since`.
        after: Option<Digest32>,
        /// Cap on rows returned; 0 means no cap.
        limit: u64,
    },
    /// Every entry the node holds for a room, in the room's one order (ADR-023
    /// decision 1): the sequence the timeline is a subsequence of.
    Order {
        /// The room.
        channel_id: Digest32,
    },
    /// The members of a room.
    Roster {
        /// The room.
        channel_id: Digest32,
    },
    /// Who this identity consents to reading it in a room, and who consents to it: both
    /// directions of trust, off the room's log (V030-17).
    Consents {
        /// The room.
        channel_id: Digest32,
    },
    /// The rooms this node holds, in room-id order, after `after` — one page of them.
    /// [`IpcClient::rooms`] asks for every page.
    Rooms {
        /// The last room of the previous page, or `None` for the first.
        after: Option<Digest32>,
    },
    /// Offer a local TCP endpoint as a room-bound service (ADR-013). Unless `persist`, only for
    /// as long as this connection stays open: it is withdrawn when the connection closes, however
    /// the client ends, and never persisted (V210-72). A [`Request::Forward`] likewise.
    AddService {
        /// The room.
        channel_id: Digest32,
        /// The service's tag, which is also how members name it.
        service_tag: String,
        /// The local endpoint to carry connections to.
        local: String,
        /// Kept: offered until removed, across this node's restarts, as `vox service add` offers
        /// it without a daemon (V030-06). Not withdrawn when the connection closes.
        persist: bool,
    },
    /// The services this node offers in a room, answered with [`Frame::Services`] (V030-24).
    Services {
        /// The room.
        channel_id: Digest32,
    },
    /// Share a file or a folder (ADR-028 F-1, F-2): the daemon hashes it, serves it and posts
    /// `envelope` as its announcement, answered with [`Frame::Shares`] holding the one share once
    /// it is served. The daemon serves it until its message expires, it is stopped, this node
    /// leaves the room or the room ends; not for as long as this connection.
    Share {
        /// The room.
        channel_id: Digest32,
        /// The file or folder, absolute.
        path: String,
        /// The announcement as addressed (see [`crate::node::shares::ShareRequest`]).
        envelope: String,
        /// Stop after this many completed fetches; `0` for none.
        count: u64,
        /// Stop after this many seconds; `0` for none.
        for_secs: u64,
    },
    /// Stop this node's shares in a room that `selector` names, answered with [`Frame::Shares`]
    /// holding those stopped.
    ShareStop {
        /// The room.
        channel_id: Digest32,
        /// A name, a tag, or a prefix of a SHA-256 or of the announcement's entry.
        selector: String,
    },
    /// This node's shares in a room, answered with [`Frame::Shares`].
    ShareList {
        /// The room.
        channel_id: Digest32,
    },
    /// Append one entry of a Session (ADR-029 SC-1), sealed under this node's drive key so only
    /// members it trusts with drive read it (SC-2). The session's hook sends it; it never shows in
    /// the room's timeline (SC-4).
    AppendSession {
        /// The room the session works in.
        channel_id: Digest32,
        /// The harness's own session id (SE-2).
        session_id: String,
        /// The activity item, in the harnesses' shared format.
        body: String,
    },
    /// Share a file through a Session (ADR-029 DR-1.7, DR-1.8; #546), answered as
    /// [`Request::Share`] is. Out of a Session: announced as its drive-sealed `file` entry and
    /// served to members with drive. Into a Session on another node: announced to nobody (the
    /// driver's drive request says it to that node) and served to that node once.
    SessionShare {
        /// The room.
        channel_id: Digest32,
        /// The file or folder, absolute.
        path: String,
        /// A file envelope carrying the note, as [`Request::Share`]'s.
        envelope: String,
        /// Which way it goes.
        to: SessionTo,
    },
    /// The Session entries this node can read in a room (ADR-029 SC-2): its own, and those of
    /// each node that released it its drive key. Answered with [`Frame::SessionEntries`].
    SessionEntries {
        /// The room.
        channel_id: Digest32,
    },
    /// A room's Sessions (ADR-029), as its log says, answered with [`Frame::Sessions`].
    Sessions {
        /// The room.
        channel_id: Digest32,
    },
    /// This node's decision record, newest first (ADR-028 D-3), answered with
    /// [`Frame::Decisions`]: read by the node, which alone opens it (#563).
    Decisions {
        /// The most events to answer with.
        limit: u64,
    },
    /// The members offered to this node's keyring (ADR-028 K-15 – K-18), answered with
    /// [`Frame::Offers`].
    Offers,
    /// Dismiss the offer of `member` (ADR-028 K-18): on this node alone, and silently.
    DismissOffer {
        /// The member offered.
        member: Digest32,
    },
    /// Stop offering a service.
    RemoveService {
        /// The room.
        channel_id: Digest32,
        /// The service's tag.
        service_tag: String,
    },
    /// Forward a local port to a member's service over the overlay.
    ///
    /// Answers [`Frame::Bound`] with the address actually bound, because a
    /// request for port 0 is resolved by the OS and the caller cannot know it.
    Forward {
        /// The room.
        channel_id: Digest32,
        /// The member offering the service.
        host: Digest32,
        /// The service's tag.
        service_tag: String,
        /// The local address to bind; port 0 lets the OS choose.
        local: String,
    },
    /// Stop a forward previously bound at this address.
    StopForward {
        /// The address [`Frame::Bound`] reported.
        local: String,
    },
    /// Join a room from an invite link.
    ///
    /// The passphrase travels over a `0600` socket on the local machine, which is
    /// the same trust boundary the node's own unlocked identity already sits
    /// behind — anything that can speak this socket can already read the rooms.
    Join {
        /// The `vox://` address.
        link: String,
        /// The room's passphrase, which the link does not carry.
        passphrase: zeroize::Zeroizing<String>,
    },
    /// Create a room on this node.
    Create {
        /// The room's shared name, one DNS label (ADR-028 R-1, R-2).
        name: String,
        /// The room's passphrase.
        passphrase: zeroize::Zeroizing<String>,
    },
    /// Mint an invite link for a room.
    ///
    /// Answers [`Frame::Link`]. The link is rendezvous information, not a
    /// credential: it names the room and where to look, carries no passphrase, and
    /// since M17.6 joining with it grants nothing at all.
    Invite {
        /// The room.
        channel_id: Digest32,
    },
    /// Open a closed room with its passphrase (ADR-026 C-7): what the TUI, as a client of the
    /// daemon, does when a person types a room's passphrase.
    OpenRoom {
        /// The room.
        channel_id: Digest32,
        /// The room's passphrase.
        passphrase: zeroize::Zeroizing<String>,
    },
    /// Close an open room, wiping its key (ADR-026 C-7).
    CloseRoom {
        /// The room.
        channel_id: Digest32,
    },
    /// Leave a room (V210-164): the node says so in the room, and deletes it once another
    /// member has that. Answers [`Frame::Ok`] once it is deleted.
    Leave {
        /// The room.
        channel_id: Digest32,
    },
    /// Add an identity to the trust keyring. Needs the identity passphrase once more than
    /// [`KEYRING_WINDOW_SECS`](crate::node::actor::KEYRING_WINDOW_SECS) have passed since it was
    /// last entered (V210-159).
    Trust {
        /// Who to trust, as a full fingerprint.
        target: Digest32,
        /// The petname to file it under.
        petname: String,
        /// The identity passphrase, or empty for none: within the window none is needed.
        identity_passphrase: zeroize::Zeroizing<String>,
        /// Whether its consents release this node's full history (PRD-001 R12).
        full_history: bool,
        /// Whether the entry carries drive as well as read (ADR-028 K-14, K-16).
        drive: bool,
    },
    /// Change what a trusted identity's entry grants, read or read + drive (ADR-028 K-14): a
    /// keyring change, behind the passphrase gate as [`Request::Trust`] is.
    SetCapability {
        /// The trusted identity, as a full fingerprint.
        target: Digest32,
        /// Whether its entry carries drive from now on.
        drive: bool,
        /// The identity passphrase, or empty for none: within the window none is needed.
        identity_passphrase: zeroize::Zeroizing<String>,
    },
    /// Set a room's retention (ADR-023 decision 2). **Not gated on the identity passphrase**
    /// (ADR-028 K-11, ADR-010 AR-28 as amended): the passphrase is asked for only to attach a node
    /// and to change its keyring. Who may set it for every member is the room's governance.
    SetRetention {
        /// The room.
        channel_id: Digest32,
        /// Seconds a message body is kept; `0` keeps it forever.
        ttl: u64,
    },
    /// Name a room for every member (ADR-028 R-1); its creator or an admin only, as the room's
    /// governance says. **Not gated on the identity passphrase** (ADR-028 K-11): it is asked for
    /// only to attach a node and to change its keyring.
    RenameRoom {
        /// The room.
        channel_id: Digest32,
        /// The new name, one DNS label.
        name: String,
    },
    /// End a room for everyone (V030-08); its creator only.
    End {
        /// The room.
        channel_id: Digest32,
    },
    /// Make a member an admin of a room, or take it back (V030-08); its creator only.
    SetAdmin {
        /// The room.
        channel_id: Digest32,
        /// The member.
        member: Digest32,
        /// `true` to add, `false` to remove.
        admin: bool,
    },
    /// A room's admins, its creator first (V030-08): answered as [`Frame::Members`].
    Admins {
        /// The room.
        channel_id: Digest32,
    },
    /// Choose a room's idle end (V030-08); its creator only.
    IdleEnd {
        /// The room.
        channel_id: Digest32,
        /// Seconds with nothing said before it ends.
        idle_secs: u64,
    },
    /// Remove an identity from the trust keyring. Needs the passphrase as [`Request::Trust`] does.
    Untrust {
        /// Who to stop trusting.
        target: Digest32,
        /// The identity passphrase, or empty for none.
        identity_passphrase: zeroize::Zeroizing<String>,
    },
    /// Rename an identity already in the trust keyring, keeping what its consents release
    /// (the history grant, PRD-001 R12). Needs the passphrase as [`Request::Trust`] does: a
    /// keyring change (V210-159). A rename through `Trust` would reset a full-history grant to
    /// from-now-on as a side effect.
    Rename {
        /// Who to rename, as a full fingerprint.
        target: Digest32,
        /// The new petname.
        petname: String,
        /// The identity passphrase, or empty for none.
        identity_passphrase: zeroize::Zeroizing<String>,
    },
    /// Read the trust keyring: who this node trusts and the name it gave each. A read, so the
    /// node checks no passphrase.
    TrustList {
        /// Carried on the wire and not checked.
        identity_passphrase: zeroize::Zeroizing<String>,
        /// The last fingerprint of the previous page, or `None` for the first.
        after: Option<Digest32>,
    },
    /// Answered `Ok` by the node's actor, changing nothing: proof it is taking commands.
    Ping,
    /// A room's **structured posts** (V210-120): every row whose body is a JSON object with a
    /// `type` in `types`, or whose operation id is in `ops`, oldest first, answered as
    /// [`Frame::Rows`] and paged like [`Request::Read`]. The node knows no `type`'s meaning; see
    /// [`crate::node::api::StructuredIndex`]. A row matched by an id's hash alone may carry
    /// another id: the client checks.
    Structured {
        /// The room.
        channel_id: Digest32,
        /// The `type` values wanted.
        types: Vec<String>,
        /// The operation ids wanted; at most [`MAX_FIND`] with `types`.
        ops: Vec<String>,
        /// Return only matching rows **after** this one. Absent reads from the first.
        since: Option<Digest32>,
    },
    /// How many rows of a room follow `since` (all of them when absent), as [`Frame::Count`]
    /// (V210-120): what a reader that reads a page at a time says is still waiting.
    Count {
        /// The room.
        channel_id: Digest32,
        /// Count only rows **after** this one.
        since: Option<Digest32>,
    },
    /// What this node's person has not read in a room, oldest first, as [`Frame::Rows`]: the rows
    /// after the newest one this node recorded as read, by someone else (ADR-028 R-8). A client
    /// counts its unread from these when it starts, then from the node's events.
    Unread {
        /// The room.
        channel_id: Digest32,
    },
    /// The rows of a room with these entry hashes, those it holds, as [`Frame::Rows`] (V210-120).
    Find {
        /// The room.
        channel_id: Digest32,
        /// The entry hashes wanted; at most [`MAX_FIND`].
        entries: Vec<Digest32>,
    },
    /// Ask every other member of a room whether it holds this node's post `entry`, and compare
    /// the posts of `types` each holds with this node's own (V210-168), answered as
    /// [`Frame::Agreement`]. What a claim waits for before it says "you hold it".
    Agree {
        /// The room.
        channel_id: Digest32,
        /// The post.
        entry: Digest32,
        /// The `type`s compared; at most [`crate::node::agreestream::MAX_TYPES`].
        types: Vec<String>,
    },
}

/// The most entries one [`Request::Find`] may name.
pub const MAX_FIND: usize = 64;

impl Request {
    /// Canonical CBOR body (unframed).
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        match self {
            Request::Subscribe => {
                e.array(1).uint(T_SUBSCRIBE);
            }
            Request::Ping => {
                e.array(1).uint(T_PING);
            }
            Request::Structured {
                channel_id,
                types,
                ops,
                since,
            } => {
                e.array(5)
                    .uint(T_STRUCTURED)
                    .bytes(channel_id)
                    .array(types.len());
                for t in types {
                    e.text(t);
                }
                e.array(ops.len());
                for o in ops {
                    e.text(o);
                }
                e.bytes(since.as_ref().map_or(&[][..], |d| &d[..]));
            }
            Request::Count { channel_id, since } => {
                e.array(3)
                    .uint(T_COUNT_REQ)
                    .bytes(channel_id)
                    .bytes(since.as_ref().map_or(&[][..], |d| &d[..]));
            }
            Request::Unread { channel_id } => {
                e.array(2).uint(T_UNREAD_REQ).bytes(channel_id);
            }
            Request::Find {
                channel_id,
                entries,
            } => {
                e.array(3)
                    .uint(T_FIND)
                    .bytes(channel_id)
                    .array(entries.len());
                for h in entries {
                    e.bytes(h);
                }
            }
            Request::Post {
                channel_id,
                text,
                card,
            } => {
                e.array(4)
                    .uint(T_POST)
                    .bytes(channel_id)
                    .text(text)
                    .uint(u64::from(*card));
            }
            Request::MarkRead {
                channel_id,
                entries,
            } => {
                e.array(3)
                    .uint(T_MARK_READ)
                    .bytes(channel_id)
                    .array(entries.len());
                for h in entries {
                    e.bytes(h);
                }
            }
            Request::Agree {
                channel_id,
                entry,
                types,
            } => {
                e.array(4)
                    .uint(T_AGREE)
                    .bytes(channel_id)
                    .bytes(entry)
                    .array(types.len());
                for t in types {
                    e.text(t);
                }
            }
            Request::Read {
                channel_id,
                since,
                after,
                limit,
            } => {
                e.array(5)
                    .uint(T_READ)
                    .bytes(channel_id)
                    // An absent cursor is the empty byte string, so the arity is
                    // fixed — ADR-008's canonical encoding has no optionals.
                    .bytes(since.as_ref().map_or(&[][..], |d| &d[..]))
                    .bytes(after.as_ref().map_or(&[][..], |d| &d[..]))
                    .uint(*limit);
            }
            Request::Roster { channel_id } => {
                e.array(2).uint(T_ROSTER).bytes(channel_id);
            }
            Request::Consents { channel_id } => {
                e.array(2).uint(T_CONSENTS_REQ).bytes(channel_id);
            }
            Request::Order { channel_id } => {
                e.array(2).uint(T_ORDER).bytes(channel_id);
            }
            Request::Services { channel_id } => {
                e.array(2).uint(T_SERVICES_REQ).bytes(channel_id);
            }
            Request::Share {
                channel_id,
                path,
                envelope,
                count,
                for_secs,
            } => {
                e.array(6)
                    .uint(T_SHARE)
                    .bytes(channel_id)
                    .text(path)
                    .text(envelope)
                    .uint(*count)
                    .uint(*for_secs);
            }
            Request::ShareStop {
                channel_id,
                selector,
            } => {
                e.array(3)
                    .uint(T_SHARE_STOP)
                    .bytes(channel_id)
                    .text(selector);
            }
            Request::Sessions { channel_id } => {
                e.array(2).uint(T_SESSIONS_REQ).bytes(channel_id);
            }
            Request::Decisions { limit } => {
                e.array(2).uint(T_DECISIONS_REQ).uint(*limit);
            }
            Request::Offers => {
                e.array(1).uint(T_OFFERS_REQ);
            }
            Request::DismissOffer { member } => {
                e.array(2).uint(T_DISMISS_OFFER).bytes(member);
            }
            Request::ShareList { channel_id } => {
                e.array(2).uint(T_SHARE_LIST).bytes(channel_id);
            }
            Request::AppendSession {
                channel_id,
                session_id,
                body,
            } => {
                e.array(4)
                    .uint(T_SESSION_APPEND)
                    .bytes(channel_id)
                    .text(session_id)
                    .text(body);
            }
            Request::SessionEntries { channel_id } => {
                e.array(2).uint(T_SESSION_ENTRIES).bytes(channel_id);
            }
            Request::SessionShare {
                channel_id,
                path,
                envelope,
                to,
            } => {
                e.array(5)
                    .uint(T_SESSION_SHARE)
                    .bytes(channel_id)
                    .text(path)
                    .text(envelope)
                    .array(2);
                match to {
                    SessionTo::Session(id) => e.uint(0).text(id),
                    SessionTo::Node(n) => e.uint(1).bytes(n),
                };
            }
            Request::Rooms { after } => {
                e.array(2)
                    .uint(T_ROOMS_REQ)
                    .bytes(after.as_ref().map_or(&[][..], |d| &d[..]));
            }
            Request::AddService {
                channel_id,
                service_tag,
                local,
                persist,
            } => {
                e.array(5)
                    .uint(T_ADD_SERVICE)
                    .bytes(channel_id)
                    .text(service_tag)
                    .text(local)
                    .uint(u64::from(*persist));
            }
            Request::RemoveService {
                channel_id,
                service_tag,
            } => {
                e.array(3)
                    .uint(T_REMOVE_SERVICE)
                    .bytes(channel_id)
                    .text(service_tag);
            }
            Request::Forward {
                channel_id,
                host,
                service_tag,
                local,
            } => {
                e.array(5)
                    .uint(T_FORWARD)
                    .bytes(channel_id)
                    .bytes(host)
                    .text(service_tag)
                    .text(local);
            }
            Request::StopForward { local } => {
                e.array(2).uint(T_STOP_FORWARD).text(local);
            }
            Request::Join { link, passphrase } => {
                e.array(3).uint(T_JOIN).text(link).text(passphrase);
            }
            Request::Create { name, passphrase } => {
                e.array(3).uint(T_CREATE).text(name).text(passphrase);
            }
            Request::RenameRoom { channel_id, name } => {
                e.array(3).uint(T_RENAME_ROOM).bytes(channel_id).text(name);
            }
            Request::Invite { channel_id } => {
                e.array(2).uint(T_INVITE).bytes(channel_id);
            }
            Request::OpenRoom {
                channel_id,
                passphrase,
            } => {
                e.array(3)
                    .uint(T_OPEN_ROOM)
                    .bytes(channel_id)
                    .text(passphrase);
            }
            Request::CloseRoom { channel_id } => {
                e.array(2).uint(T_CLOSE_ROOM).bytes(channel_id);
            }
            Request::Leave { channel_id } => {
                e.array(2).uint(T_LEAVE).bytes(channel_id);
            }
            Request::SetAdmin {
                channel_id,
                member,
                admin,
            } => {
                e.array(4)
                    .uint(T_SET_ADMIN)
                    .bytes(channel_id)
                    .bytes(member)
                    .uint(u64::from(*admin));
            }
            Request::Admins { channel_id } => {
                e.array(2).uint(T_ADMINS).bytes(channel_id);
            }
            Request::End { channel_id } => {
                e.array(2).uint(T_END).bytes(channel_id);
            }
            Request::IdleEnd {
                channel_id,
                idle_secs,
            } => {
                e.array(3)
                    .uint(T_IDLE_END)
                    .bytes(channel_id)
                    .uint(*idle_secs);
            }
            Request::Trust {
                target,
                petname,
                identity_passphrase,
                full_history,
                drive,
            } => {
                e.array(6)
                    .uint(T_TRUST)
                    .bytes(target)
                    .text(petname)
                    .text(identity_passphrase)
                    .uint(u64::from(*full_history))
                    .uint(u64::from(*drive));
            }
            Request::SetCapability {
                target,
                drive,
                identity_passphrase,
            } => {
                e.array(4)
                    .uint(T_SET_CAPABILITY)
                    .bytes(target)
                    .uint(u64::from(*drive))
                    .text(identity_passphrase);
            }
            Request::Rename {
                target,
                petname,
                identity_passphrase,
            } => {
                e.array(4)
                    .uint(T_RENAME)
                    .bytes(target)
                    .text(petname)
                    .text(identity_passphrase);
            }
            Request::SetRetention { channel_id, ttl } => {
                e.array(3).uint(T_RETENTION).bytes(channel_id).uint(*ttl);
            }
            Request::Untrust {
                target,
                identity_passphrase,
            } => {
                e.array(3)
                    .uint(T_UNTRUST)
                    .bytes(target)
                    .text(identity_passphrase);
            }
            Request::TrustList {
                identity_passphrase,
                after,
            } => {
                e.array(3)
                    .uint(T_TRUST_LIST)
                    .text(identity_passphrase)
                    .bytes(after.as_ref().map_or(&[][..], |d| &d[..]));
            }
        }
        e.finish()
    }

    /// Parse one request body.
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(b);
        let n = d.array().map_err(|_| Error::MalformedIpc("ipc request"))?;
        let tag = d
            .uint()
            .map_err(|_| Error::MalformedIpc("ipc request tag"))?;
        match (tag, n) {
            (T_SUBSCRIBE, 1) => {
                d.finish()
                    .map_err(|_| Error::MalformedIpc("ipc request trailing"))?;
                Ok(Request::Subscribe)
            }
            (T_PING, 1) => {
                d.finish()
                    .map_err(|_| Error::MalformedIpc("ipc request trailing"))?;
                Ok(Request::Ping)
            }
            (T_POST, 4) => {
                let channel_id = digest(&mut d)?;
                let text = d
                    .text()
                    .map_err(|_| Error::MalformedIpc("ipc post text"))?
                    .to_owned();
                let card = d.uint().map_err(|_| Error::MalformedIpc("ipc post card"))? != 0;
                d.finish()
                    .map_err(|_| Error::MalformedIpc("ipc request trailing"))?;
                Ok(Request::Post {
                    channel_id,
                    text,
                    card,
                })
            }
            (T_READ, 5) => {
                let channel_id = digest(&mut d)?;
                let mut hash = |what: &'static str| -> Result<Option<Digest32>> {
                    let b = d.bytes().map_err(|_| Error::MalformedIpc(what))?;
                    if b.is_empty() {
                        return Ok(None);
                    }
                    Digest32::try_from(b)
                        .map(Some)
                        .map_err(|_| Error::MalformedIpc(what))
                };
                let since = hash("ipc cursor")?;
                let after = hash("ipc page mark")?;
                let limit = d.uint().map_err(|_| Error::MalformedIpc("ipc limit"))?;
                d.finish()
                    .map_err(|_| Error::MalformedIpc("ipc request trailing"))?;
                Ok(Request::Read {
                    channel_id,
                    since,
                    after,
                    limit,
                })
            }
            (T_ROSTER, 2) => {
                let channel_id = digest(&mut d)?;
                d.finish()
                    .map_err(|_| Error::MalformedIpc("ipc request trailing"))?;
                Ok(Request::Roster { channel_id })
            }
            (T_CONSENTS_REQ, 2) => {
                let channel_id = digest(&mut d)?;
                d.finish()
                    .map_err(|_| Error::MalformedIpc("ipc request trailing"))?;
                Ok(Request::Consents { channel_id })
            }
            (T_ORDER, 2) => {
                let channel_id = digest(&mut d)?;
                d.finish()
                    .map_err(|_| Error::MalformedIpc("ipc request trailing"))?;
                Ok(Request::Order { channel_id })
            }
            (T_SERVICES_REQ, 2) => {
                let channel_id = digest(&mut d)?;
                d.finish()
                    .map_err(|_| Error::MalformedIpc("ipc request trailing"))?;
                Ok(Request::Services { channel_id })
            }
            // The unpaged form (no `after`), as any release before #189 sends it: read as the first
            // page. Refused, a worker on an older release died at its first room lookup with
            // "ipc request unknown tag" and never reached the version check that exists to refuse it
            // by name (ADR-021 M21.1, work_version_proof).
            (T_ROOMS_REQ, 1) => {
                d.finish()
                    .map_err(|_| Error::MalformedIpc("ipc request trailing"))?;
                Ok(Request::Rooms { after: None })
            }
            (T_ROOMS_REQ, 2) => {
                let after = optional_digest(&mut d)?;
                d.finish()
                    .map_err(|_| Error::MalformedIpc("ipc request trailing"))?;
                Ok(Request::Rooms { after })
            }
            (T_STRUCTURED, 5) => {
                let channel_id = digest(&mut d)?;
                let n = d.array().map_err(|_| Error::MalformedIpc("ipc types"))?;
                if n > MAX_FIND {
                    return Err(Error::MalformedIpc("ipc too many types"));
                }
                let mut types = Vec::with_capacity(n);
                for _ in 0..n {
                    types.push(text(&mut d, "ipc type")?);
                }
                let m = d.array().map_err(|_| Error::MalformedIpc("ipc ops"))?;
                if n + m > MAX_FIND {
                    return Err(Error::MalformedIpc("ipc too many operation ids"));
                }
                let mut ops = Vec::with_capacity(m);
                for _ in 0..m {
                    ops.push(text(&mut d, "ipc op")?);
                }
                let since = optional_digest(&mut d)?;
                d.finish()
                    .map_err(|_| Error::MalformedIpc("ipc request trailing"))?;
                Ok(Request::Structured {
                    channel_id,
                    types,
                    ops,
                    since,
                })
            }
            (T_COUNT_REQ, 3) => {
                let channel_id = digest(&mut d)?;
                let since = optional_digest(&mut d)?;
                d.finish()
                    .map_err(|_| Error::MalformedIpc("ipc request trailing"))?;
                Ok(Request::Count { channel_id, since })
            }
            (T_UNREAD_REQ, 2) => {
                let channel_id = digest(&mut d)?;
                d.finish()
                    .map_err(|_| Error::MalformedIpc("ipc request trailing"))?;
                Ok(Request::Unread { channel_id })
            }
            (T_AGREE, 4) => {
                let channel_id = digest(&mut d)?;
                let entry = digest(&mut d)?;
                let n = d.array().map_err(|_| Error::MalformedIpc("ipc types"))?;
                if n > crate::node::agreestream::MAX_TYPES {
                    return Err(Error::MalformedIpc("ipc too many types"));
                }
                let mut types = Vec::with_capacity(n);
                for _ in 0..n {
                    types.push(text(&mut d, "ipc type")?);
                }
                d.finish()
                    .map_err(|_| Error::MalformedIpc("ipc request trailing"))?;
                Ok(Request::Agree {
                    channel_id,
                    entry,
                    types,
                })
            }
            (T_MARK_READ, 3) => {
                let channel_id = digest(&mut d)?;
                let n = d.array().map_err(|_| Error::MalformedIpc("ipc entries"))?;
                if n > crate::node::content::MAX_READ_HASHES {
                    return Err(Error::MalformedIpc("ipc too many entries"));
                }
                let mut entries = Vec::with_capacity(n);
                for _ in 0..n {
                    entries.push(digest(&mut d)?);
                }
                d.finish()
                    .map_err(|_| Error::MalformedIpc("ipc request trailing"))?;
                Ok(Request::MarkRead {
                    channel_id,
                    entries,
                })
            }
            (T_FIND, 3) => {
                let channel_id = digest(&mut d)?;
                let n = d.array().map_err(|_| Error::MalformedIpc("ipc entries"))?;
                if n > MAX_FIND {
                    return Err(Error::MalformedIpc("ipc too many entries"));
                }
                let mut entries = Vec::with_capacity(n);
                for _ in 0..n {
                    entries.push(digest(&mut d)?);
                }
                d.finish()
                    .map_err(|_| Error::MalformedIpc("ipc request trailing"))?;
                Ok(Request::Find {
                    channel_id,
                    entries,
                })
            }
            (T_TRUST, 6) => {
                let target = digest(&mut d)?;
                let petname = text(&mut d, "ipc petname")?;
                let identity_passphrase = secret_text(&mut d, "ipc identity passphrase")?;
                let full_history = flag(&mut d, "ipc history")?;
                let drive = flag(&mut d, "ipc drive")?;
                d.finish()
                    .map_err(|_| Error::MalformedIpc("ipc request trailing"))?;
                Ok(Request::Trust {
                    target,
                    petname,
                    identity_passphrase,
                    full_history,
                    drive,
                })
            }
            (T_SET_CAPABILITY, 4) => {
                let target = digest(&mut d)?;
                let drive = flag(&mut d, "ipc drive")?;
                let identity_passphrase = secret_text(&mut d, "ipc identity passphrase")?;
                d.finish()
                    .map_err(|_| Error::MalformedIpc("ipc request trailing"))?;
                Ok(Request::SetCapability {
                    target,
                    drive,
                    identity_passphrase,
                })
            }
            (T_RENAME, 4) => {
                let target = digest(&mut d)?;
                let petname = text(&mut d, "ipc petname")?;
                let identity_passphrase = secret_text(&mut d, "ipc identity passphrase")?;
                d.finish()
                    .map_err(|_| Error::MalformedBundle("ipc request trailing"))?;
                Ok(Request::Rename {
                    target,
                    petname,
                    identity_passphrase,
                })
            }
            (T_RENAME_ROOM, 3) => {
                let channel_id = digest(&mut d)?;
                let name = text(&mut d, "ipc room name")?;
                d.finish()
                    .map_err(|_| Error::MalformedBundle("ipc request trailing"))?;
                Ok(Request::RenameRoom { channel_id, name })
            }
            (T_RETENTION, 3) => {
                let channel_id = digest(&mut d)?;
                let ttl = d.uint().map_err(|_| Error::MalformedBundle("ipc ttl"))?;
                d.finish()
                    .map_err(|_| Error::MalformedBundle("ipc request trailing"))?;
                Ok(Request::SetRetention { channel_id, ttl })
            }
            (T_UNTRUST, 3) => {
                let target = digest(&mut d)?;
                let identity_passphrase = secret_text(&mut d, "ipc identity passphrase")?;
                d.finish()
                    .map_err(|_| Error::MalformedIpc("ipc request trailing"))?;
                Ok(Request::Untrust {
                    target,
                    identity_passphrase,
                })
            }
            // The unpaged form, as for `Rooms` above.
            (T_TRUST_LIST, 2) => {
                let identity_passphrase = secret_text(&mut d, "ipc identity passphrase")?;
                d.finish()
                    .map_err(|_| Error::MalformedIpc("ipc request trailing"))?;
                Ok(Request::TrustList {
                    identity_passphrase,
                    after: None,
                })
            }
            (T_TRUST_LIST, 3) => {
                let identity_passphrase = secret_text(&mut d, "ipc identity passphrase")?;
                let after = optional_digest(&mut d)?;
                d.finish()
                    .map_err(|_| Error::MalformedIpc("ipc request trailing"))?;
                Ok(Request::TrustList {
                    identity_passphrase,
                    after,
                })
            }
            (T_SHARE, 6) => {
                let channel_id = digest(&mut d)?;
                let path = text(&mut d, "ipc share path")?;
                let envelope = text(&mut d, "ipc share envelope")?;
                let count = d
                    .uint()
                    .map_err(|_| Error::MalformedIpc("ipc share count"))?;
                let for_secs = d.uint().map_err(|_| Error::MalformedIpc("ipc share for"))?;
                d.finish()
                    .map_err(|_| Error::MalformedIpc("ipc request trailing"))?;
                Ok(Request::Share {
                    channel_id,
                    path,
                    envelope,
                    count,
                    for_secs,
                })
            }
            (T_SHARE_STOP, 3) => {
                let channel_id = digest(&mut d)?;
                let selector = text(&mut d, "ipc share selector")?;
                d.finish()
                    .map_err(|_| Error::MalformedIpc("ipc request trailing"))?;
                Ok(Request::ShareStop {
                    channel_id,
                    selector,
                })
            }
            (T_SHARE_LIST, 2) => {
                let channel_id = digest(&mut d)?;
                d.finish()
                    .map_err(|_| Error::MalformedIpc("ipc request trailing"))?;
                Ok(Request::ShareList { channel_id })
            }
            (T_SESSION_APPEND, 4) => {
                let channel_id = digest(&mut d)?;
                let session_id = text(&mut d, "ipc session id")?;
                let body = text(&mut d, "ipc session entry")?;
                d.finish()
                    .map_err(|_| Error::MalformedIpc("ipc request trailing"))?;
                Ok(Request::AppendSession {
                    channel_id,
                    session_id,
                    body,
                })
            }
            (T_SESSION_SHARE, 5) => {
                let channel_id = digest(&mut d)?;
                let path = text(&mut d, "ipc share path")?;
                let envelope = text(&mut d, "ipc share envelope")?;
                if d.array()
                    .map_err(|_| Error::MalformedIpc("ipc session share to"))?
                    != 2
                {
                    return Err(Error::MalformedIpc("ipc session share to arity"));
                }
                let to = match d
                    .uint()
                    .map_err(|_| Error::MalformedIpc("ipc session share way"))?
                {
                    0 => SessionTo::Session(text(&mut d, "ipc session id")?),
                    1 => SessionTo::Node(digest(&mut d)?),
                    _ => return Err(Error::MalformedIpc("ipc session share way")),
                };
                d.finish()
                    .map_err(|_| Error::MalformedIpc("ipc request trailing"))?;
                Ok(Request::SessionShare {
                    channel_id,
                    path,
                    envelope,
                    to,
                })
            }
            (T_SESSION_ENTRIES, 2) => {
                let channel_id = digest(&mut d)?;
                d.finish()
                    .map_err(|_| Error::MalformedIpc("ipc request trailing"))?;
                Ok(Request::SessionEntries { channel_id })
            }
            (T_SESSIONS_REQ, 2) => {
                let channel_id = digest(&mut d)?;
                d.finish()
                    .map_err(|_| Error::MalformedIpc("ipc request trailing"))?;
                Ok(Request::Sessions { channel_id })
            }
            (T_DECISIONS_REQ, 2) => {
                let limit = d
                    .uint()
                    .map_err(|_| Error::MalformedIpc("ipc decisions limit"))?;
                d.finish()
                    .map_err(|_| Error::MalformedIpc("ipc request trailing"))?;
                Ok(Request::Decisions { limit })
            }
            (T_OFFERS_REQ, 1) => {
                d.finish()
                    .map_err(|_| Error::MalformedIpc("ipc request trailing"))?;
                Ok(Request::Offers)
            }
            (T_DISMISS_OFFER, 2) => {
                let member = digest(&mut d)?;
                d.finish()
                    .map_err(|_| Error::MalformedIpc("ipc request trailing"))?;
                Ok(Request::DismissOffer { member })
            }
            (T_ADD_SERVICE, 5) => {
                let channel_id = digest(&mut d)?;
                let service_tag = text(&mut d, "ipc service tag")?;
                let local = text(&mut d, "ipc local address")?;
                let persist = flag(&mut d, "ipc service persist")?;
                d.finish()
                    .map_err(|_| Error::MalformedIpc("ipc request trailing"))?;
                Ok(Request::AddService {
                    channel_id,
                    service_tag,
                    local,
                    persist,
                })
            }
            (T_REMOVE_SERVICE, 3) => {
                let channel_id = digest(&mut d)?;
                let service_tag = text(&mut d, "ipc service tag")?;
                d.finish()
                    .map_err(|_| Error::MalformedIpc("ipc request trailing"))?;
                Ok(Request::RemoveService {
                    channel_id,
                    service_tag,
                })
            }
            (T_FORWARD, 5) => {
                let channel_id = digest(&mut d)?;
                let host = digest(&mut d)?;
                let service_tag = text(&mut d, "ipc service tag")?;
                let local = text(&mut d, "ipc local address")?;
                d.finish()
                    .map_err(|_| Error::MalformedIpc("ipc request trailing"))?;
                Ok(Request::Forward {
                    channel_id,
                    host,
                    service_tag,
                    local,
                })
            }
            (T_STOP_FORWARD, 2) => {
                let local = text(&mut d, "ipc local address")?;
                d.finish()
                    .map_err(|_| Error::MalformedIpc("ipc request trailing"))?;
                Ok(Request::StopForward { local })
            }
            (T_JOIN, 3) => {
                let link = text(&mut d, "ipc join link")?;
                let passphrase = secret_text(&mut d, "ipc join passphrase")?;
                d.finish()
                    .map_err(|_| Error::MalformedIpc("ipc request trailing"))?;
                Ok(Request::Join { link, passphrase })
            }
            (T_CREATE, 3) => {
                let name = text(&mut d, "ipc create name")?;
                let passphrase = secret_text(&mut d, "ipc create passphrase")?;
                d.finish()
                    .map_err(|_| Error::MalformedIpc("ipc request trailing"))?;
                Ok(Request::Create { name, passphrase })
            }
            (T_INVITE, 2) => {
                let channel_id = digest(&mut d)?;
                d.finish()
                    .map_err(|_| Error::MalformedIpc("ipc request trailing"))?;
                Ok(Request::Invite { channel_id })
            }
            (T_OPEN_ROOM, 3) => {
                let channel_id = digest(&mut d)?;
                let passphrase = secret_text(&mut d, "ipc open room passphrase")?;
                d.finish()
                    .map_err(|_| Error::MalformedIpc("ipc request trailing"))?;
                Ok(Request::OpenRoom {
                    channel_id,
                    passphrase,
                })
            }
            (T_CLOSE_ROOM, 2) => {
                let channel_id = digest(&mut d)?;
                d.finish()
                    .map_err(|_| Error::MalformedIpc("ipc request trailing"))?;
                Ok(Request::CloseRoom { channel_id })
            }
            (T_LEAVE | T_END, 2) => {
                let channel_id = digest(&mut d)?;
                d.finish()
                    .map_err(|_| Error::MalformedIpc("ipc request trailing"))?;
                Ok(if tag == T_LEAVE {
                    Request::Leave { channel_id }
                } else {
                    Request::End { channel_id }
                })
            }
            (T_SET_ADMIN, 4) => {
                let channel_id = digest(&mut d)?;
                let member = digest(&mut d)?;
                let admin = d.uint().map_err(|_| Error::MalformedIpc("ipc admin"))? != 0;
                d.finish()
                    .map_err(|_| Error::MalformedIpc("ipc request trailing"))?;
                Ok(Request::SetAdmin {
                    channel_id,
                    member,
                    admin,
                })
            }
            (T_ADMINS, 2) => {
                let channel_id = digest(&mut d)?;
                d.finish()
                    .map_err(|_| Error::MalformedIpc("ipc request trailing"))?;
                Ok(Request::Admins { channel_id })
            }
            (T_IDLE_END, 3) => {
                let channel_id = digest(&mut d)?;
                let idle_secs = d.uint().map_err(|_| Error::MalformedIpc("ipc idle end"))?;
                d.finish()
                    .map_err(|_| Error::MalformedIpc("ipc request trailing"))?;
                Ok(Request::IdleEnd {
                    channel_id,
                    idle_secs,
                })
            }
            _ => Err(Error::UnknownIpcRequest),
        }
    }
}

/// A service a member shares in a room, as [`Frame::Services`] carries it (V030-25).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharedService {
    /// Its readable address, in this node's own aliases for the node and the room where it has
    /// them (ADR-028 S-1a): for showing only.
    pub address: String,
    /// Its canonical address, every part an identifier (ADR-028 S-1): what is copied or sent.
    pub canonical: String,
    /// Who shares it: this node's name for them, or `you`.
    pub by: String,
    /// Whether it carries datagrams.
    pub udp: bool,
    /// What its sharer's node detected it to be (ADR-028 S-2).
    pub kind: String,
    /// Whether the sharer trusts this node, as the room's log says (it consents to this node
    /// reading it): reach is the sharer's decision (ADR-017 decision 3).
    pub trusts_you: bool,
    /// Whether this node holds a live connection to the sharer now.
    pub online: bool,
}

/// What the node sends.
///
/// Not `#[non_exhaustive]`, for the same reason as
/// [`EventStreamItem`]: a catch-all arm is
/// how a `Lagged` report comes to be silently swallowed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    /// Sent once on connect, before anything else.
    Hello {
        /// The [`PROTOCOL_VERSION`] this node speaks.
        protocol: u64,
        /// **Who this client is**: the node's own identity fingerprint, or `None`
        /// if no identity exists yet.
        ///
        /// Added in protocol 2 for the work board (ADR-020 §5). Without it a
        /// client cannot answer "did my claim win?" — `resolve` returns an owner
        /// fingerprint and the client had no way to tell whether that was itself.
        /// A claim that cannot report whether it was won is useless for splitting
        /// work, which is the whole point of claims.
        me: Option<Digest32>,
    },
    /// This client fell behind and `missed` events were dropped **for it alone**.
    ///
    /// Not an error: an event is a wake, not the delivery mechanism. The client
    /// re-reads the ADR-008 log from its cursor (ADR-020 §7).
    Lagged {
        /// How many events were dropped for this client alone.
        missed: u64,
    },
    /// A node event.
    Event(NodeEvent),
    /// The node this connection acts as detached while a request was in flight, or before it was
    /// made (ADR-026 L-3). Distinct from [`Frame::Error`]: it says the request was not done
    /// because the node is gone, and a client MUST NOT attach the node again to retry it.
    NodeDetached {
        /// The node.
        node: crate::node::daemonipc::NodeName,
    },
    /// A request succeeded and carries nothing further.
    Ok,
    /// A request failed. The reason is for a person to read, not to branch on.
    Error {
        /// Why it failed.
        reason: String,
    },
    /// Where every other member stands on a post, answering [`Request::Agree`] (V210-168).
    Agreement {
        /// The report.
        report: crate::node::agreestream::Report,
    },
    /// How many rows a [`Request::Count`] found, and the room's newest row.
    Count {
        /// The count.
        n: u64,
        /// The entry hash of the room's newest row, if it has any.
        last: Option<Digest32>,
    },
    /// The rows a [`Request::Read`] asked for, oldest first.
    Rows {
        /// The rendered entries.
        rows: Vec<MessageRow>,
    },
    /// The order a [`Request::Order`] asked for.
    Order {
        /// `(entry hash, clock in ms)`, first to last.
        entries: Vec<(Digest32, u64)>,
    },
    /// The members a [`Request::Roster`] asked for.
    Members {
        /// Member fingerprints, in the order the node holds them.
        members: Vec<Digest32>,
    },
    /// The answer to a [`Request::SetRetention`] from a member who is not the room's creator or
    /// an admin (V030-32): it set **its own node's** retention for the room, `own` seconds, while
    /// the room keeps `room` (`0` = forever). Its own frame, so the CLI says plainly that nothing
    /// changed for anyone else.
    OwnRetention {
        /// This node's retention for the room now, seconds.
        own: u64,
        /// The room's retention, seconds.
        room: u64,
    },
    /// What a [`Request::Consents`] asked for, each in fingerprint order.
    Consents {
        /// The members this identity consents to reading it.
        outbound: Vec<Digest32>,
        /// The members that consent to this identity reading them.
        inbound: Vec<Digest32>,
    },
    /// The address a [`Request::Forward`] actually bound.
    ///
    /// Its own frame rather than a reused `Ok`, because a forward asked for port
    /// 0 is resolved by the OS and the caller has no other way to learn it.
    Bound {
        /// The bound local address.
        local: String,
    },
    /// The invite link a [`Request::Invite`] asked for.
    Link {
        /// The `vox://` address.
        url: String,
        /// What it carries ([`NodeEvent::AddressNote`]); empty when none was said. Additive: a
        /// two-element frame decodes with none.
        note: String,
    },
    /// The trust keyring a [`Request::TrustList`] asked for.
    Trusted {
        /// `(fingerprint, petname, capability)` in fingerprint order (ADR-028 K-14).
        entries: Vec<(Digest32, String, crate::node::trust::Capability)>,
    },
    /// The rooms a [`Request::Rooms`] asked for.
    Rooms {
        /// `(channel_id, local name, open, over)` per room; `over` says, in plain words, that
        /// this identity left the room or it ended (V030-08), and is empty while it goes on.
        rooms: Vec<(Digest32, String, bool, String)>,
    },
    /// The services a [`Request::Services`] asked for: the room's local name, and
    /// `(service tag, local address)` per service, as the node offers them.
    Services {
        /// The room's local name.
        room: String,
        /// `(service tag, local address)`, in the node's order.
        services: Vec<(String, String)>,
        /// What every member shares in the room (V030-25), with both forms of each address.
        shared: Vec<SharedService>,
    },
    /// File shares, as a [`Request::Share`], [`Request::ShareStop`] or [`Request::ShareList`]
    /// asked for.
    Shares {
        /// Each share.
        shares: Vec<crate::node::shares::ShareRow>,
    },
    /// The Session entry a [`Request::AppendSession`] appended.
    Appended {
        /// Its entry hash.
        entry: Digest32,
    },
    /// Session entries, as a [`Request::SessionEntries`] asked for, in the order this node
    /// opened or wrote them.
    SessionEntries {
        /// Each entry.
        rows: Vec<crate::node::drive::SessionRow>,
    },
    /// A room's Sessions, oldest opening first, as a [`Request::Sessions`] asked for.
    Sessions {
        /// Each Session.
        sessions: Vec<crate::node::sessions::SessionRow>,
    },
    /// The decision record's newest events, as a [`Request::Decisions`] asked for.
    Decisions {
        /// Each event, newest first.
        events: Vec<crate::node::decisions::Event>,
    },
    /// The members offered to the keyring, as a [`Request::Offers`] asked for.
    Offers {
        /// Each offer, in fingerprint order.
        offers: Vec<crate::node::api::Offer>,
    },
}

impl Frame {
    /// Canonical CBOR body (unframed).
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        match self {
            Frame::Hello { protocol, me } => {
                // An absent identity is the empty byte string, so the arity stays
                // fixed — ADR-008's canonical encoding has no optionals.
                e.array(3)
                    .uint(T_HELLO)
                    .uint(*protocol)
                    .bytes(me.as_ref().map_or(&[][..], |d| &d[..]));
            }
            Frame::Lagged { missed } => {
                e.array(2).uint(T_LAGGED).uint(*missed);
            }
            Frame::Event(ev) => encode_event(&mut e, ev),
            Frame::NodeDetached { node } => {
                e.array(2)
                    .uint(crate::node::daemonipc::T_NODE_DETACHED)
                    .text(node.as_str());
            }
            Frame::Ok => {
                e.array(1).uint(T_OK);
            }
            Frame::Error { reason } => {
                e.array(2).uint(T_ERROR).text(reason);
            }
            Frame::Agreement { report } => {
                e.array(2).uint(T_AGREEMENT);
                crate::node::agreestream::encode_report(&mut e, report);
            }
            Frame::Count { n, last } => {
                e.array(3)
                    .uint(T_COUNT)
                    .uint(*n)
                    .bytes(last.as_ref().map_or(&[][..], |d| &d[..]));
            }
            Frame::Rows { rows } => {
                e.array(2).uint(T_ROWS).array(rows.len());
                for r in rows {
                    e.array(7)
                        .bytes(&r.entry_hash)
                        .bytes(&r.author)
                        .uint(r.created_millis)
                        .text(&r.text)
                        .uint(r.arrival)
                        .uint(u64::from(r.late))
                        .uint(u64::from(r.owed));
                }
            }
            Frame::Order { entries } => {
                e.array(2).uint(T_ORDER_ROWS).array(entries.len());
                for (h, clock) in entries {
                    e.array(2).bytes(h).uint(*clock);
                }
            }
            Frame::Members { members } => {
                e.array(2).uint(T_MEMBERS).array(members.len());
                for m in members {
                    e.bytes(m);
                }
            }
            Frame::Consents { outbound, inbound } => {
                e.array(3).uint(T_CONSENTS).array(outbound.len());
                for m in outbound {
                    e.bytes(m);
                }
                e.array(inbound.len());
                for m in inbound {
                    e.bytes(m);
                }
            }
            Frame::Bound { local } => {
                e.array(2).uint(T_BOUND).text(local);
            }
            Frame::OwnRetention { own, room } => {
                e.array(3).uint(T_OWN_RETENTION).uint(*own).uint(*room);
            }
            Frame::Link { url, note } if note.is_empty() => {
                e.array(2).uint(T_LINK).text(url);
            }
            Frame::Link { url, note } => {
                e.array(3).uint(T_LINK).text(url).text(note);
            }
            Frame::Rooms { rooms } => {
                e.array(2).uint(T_ROOMS).array(rooms.len());
                for (id, name, open, over) in rooms {
                    // `over` only when there is one: additive, so an older client still decodes.
                    if over.is_empty() {
                        e.array(3).bytes(id).text(name).uint(u64::from(*open));
                    } else {
                        e.array(4)
                            .bytes(id)
                            .text(name)
                            .uint(u64::from(*open))
                            .text(over);
                    }
                }
            }
            Frame::Trusted { entries } => {
                e.array(2).uint(T_TRUSTED).array(entries.len());
                for (id, petname, capability) in entries {
                    e.array(3)
                        .bytes(id)
                        .text(petname)
                        .uint(u64::from(capability.drive()));
                }
            }
            Frame::Services {
                room,
                services,
                shared,
            } => {
                e.array(4).uint(T_SERVICES).text(room).array(services.len());
                for (tag, local) in services {
                    e.array(2).text(tag).text(local);
                }
                e.array(shared.len());
                for s in shared {
                    e.array(7)
                        .text(&s.address)
                        .text(&s.canonical)
                        .text(&s.by)
                        .uint(u64::from(s.udp))
                        .text(&s.kind)
                        .uint(u64::from(s.trusts_you))
                        .uint(u64::from(s.online));
                }
            }
            Frame::Shares { shares } => {
                e.array(2).uint(T_SHARES).array(shares.len());
                for r in shares {
                    e.array(7)
                        .text(&r.tag)
                        .text(&r.name)
                        .uint(r.size)
                        .text(&r.sha256)
                        .text(&r.entry)
                        .uint(r.fetched)
                        .uint(r.files);
                }
            }
            Frame::Appended { entry } => {
                e.array(2).uint(T_APPENDED).bytes(entry);
            }
            Frame::SessionEntries { rows } => {
                e.array(2).uint(T_SESSION_ROWS).array(rows.len());
                for r in rows {
                    e.array(5)
                        .bytes(&r.entry_hash)
                        .bytes(&r.author)
                        .uint(r.created_millis)
                        .text(&r.session_id)
                        .text(&r.body);
                }
            }
            Frame::Sessions { sessions } => {
                e.array(2).uint(T_SESSIONS);
                crate::node::sessions::put_rows(&mut e, sessions);
            }
            Frame::Decisions { events } => {
                e.array(2).uint(T_DECISIONS).array(events.len());
                for ev in events {
                    e.array(7).uint(ev.at_ms).text(&ev.asked).text(&ev.by);
                    match &ev.alias {
                        Some(a) => {
                            e.array(1).text(a);
                        }
                        None => {
                            e.array(0);
                        }
                    }
                    e.text(&ev.decided).text(&ev.why);
                    match &ev.room {
                        Some(r) => {
                            e.array(1).text(r);
                        }
                        None => {
                            e.array(0);
                        }
                    }
                }
            }
            Frame::Offers { offers } => {
                e.array(2).uint(T_OFFERS);
                crate::node::offers::put_offers(&mut e, offers);
            }
        }
        e.finish()
    }

    /// Parse one frame body.
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(b);
        let n = d.array().map_err(|_| Error::MalformedIpc("ipc frame"))?;
        let tag = d.uint().map_err(|_| Error::MalformedIpc("ipc frame tag"))?;
        let out = decode_body(&mut d, tag, n)?;
        d.finish()
            .map_err(|_| Error::MalformedIpc("ipc frame trailing"))?;
        Ok(out)
    }
}

fn digest(d: &mut Decoder<'_>) -> Result<Digest32> {
    let b = d.bytes().map_err(|_| Error::MalformedIpc("ipc digest"))?;
    Digest32::try_from(b).map_err(|_| Error::MalformedIpc("ipc digest length"))
}

/// A page cursor: empty bytes for "from the start", else a digest.
fn optional_digest(d: &mut Decoder<'_>) -> Result<Option<Digest32>> {
    let b = d.bytes().map_err(|_| Error::MalformedIpc("ipc cursor"))?;
    if b.is_empty() {
        return Ok(None);
    }
    Digest32::try_from(b)
        .map(Some)
        .map_err(|_| Error::MalformedIpc("ipc cursor length"))
}

/// A CBOR text string, named so a decode failure says which field it was.
fn text(d: &mut Decoder<'_>, what: &'static str) -> Result<String> {
    Ok(d.text().map_err(|_| Error::MalformedIpc(what))?.to_owned())
}

/// A 0/1 flag; any other value is malformed rather than read as true.
fn flag(d: &mut Decoder<'_>, what: &'static str) -> Result<bool> {
    match d.uint().map_err(|_| Error::MalformedBundle(what))? {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(Error::MalformedBundle(what)),
    }
}

/// A passphrase field, decoded into a buffer that is wiped when dropped (V210-94): a request that
/// fails to decode after it is returns an error, and a plain `String` would free a copy unwiped.
/// The decoded [`Request`] keeps it in that buffer, as every client that builds one does.
fn secret_text(d: &mut Decoder<'_>, what: &'static str) -> Result<zeroize::Zeroizing<String>> {
    Ok(zeroize::Zeroizing::new(text(d, what)?))
}

fn addr(d: &mut Decoder<'_>) -> Result<std::net::SocketAddr> {
    d.text()
        .map_err(|_| Error::MalformedIpc("ipc addr"))?
        .parse()
        .map_err(|_| Error::MalformedIpc("ipc addr syntax"))
}

fn encode_event(e: &mut Encoder, ev: &NodeEvent) {
    match ev {
        NodeEvent::NewEntry { channel_id, row } => {
            e.array(8)
                .uint(T_NEW_ENTRY)
                .bytes(channel_id)
                .bytes(&row.entry_hash)
                .bytes(&row.author)
                .uint(row.created_millis)
                .text(&row.text)
                .uint(row.arrival)
                .uint(u64::from(row.late));
        }
        NodeEvent::WaitingForProfile => {
            e.array(1).uint(T_WAITING_FOR_PROFILE);
        }
        NodeEvent::CapabilityChanged { fingerprint, drive } => {
            e.array(3)
                .uint(T_CAPABILITY_CHANGED)
                .bytes(fingerprint)
                .uint(u64::from(*drive));
        }
        NodeEvent::SessionEntry {
            channel_id,
            session_id,
        } => {
            e.array(3)
                .uint(T_SESSION_ENTRY)
                .bytes(channel_id)
                .text(session_id);
        }
        NodeEvent::Shutdown => {
            e.array(1).uint(T_SHUTDOWN);
        }
        NodeEvent::ChannelOpened { channel_id } => {
            e.array(2).uint(T_CHANNEL_OPENED).bytes(channel_id);
        }
        NodeEvent::ChannelClosed { channel_id } => {
            e.array(2).uint(T_CHANNEL_CLOSED).bytes(channel_id);
        }
        NodeEvent::PeerJoined { channel_id, peer } => {
            e.array(3).uint(T_PEER_JOINED).bytes(channel_id).bytes(peer);
        }
        NodeEvent::KeyNotTaken {
            channel_id,
            peer,
            why,
        } => {
            e.array(4)
                .uint(T_KEY_NOT_TAKEN)
                .bytes(channel_id)
                .bytes(peer)
                .text(why);
        }
        NodeEvent::SenderKeyReceived {
            channel_id,
            peer,
            backfilled,
        } => {
            e.array(4)
                .uint(T_SENDER_KEY)
                .bytes(channel_id)
                .bytes(peer)
                .uint(*backfilled);
        }
        NodeEvent::Forwarding {
            channel_id,
            host,
            service_tag,
            local,
        } => {
            e.array(5)
                .uint(T_FORWARDING)
                .bytes(channel_id)
                .bytes(host)
                .text(service_tag)
                .text(&local.to_string());
        }
        NodeEvent::Stalled { what, millis } => {
            e.array(3).uint(T_STALLED).text(what).uint(*millis);
        }
        NodeEvent::PublishRefused {
            channel_id,
            what,
            why,
        } => {
            e.array(4)
                .uint(T_PUBLISH_REFUSED)
                .bytes(channel_id)
                .text(what)
                .text(why);
        }
        NodeEvent::PublishCured { channel_id, what } => {
            e.array(3)
                .uint(T_PUBLISH_CURED)
                .bytes(channel_id)
                .text(what);
        }
        NodeEvent::ConnectionNote { peer, note } => {
            e.array(3).uint(T_CONNECTION_NOTE).bytes(peer).text(note);
        }
        NodeEvent::NodeNote { note } => {
            e.array(2).uint(T_NODE_NOTE).text(note);
        }
        NodeEvent::NetworkChanged { summary } => {
            e.array(2).uint(T_NETWORK_CHANGED).text(summary);
        }
        NodeEvent::RetentionAboveRoom {
            channel_id,
            node,
            room,
        } => {
            e.array(4)
                .uint(T_RETENTION_ABOVE_ROOM)
                .bytes(channel_id)
                .uint(*node)
                .uint(*room);
        }
        NodeEvent::RoomEnded {
            channel_id,
            handed,
            members,
        } => {
            e.array(4)
                .uint(T_ROOM_ENDED)
                .bytes(channel_id)
                .uint(*handed as u64)
                .uint(*members as u64);
        }
        NodeEvent::RoomRemoved { channel_id } => {
            e.array(2).uint(T_ROOM_REMOVED).bytes(channel_id);
        }
        NodeEvent::HandshakesQueued {
            waited,
            most_waiting,
            most_running,
            refused,
            longest_ms,
        } => {
            e.array(6)
                .uint(T_HANDSHAKES_QUEUED)
                .uint(*waited as u64)
                .uint(*most_waiting as u64)
                .uint(*most_running as u64)
                .uint(*refused as u64)
                .uint(*longest_ms);
        }
        NodeEvent::SyncFailed {
            channel_id,
            peer,
            reason,
        } => {
            e.array(4)
                .uint(T_SYNC_FAILED)
                .bytes(channel_id)
                .bytes(peer)
                .text(reason);
        }
        NodeEvent::JoinFailed { reason } => {
            e.array(2).uint(T_JOIN_FAILED).text(reason);
        }
        NodeEvent::AddressNote { channel_id, note } => {
            e.array(3).uint(T_ADDRESS_NOTE).bytes(channel_id).text(note);
        }
        NodeEvent::AddressWithheld { channel_id, reason } => {
            e.array(3)
                .uint(T_ADDRESS_WITHHELD)
                .bytes(channel_id)
                .text(reason);
        }
        NodeEvent::RoomNotRemembered { channel_id, why } => {
            e.array(3)
                .uint(T_ROOM_NOT_REMEMBERED)
                .bytes(channel_id)
                .text(why);
        }
        NodeEvent::JoinSteps { joined, steps } => {
            e.array(3)
                .uint(T_JOIN_STEPS)
                .uint(u64::from(*joined))
                .text(steps);
        }
        NodeEvent::JoinStep { step } => {
            e.array(2).uint(T_JOIN_STEP).text(step);
        }
        NodeEvent::StillRelayed { peer, reason } => {
            e.array(3).uint(T_STILL_RELAYED).bytes(peer).text(reason);
        }
        NodeEvent::TunnelClosed { reason } => {
            e.array(2).uint(T_TUNNEL_CLOSED).text(reason);
        }
        NodeEvent::ProxyRefused { reason } => {
            e.array(2).uint(T_PROXY_REFUSED).text(reason);
        }
        NodeEvent::PeerUnreachable { peer, why } => {
            e.array(3).uint(T_PEER_UNREACHABLE).bytes(peer).text(why);
        }
        NodeEvent::ReachWithdrawn { channel_id, port } => {
            e.array(3)
                .uint(T_REACH_WITHDRAWN)
                .bytes(channel_id)
                .uint(u64::from(*port));
        }
        NodeEvent::InviteLink { channel_id, url } => {
            e.array(3).uint(T_INVITE_LINK).bytes(channel_id).text(url);
        }
        NodeEvent::Joined {
            channel_id,
            responder,
        } => {
            e.array(3).uint(T_JOINED).bytes(channel_id).bytes(responder);
        }
        NodeEvent::Consented { channel_id, target } => {
            e.array(3).uint(T_CONSENTED).bytes(channel_id).bytes(target);
        }
        NodeEvent::Revoked {
            channel_id,
            target,
            generation,
            rekeyed,
        } => {
            e.array(5)
                .uint(T_REVOKED)
                .bytes(channel_id)
                .bytes(target)
                .uint(*generation)
                .uint(*rekeyed);
        }
        NodeEvent::TunnelServed {
            channel_id,
            client,
            service_tag,
        } => {
            e.array(4)
                .uint(T_TUNNEL_SERVED)
                .bytes(channel_id)
                .bytes(client)
                .text(service_tag);
        }
        NodeEvent::ProxyUp {
            channel_id,
            hostname,
            bind,
        } => {
            e.array(4)
                .uint(T_PROXY_UP)
                .bytes(channel_id)
                .text(hostname)
                .text(&bind.to_string());
        }
        NodeEvent::Synced {
            channel_id,
            applied,
            rendered,
        } => {
            e.array(4)
                .uint(T_SYNCED)
                .bytes(channel_id)
                .uint(*applied)
                .uint(*rendered);
        }
    }
    // Deliberately no catch-all. `NodeEvent` is `#[non_exhaustive]`, but that
    // only obliges *other* crates; inside `vox-core` this match is exhaustive,
    // so adding a variant upstream breaks this build until it is given a codec
    // arm. A `_` here would instead drop the new event silently — the compiler
    // is a better guard than any runtime fallback.
}

fn decode_body(d: &mut Decoder<'_>, tag: u64, n: usize) -> Result<Frame> {
    let ev = match (tag, n) {
        (T_HELLO, 3) => {
            let protocol = d.uint().map_err(|_| Error::MalformedIpc("ipc hello"))?;
            let fp = d
                .bytes()
                .map_err(|_| Error::MalformedIpc("ipc hello identity"))?;
            let me = if fp.is_empty() {
                None
            } else {
                Some(
                    Digest32::try_from(fp)
                        .map_err(|_| Error::MalformedIpc("ipc hello identity length"))?,
                )
            };
            return Ok(Frame::Hello { protocol, me });
        }
        (crate::node::daemonipc::T_NODE_DETACHED, 2) => {
            let node = d
                .text()
                .map_err(|_| Error::MalformedIpc("ipc node detached"))?;
            return Ok(Frame::NodeDetached {
                node: crate::node::daemonipc::NodeName::parse(node)
                    .map_err(|_| Error::MalformedIpc("ipc node detached name"))?,
            });
        }
        (T_LAGGED, 2) => {
            return Ok(Frame::Lagged {
                missed: d.uint().map_err(|_| Error::MalformedIpc("ipc lagged"))?,
            })
        }
        (T_OK, 1) => return Ok(Frame::Ok),
        (T_ERROR, 2) => {
            return Ok(Frame::Error {
                reason: d
                    .text()
                    .map_err(|_| Error::MalformedIpc("ipc error reason"))?
                    .to_owned(),
            })
        }
        (T_AGREEMENT, 2) => {
            let report = crate::node::agreestream::decode_report(d)?;
            return Ok(Frame::Agreement { report });
        }
        (T_COUNT, 3) => {
            let n = d.uint().map_err(|_| Error::MalformedIpc("ipc count"))?;
            let last = optional_digest(d)?;
            return Ok(Frame::Count { n, last });
        }
        (T_ROWS, 2) => {
            let n = d.array().map_err(|_| Error::MalformedIpc("ipc rows"))?;
            let mut rows = Vec::with_capacity(n.min(1024));
            for _ in 0..n {
                let arity = d.array().map_err(|_| Error::MalformedIpc("ipc row"))?;
                if arity != 7 {
                    return Err(Error::MalformedIpc("ipc row arity"));
                }
                rows.push(MessageRow {
                    entry_hash: digest(d)?,
                    author: digest(d)?,
                    created_millis: d.uint().map_err(|_| Error::MalformedIpc("ipc millis"))?,
                    text: d
                        .text()
                        .map_err(|_| Error::MalformedIpc("ipc text"))?
                        .to_owned(),
                    arrival: d
                        .uint()
                        .map_err(|_| Error::MalformedBundle("ipc arrival"))?,
                    late: flag(d, "ipc late")?,
                    owed: flag(d, "ipc owed")?,
                });
            }
            return Ok(Frame::Rows { rows });
        }
        (T_ORDER_ROWS, 2) => {
            let n = d.array().map_err(|_| Error::MalformedBundle("ipc order"))?;
            let mut entries = Vec::with_capacity(n.min(1024));
            for _ in 0..n {
                if d.array()
                    .map_err(|_| Error::MalformedBundle("ipc order entry"))?
                    != 2
                {
                    return Err(Error::MalformedBundle("ipc order entry arity"));
                }
                let h = digest(d)?;
                let clock = d
                    .uint()
                    .map_err(|_| Error::MalformedBundle("ipc order clock"))?;
                entries.push((h, clock));
            }
            return Ok(Frame::Order { entries });
        }
        (T_MEMBERS, 2) => {
            let n = d.array().map_err(|_| Error::MalformedIpc("ipc members"))?;
            let mut members = Vec::with_capacity(n.min(1024));
            for _ in 0..n {
                members.push(digest(d)?);
            }
            return Ok(Frame::Members { members });
        }
        (T_OWN_RETENTION, 3) => {
            return Ok(Frame::OwnRetention {
                own: d
                    .uint()
                    .map_err(|_| Error::MalformedIpc("ipc own retention"))?,
                room: d
                    .uint()
                    .map_err(|_| Error::MalformedIpc("ipc room retention"))?,
            });
        }
        (T_CONSENTS, 3) => {
            let mut set = |what: &'static str| -> Result<Vec<Digest32>> {
                let n = d.array().map_err(|_| Error::MalformedIpc(what))?;
                let mut out = Vec::with_capacity(n.min(1024));
                for _ in 0..n {
                    out.push(digest(d)?);
                }
                Ok(out)
            };
            let outbound = set("ipc trust grants outbound")?;
            let inbound = set("ipc trust grants inbound")?;
            return Ok(Frame::Consents { outbound, inbound });
        }
        (T_BOUND, 2) => {
            return Ok(Frame::Bound {
                local: text(d, "ipc bound address")?,
            });
        }
        (T_LINK, 2) => {
            return Ok(Frame::Link {
                url: text(d, "ipc link")?,
                note: String::new(),
            });
        }
        (T_LINK, 3) => {
            return Ok(Frame::Link {
                url: text(d, "ipc link")?,
                note: text(d, "ipc link note")?,
            });
        }
        (T_ROOMS, 2) => {
            let n = d.array().map_err(|_| Error::MalformedIpc("ipc rooms"))?;
            let mut rooms = Vec::with_capacity(n.min(1024));
            for _ in 0..n {
                let arity = d.array().map_err(|_| Error::MalformedIpc("ipc room"))?;
                if !(3..=4).contains(&arity) {
                    return Err(Error::MalformedIpc("ipc room arity"));
                }
                let id = digest(d)?;
                let name = d
                    .text()
                    .map_err(|_| Error::MalformedIpc("ipc room name"))?
                    .to_owned();
                let open = d.uint().map_err(|_| Error::MalformedIpc("ipc room open"))? != 0;
                let over = if arity == 4 {
                    d.text()
                        .map_err(|_| Error::MalformedIpc("ipc room over"))?
                        .to_owned()
                } else {
                    String::new()
                };
                rooms.push((id, name, open, over));
            }
            return Ok(Frame::Rooms { rooms });
        }
        (T_SERVICES, 4) => {
            let room = text(d, "ipc services room")?;
            let count = d
                .array()
                .map_err(|_| Error::MalformedIpc("ipc services array"))?;
            let mut services = Vec::with_capacity(count.min(1024));
            for _ in 0..count {
                let arity = d
                    .array()
                    .map_err(|_| Error::MalformedIpc("ipc service row"))?;
                if arity != 2 {
                    return Err(Error::MalformedIpc("ipc service row arity"));
                }
                services.push((text(d, "ipc service tag")?, text(d, "ipc service address")?));
            }
            let count = d
                .array()
                .map_err(|_| Error::MalformedIpc("ipc shared array"))?;
            let mut shared = Vec::with_capacity(count.min(1024));
            for _ in 0..count {
                if d.array()
                    .map_err(|_| Error::MalformedIpc("ipc shared row"))?
                    != 7
                {
                    return Err(Error::MalformedIpc("ipc shared row arity"));
                }
                let address = text(d, "ipc shared address")?;
                let canonical = text(d, "ipc shared canonical address")?;
                let by = text(d, "ipc shared sharer")?;
                let udp = d
                    .uint()
                    .map_err(|_| Error::MalformedIpc("ipc shared udp"))?
                    != 0;
                let kind = text(d, "ipc shared kind")?;
                let trusts_you = d
                    .uint()
                    .map_err(|_| Error::MalformedIpc("ipc shared trusts you"))?
                    != 0;
                let online = d
                    .uint()
                    .map_err(|_| Error::MalformedIpc("ipc shared online"))?
                    != 0;
                shared.push(SharedService {
                    address,
                    canonical,
                    by,
                    udp,
                    kind,
                    trusts_you,
                    online,
                });
            }
            return Ok(Frame::Services {
                room,
                services,
                shared,
            });
        }
        (T_SHARES, 2) => {
            let count = d
                .array()
                .map_err(|_| Error::MalformedIpc("ipc shares array"))?;
            let mut shares = Vec::with_capacity(count.min(1024));
            for _ in 0..count {
                if d.array()
                    .map_err(|_| Error::MalformedIpc("ipc share row"))?
                    != 7
                {
                    return Err(Error::MalformedIpc("ipc share row arity"));
                }
                let tag = text(d, "ipc share tag")?;
                let name = text(d, "ipc share name")?;
                let size = d
                    .uint()
                    .map_err(|_| Error::MalformedIpc("ipc share size"))?;
                let sha256 = text(d, "ipc share sha256")?;
                let entry = text(d, "ipc share entry")?;
                let fetched = d
                    .uint()
                    .map_err(|_| Error::MalformedIpc("ipc share fetched"))?;
                let files = d
                    .uint()
                    .map_err(|_| Error::MalformedIpc("ipc share files"))?;
                shares.push(crate::node::shares::ShareRow {
                    tag,
                    name,
                    size,
                    sha256,
                    entry,
                    fetched,
                    files,
                });
            }
            return Ok(Frame::Shares { shares });
        }
        (T_APPENDED, 2) => {
            let entry = digest(d)?;
            return Ok(Frame::Appended { entry });
        }
        (T_SESSION_ROWS, 2) => {
            let count = d
                .array()
                .map_err(|_| Error::MalformedIpc("ipc session entries array"))?;
            let mut rows = Vec::with_capacity(count.min(1024));
            for _ in 0..count {
                if d.array()
                    .map_err(|_| Error::MalformedIpc("ipc session entry row"))?
                    != 5
                {
                    return Err(Error::MalformedIpc("ipc session entry arity"));
                }
                let entry_hash = digest(d)?;
                let author = digest(d)?;
                let created_millis = d
                    .uint()
                    .map_err(|_| Error::MalformedIpc("ipc session entry time"))?;
                let session_id = text(d, "ipc session id")?;
                let body = text(d, "ipc session entry body")?;
                rows.push(crate::node::drive::SessionRow {
                    entry_hash,
                    author,
                    created_millis,
                    session_id,
                    body,
                });
            }
            return Ok(Frame::SessionEntries { rows });
        }
        (T_SESSIONS, 2) => {
            let sessions = crate::node::sessions::read_rows(d)?;
            return Ok(Frame::Sessions { sessions });
        }
        (T_DECISIONS, 2) => {
            let bad = || Error::MalformedIpc("ipc decisions");
            let n = d.array().map_err(|_| bad())?;
            let mut events = Vec::with_capacity(n.min(1_024));
            for _ in 0..n {
                if d.array().map_err(|_| bad())? != 7 {
                    return Err(bad());
                }
                let at_ms = d.uint().map_err(|_| bad())?;
                let asked = text(d, "ipc decision asked")?;
                let by = text(d, "ipc decision by")?;
                let alias = match d.array().map_err(|_| bad())? {
                    0 => None,
                    1 => Some(text(d, "ipc decision alias")?),
                    _ => return Err(bad()),
                };
                let decided = text(d, "ipc decision decided")?;
                let why = text(d, "ipc decision why")?;
                let room = match d.array().map_err(|_| bad())? {
                    0 => None,
                    1 => Some(text(d, "ipc decision room")?),
                    _ => return Err(bad()),
                };
                events.push(crate::node::decisions::Event {
                    at_ms,
                    asked,
                    by,
                    alias,
                    decided,
                    why,
                    room,
                });
            }
            return Ok(Frame::Decisions { events });
        }
        (T_OFFERS, 2) => {
            let offers = crate::node::offers::read_offers(d)?;
            return Ok(Frame::Offers { offers });
        }
        (T_TRUSTED, 2) => {
            let count = d
                .array()
                .map_err(|_| Error::MalformedIpc("ipc trusted array"))?;
            let mut entries = Vec::with_capacity(count.min(1024));
            for _ in 0..count {
                let arity = d
                    .array()
                    .map_err(|_| Error::MalformedIpc("ipc trusted row"))?;
                if arity != 3 {
                    return Err(Error::MalformedIpc("ipc trusted row arity"));
                }
                let id = digest(d)?;
                let petname = d
                    .text()
                    .map_err(|_| Error::MalformedIpc("ipc trusted petname"))?
                    .to_owned();
                let capability = if flag(d, "ipc trusted capability")? {
                    crate::node::trust::Capability::ReadDrive
                } else {
                    crate::node::trust::Capability::Read
                };
                entries.push((id, petname, capability));
            }
            return Ok(Frame::Trusted { entries });
        }
        (T_NEW_ENTRY, 8) => {
            let channel_id = digest(d)?;
            let entry_hash = digest(d)?;
            let author = digest(d)?;
            let created_millis = d.uint().map_err(|_| Error::MalformedIpc("ipc millis"))?;
            let text = d
                .text()
                .map_err(|_| Error::MalformedIpc("ipc text"))?
                .to_owned();
            let arrival = d
                .uint()
                .map_err(|_| Error::MalformedBundle("ipc arrival"))?;
            let late = flag(d, "ipc late")?;
            NodeEvent::NewEntry {
                channel_id,
                row: MessageRow {
                    entry_hash,
                    author,
                    created_millis,
                    text,
                    arrival,
                    late,
                    owed: false,
                },
            }
        }
        (T_WAITING_FOR_PROFILE, 1) => NodeEvent::WaitingForProfile,
        (T_SHUTDOWN, 1) => NodeEvent::Shutdown,
        (T_CHANNEL_OPENED, 2) => NodeEvent::ChannelOpened {
            channel_id: digest(d)?,
        },
        (T_CAPABILITY_CHANGED, 3) => NodeEvent::CapabilityChanged {
            fingerprint: digest(d)?,
            drive: flag(d, "ipc event drive")?,
        },
        (T_SESSION_ENTRY, 3) => NodeEvent::SessionEntry {
            channel_id: digest(d)?,
            session_id: text(d, "ipc event session id")?,
        },
        (T_CHANNEL_CLOSED, 2) => NodeEvent::ChannelClosed {
            channel_id: digest(d)?,
        },
        (T_PEER_JOINED, 3) => NodeEvent::PeerJoined {
            channel_id: digest(d)?,
            peer: digest(d)?,
        },
        (T_KEY_NOT_TAKEN, 4) => NodeEvent::KeyNotTaken {
            channel_id: digest(d)?,
            peer: digest(d)?,
            why: d
                .text()
                .map_err(|_| Error::MalformedIpc("ipc why"))?
                .to_owned(),
        },
        (T_SENDER_KEY, 4) => NodeEvent::SenderKeyReceived {
            channel_id: digest(d)?,
            peer: digest(d)?,
            backfilled: d.uint().map_err(|_| Error::MalformedIpc("ipc n"))?,
        },
        (T_FORWARDING, 5) => NodeEvent::Forwarding {
            channel_id: digest(d)?,
            host: digest(d)?,
            service_tag: d
                .text()
                .map_err(|_| Error::MalformedIpc("ipc tag"))?
                .to_owned(),
            local: addr(d)?,
        },
        (T_STALLED, 3) => NodeEvent::Stalled {
            what: d
                .text()
                .map_err(|_| Error::MalformedIpc("ipc stall what"))?
                .to_owned(),
            millis: d.uint().map_err(|_| Error::MalformedIpc("ipc stall ms"))?,
        },
        (T_SYNC_FAILED, 4) => NodeEvent::SyncFailed {
            channel_id: digest(d)?,
            peer: digest(d)?,
            reason: d
                .text()
                .map_err(|_| Error::MalformedIpc("ipc sync failed reason"))?
                .to_owned(),
        },
        (T_ROOM_NOT_REMEMBERED, 3) => NodeEvent::RoomNotRemembered {
            channel_id: digest(d)?,
            why: d
                .text()
                .map_err(|_| Error::MalformedIpc("ipc room not remembered why"))?
                .to_owned(),
        },
        (T_ROOM_ENDED, 4) => NodeEvent::RoomEnded {
            channel_id: digest(d)?,
            handed: usize::try_from(
                d.uint()
                    .map_err(|_| Error::MalformedIpc("ipc room quiet"))?,
            )
            .unwrap_or(usize::MAX),
            members: usize::try_from(
                d.uint()
                    .map_err(|_| Error::MalformedIpc("ipc room quiet"))?,
            )
            .unwrap_or(usize::MAX),
        },
        (T_ROOM_REMOVED, 2) => NodeEvent::RoomRemoved {
            channel_id: digest(d)?,
        },
        (T_HANDSHAKES_QUEUED, 6) => {
            let mut count = |what| {
                d.uint()
                    .ok()
                    .and_then(|n| usize::try_from(n).ok())
                    .ok_or(Error::MalformedIpc(what))
            };
            NodeEvent::HandshakesQueued {
                waited: count("ipc handshakes waited")?,
                most_waiting: count("ipc handshakes most waiting")?,
                most_running: count("ipc handshakes most running")?,
                refused: count("ipc handshakes refused")?,
                longest_ms: d
                    .uint()
                    .map_err(|_| Error::MalformedIpc("ipc handshakes longest"))?,
            }
        }
        (T_ADDRESS_NOTE, 3) => NodeEvent::AddressNote {
            channel_id: digest(d)?,
            note: d
                .text()
                .map_err(|_| Error::MalformedIpc("ipc address note"))?
                .to_owned(),
        },
        (T_ADDRESS_WITHHELD, 3) => NodeEvent::AddressWithheld {
            channel_id: digest(d)?,
            reason: d
                .text()
                .map_err(|_| Error::MalformedIpc("ipc address withheld"))?
                .to_owned(),
        },
        (T_RETENTION_ABOVE_ROOM, 4) => NodeEvent::RetentionAboveRoom {
            channel_id: digest(d)?,
            node: d
                .uint()
                .map_err(|_| Error::MalformedIpc("ipc retention node"))?,
            room: d
                .uint()
                .map_err(|_| Error::MalformedIpc("ipc retention room"))?,
        },
        (T_CONNECTION_NOTE, 3) => NodeEvent::ConnectionNote {
            peer: digest(d)?,
            note: d
                .text()
                .map_err(|_| Error::MalformedIpc("ipc connection note"))?
                .to_owned(),
        },
        (T_NODE_NOTE, 2) => NodeEvent::NodeNote {
            note: d
                .text()
                .map_err(|_| Error::MalformedIpc("ipc node note"))?
                .to_owned(),
        },
        (T_NETWORK_CHANGED, 2) => NodeEvent::NetworkChanged {
            summary: d
                .text()
                .map_err(|_| Error::MalformedIpc("ipc network changed"))?
                .to_owned(),
        },
        (T_PUBLISH_CURED, 3) => NodeEvent::PublishCured {
            channel_id: digest(d)?,
            what: d
                .text()
                .map_err(|_| Error::MalformedIpc("ipc publish cured what"))?
                .to_owned(),
        },
        (T_PUBLISH_REFUSED, 4) => NodeEvent::PublishRefused {
            channel_id: digest(d)?,
            what: d
                .text()
                .map_err(|_| Error::MalformedIpc("ipc publish what"))?
                .to_owned(),
            why: d
                .text()
                .map_err(|_| Error::MalformedIpc("ipc publish why"))?
                .to_owned(),
        },
        (T_JOIN_STEPS, 3) => NodeEvent::JoinSteps {
            joined: match d.uint()? {
                0 => false,
                1 => true,
                _ => return Err(Error::MalformedIpc("ipc join steps flag")),
            },
            steps: d
                .text()
                .map_err(|_| Error::MalformedIpc("ipc join steps"))?
                .to_owned(),
        },
        (T_JOIN_STEP, 2) => NodeEvent::JoinStep {
            step: d
                .text()
                .map_err(|_| Error::MalformedIpc("ipc join step"))?
                .to_owned(),
        },
        (T_JOIN_FAILED, 2) => NodeEvent::JoinFailed {
            reason: d
                .text()
                .map_err(|_| Error::MalformedIpc("ipc join reason"))?
                .to_owned(),
        },
        (T_STILL_RELAYED, 3) => NodeEvent::StillRelayed {
            peer: digest(d)?,
            reason: d
                .text()
                .map_err(|_| Error::MalformedIpc("ipc relayed reason"))?
                .to_owned(),
        },
        (T_PROXY_REFUSED, 2) => NodeEvent::ProxyRefused {
            reason: d
                .text()
                .map_err(|_| Error::MalformedIpc("ipc proxy refusal reason"))?
                .to_owned(),
        },
        (T_TUNNEL_CLOSED, 2) => NodeEvent::TunnelClosed {
            reason: d
                .text()
                .map_err(|_| Error::MalformedIpc("ipc tunnel close reason"))?
                .to_owned(),
        },
        (T_PEER_UNREACHABLE, 3) => NodeEvent::PeerUnreachable {
            peer: digest(d)?,
            why: d
                .text()
                .map_err(|_| Error::MalformedIpc("ipc unreachable reason"))?
                .to_owned(),
        },
        (T_REACH_WITHDRAWN, 3) => NodeEvent::ReachWithdrawn {
            channel_id: digest(d)?,
            port: u16::try_from(d.uint().map_err(|_| Error::MalformedIpc("ipc port"))?)
                .map_err(|_| Error::MalformedIpc("ipc port range"))?,
        },
        (T_INVITE_LINK, 3) => NodeEvent::InviteLink {
            channel_id: digest(d)?,
            url: d
                .text()
                .map_err(|_| Error::MalformedIpc("ipc url"))?
                .to_owned(),
        },
        (T_JOINED, 3) => NodeEvent::Joined {
            channel_id: digest(d)?,
            responder: digest(d)?,
        },
        (T_CONSENTED, 3) => NodeEvent::Consented {
            channel_id: digest(d)?,
            target: digest(d)?,
        },
        (T_REVOKED, 5) => NodeEvent::Revoked {
            channel_id: digest(d)?,
            target: digest(d)?,
            generation: d.uint().map_err(|_| Error::MalformedIpc("ipc gen"))?,
            rekeyed: d.uint().map_err(|_| Error::MalformedIpc("ipc rekeyed"))?,
        },
        (T_TUNNEL_SERVED, 4) => NodeEvent::TunnelServed {
            channel_id: digest(d)?,
            client: digest(d)?,
            service_tag: d
                .text()
                .map_err(|_| Error::MalformedIpc("ipc tag"))?
                .to_owned(),
        },
        (T_PROXY_UP, 4) => NodeEvent::ProxyUp {
            channel_id: digest(d)?,
            hostname: d
                .text()
                .map_err(|_| Error::MalformedIpc("ipc host"))?
                .to_owned(),
            bind: addr(d)?,
        },
        (T_SYNCED, 4) => NodeEvent::Synced {
            channel_id: digest(d)?,
            applied: d.uint().map_err(|_| Error::MalformedIpc("ipc applied"))?,
            rendered: d.uint().map_err(|_| Error::MalformedIpc("ipc rendered"))?,
        },
        _ => return Err(Error::MalformedIpc("ipc frame unknown tag")),
    };
    Ok(Frame::Event(ev))
}

// ---- transport -------------------------------------------------------------

/// Write one length-prefixed frame, mirroring [`crate::transport::framing`].
///
/// A write that fails is the connection ending under it ([`IpcHandshake::Cut`]), never a
/// malformed message (V210-101): nothing was received to be malformed.
pub async fn write_frame(s: &mut UnixStream, body: &[u8]) -> Result<()> {
    let len =
        u32::try_from(body.len()).map_err(|_| Error::SizeLimitExceeded("ipc frame length"))?;
    s.write_all(&len.to_be_bytes())
        .await
        .map_err(|_| Error::Ipc(IpcHandshake::Cut))?;
    s.write_all(body)
        .await
        .map_err(|_| Error::Ipc(IpcHandshake::Cut))?;
    Ok(())
}

/// Read one length-prefixed frame of at most `MAX_FRAME` bytes. The connection ending, at a
/// frame boundary **or part-way through a frame**, is the peer hanging up → `Ok(None)`.
///
/// Part-way counts too (V210-101): a node killed while it writes a reply larger than the socket's
/// buffer leaves the reader a length and part of a body, then EOF. That is a hang-up, not a
/// malformed message, and so is a read the OS fails (a reset): neither is bytes that arrived and
/// did not parse, the one case "malformed" names.
pub async fn read_frame(s: &mut UnixStream) -> Result<Option<Vec<u8>>> {
    let mut len_buf = [0u8; 4];
    if s.read_exact(&mut len_buf).await.is_err() {
        return Ok(None);
    }
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > frame_limit() {
        return Err(Error::SizeLimitExceeded("ipc frame length"));
    }
    let mut body = vec![0u8; len];
    if s.read_exact(&mut body).await.is_err() {
        // What did arrive may be part of a passphrase (V210-94).
        zeroize::Zeroize::zeroize(&mut body);
        return Ok(None);
    }
    Ok(Some(body))
}

/// A failed exchange with the node at `path`, with the connection ending under a write named as
/// the hang-up it is ([`hung_up`]).
pub(crate) async fn named(path: &Path, e: Error) -> Error {
    match e {
        Error::Ipc(IpcHandshake::Cut) => hung_up(path).await,
        e => e,
    }
}

// ---- server ----------------------------------------------------------------

/// A bound control socket. Dropping it stops accepting and unlinks the path.
#[derive(Debug)]
pub struct IpcServer {
    path: PathBuf,
    task: tokio::task::JoinHandle<()>,
}

impl IpcServer {
    /// The bound path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for IpcServer {
    fn drop(&mut self) {
        self.task.abort();
        // Best effort: leaving the file behind only costs the next bind an
        // unlink, which `place_socket` does anyway.
        let _ = std::fs::remove_file(&self.path);
    }
}

/// How long a client waits for a node to greet it, and for `vox status` to be answered. Both are
/// served off the actor the moment they are asked, so a node that takes this long is not busy: it
/// is suspended or stuck, and waiting longer only hides that.
pub const ANSWER_WITHIN: std::time::Duration = std::time::Duration::from_secs(10);

/// The error for a node that closed the connection before replying (V210-101): never "malformed",
/// since nothing arrived to be malformed. A fresh connection, bounded, tells a node that is gone
/// from one that ended this request itself.
///
/// **Running means greeting, not accepting**: a process being killed closes its connections and
/// its listening socket in whatever order the kernel takes, and a connect in between lands in the
/// backlog of a listener about to close. Measured: a daemon SIGKILLed mid-request was reported
/// "still running". Only a hello read back counts.
pub async fn hung_up(path: &Path) -> Error {
    let still_running = matches!(
        tokio::time::timeout(ANSWER_WITHIN, async {
            let mut s = connect_own(path).await?;
            read_frame(&mut s).await
        })
        .await,
        Ok(Ok(Some(_)))
    );
    Error::Ipc(IpcHandshake::HungUp { still_running })
}

/// The error for a node that did not answer within [`ANSWER_WITHIN`].
#[must_use]
pub fn silent() -> Error {
    Error::Ipc(IpcHandshake::Silent {
        secs: ANSWER_WITHIN.as_secs(),
    })
}

/// How long a node's actor may take to answer a [`Request::Ping`] before it is called stuck.
///
/// The actor reports itself busy past five seconds (`STALL_BUDGET`), and does its long work —
/// joins, passphrase checks, dials — off itself. Twelve times that is not a busy actor.
pub const ACTOR_WITHIN: std::time::Duration = std::time::Duration::from_secs(60);

/// Run `exchange` — one request on a connection to the node at `path` — for as long as that
/// node shows it is still answering.
///
/// Every [`ANSWER_WITHIN`] the exchange is still waiting, a second connection asks the node to
/// greet (within [`ANSWER_WITHIN`]) and its actor to answer a [`Request::Ping`] (within
/// [`ACTOR_WITHIN`]). A suspended node greets nobody; a stuck actor pings nobody back. Either
/// fails the exchange with an error that says which, instead of the wait that never ended
/// (V210-83). A node that is merely slow at this request answers both, and is waited for.
async fn while_answering<T>(
    path: &Path,
    node: Option<&crate::node::paths::NodeName>,
    exchange: impl std::future::Future<Output = Result<T>>,
) -> Result<T> {
    tokio::pin!(exchange);
    loop {
        tokio::select! {
            // The answer wins a tie: a request answered as a check fails was answered.
            biased;
            out = &mut exchange => return out,
            alive = async {
                tokio::time::sleep(ANSWER_WITHIN).await;
                still_answering(path, node).await
            } => alive?,
        }
    }
}

/// Whether the node at `path` greets a new connection and its actor answers a ping, or why not.
/// On the daemon's socket the new connection uses `node`, never attaching it.
async fn still_answering(path: &Path, node: Option<&crate::node::paths::NodeName>) -> Result<()> {
    let opened = match node {
        Some(node) => {
            IpcClient::open_at(&NodeSocket::one_shot(path.to_owned(), node.clone())).await
        }
        None => IpcClient::open(path).await,
    };
    let mut probe = match opened {
        Ok(c) => c,
        Err(Error::Ipc(IpcHandshake::Silent { secs })) => {
            return Err(Error::Ipc(IpcHandshake::StoppedAnswering { secs }))
        }
        Err(e) => return Err(e),
    };
    // A bare exchange, not `request`, which would check on the check.
    let ping = async {
        if let Err(e) = write_frame(&mut probe.stream, &Request::Ping.to_bytes()).await {
            return Err(named(path, e).await);
        }
        read_frame(&mut probe.stream).await
    };
    match tokio::time::timeout(ACTOR_WITHIN, ping).await {
        // Any answer, even an error from a node too old to know the ping, is an answer.
        Ok(Ok(Some(_))) => Ok(()),
        Ok(Ok(None)) => Err(hung_up(path).await),
        Ok(Err(e)) => Err(e),
        Err(_) => Err(Error::Ipc(IpcHandshake::Stuck {
            secs: ACTOR_WITHIN.as_secs(),
        })),
    }
}

/// Place a listening socket at `path`, `0600`, by binding a staging name and renaming it into
/// place, so no client ever finds the socket with a wider mode.
///
/// The directory is made private to this user first ([`prepare_socket_dir`]), and one that is
/// not is refused: whoever owns the directory can replace the socket in it. The stale socket file
/// of a process that died is **unlinked first**: `bind` fails with `AddrInUse` otherwise
/// (measured), and inheriting that error would report a dead predecessor as a live conflict. The
/// staging name is chmod'd to `0600` before the rename because `bind` itself yields `0755` from
/// the umask (also measured), so `path` is never a socket at any other mode (V210-72).
///
/// [`prepare_socket_dir`]: crate::node::paths::prepare_socket_dir
fn place_socket(path: &Path) -> Result<UnixListener> {
    crate::node::paths::prepare_socket_dir(path)?;
    // Never longer than `path`, so it fits wherever `path` does.
    let staging = path.with_extension("new");
    for stale in [staging.as_path(), path] {
        if std::fs::symlink_metadata(stale).is_ok() {
            std::fs::remove_file(stale).map_err(|e| Error::Path {
                op: "unlink stale control socket",
                detail: format!("{}: {e}", stale.display()),
            })?;
        }
    }
    let listener = UnixListener::bind(&staging).map_err(|e| Error::Path {
        op: "bind control socket",
        detail: format!("{}: {e}", staging.display()),
    })?;
    let placed = {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&staging, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| Error::Path {
                op: "chmod control socket",
                detail: format!("{}: {e}", staging.display()),
            })
            .and_then(|()| {
                std::fs::rename(&staging, path).map_err(|e| Error::Path {
                    op: "place control socket",
                    detail: format!("{}: {e}", path.display()),
                })
            })
    };
    if let Err(e) = placed {
        let _ = std::fs::remove_file(&staging);
        return Err(e);
    }
    Ok(listener)
}

/// What a client opened over its connection and has not closed: a file offer's service,
/// a get's forward.
///
/// **They last as long as the connection** (V210-72). `vox room send` (since replaced by
/// `vox share`) and `vox room get` withdrew them only on Ctrl-C, so a SIGTERM, a SIGHUP, a closed terminal or a crash left
/// the offer's service registered — persisted, and pointing at a port some later process
/// could take — and the get's forward listening. The daemon sees the connection close
/// however the process ends, so it withdraws them itself.
#[derive(Default)]
struct Held {
    services: Vec<(Digest32, String)>,
    forwards: Vec<String>,
}

impl Held {
    /// What `request` would open or close, taken before it is served (a request is not
    /// cloned for this: some carry passphrases).
    fn intent(request: &Request) -> Intent {
        match request {
            // A kept offer outlives the connection that made it, as `vox service add` means it to.
            Request::AddService { persist: true, .. } => Intent::Nothing,
            Request::AddService {
                channel_id,
                service_tag,
                ..
            } => Intent::Offer(*channel_id, service_tag.clone()),
            Request::RemoveService {
                channel_id,
                service_tag,
            } => Intent::Withdraw(*channel_id, service_tag.clone()),
            Request::Forward { .. } => Intent::Forward,
            Request::StopForward { local } => Intent::StopForward(local.clone()),
            _ => Intent::Nothing,
        }
    }

    /// Note what `intent` did, given the node's `reply`.
    fn note(&mut self, intent: Intent, reply: &Frame) {
        match (intent, reply) {
            (Intent::Offer(c, t), Frame::Ok) => self.services.push((c, t)),
            (Intent::Withdraw(c, t), _) => self.services.retain(|(hc, ht)| !(*hc == c && *ht == t)),
            (Intent::Forward, Frame::Bound { local }) => self.forwards.push(local.clone()),
            (Intent::StopForward(local), _) => self.forwards.retain(|l| *l != local),
            _ => {}
        }
    }

    /// Withdraw everything still held.
    async fn release(self, handle: &NodeHandle) {
        for (channel_id, service_tag) in self.services {
            let _ = handle
                .apply(crate::node::api::NodeCommand::RemoveService {
                    channel_id,
                    service_tag,
                })
                .await;
        }
        for local in self.forwards {
            if let Ok(local) = local.parse() {
                let _ = handle
                    .apply(crate::node::api::NodeCommand::StopForward { local })
                    .await;
            }
        }
    }
}

/// See [`Held::intent`].
enum Intent {
    Offer(Digest32, String),
    Withdraw(Digest32, String),
    Forward,
    StopForward(String),
    Nothing,
}

/// Wait until `detached` says the node detached (ADR-026 L-3); for ever when there is none to
/// watch, or its sender is gone without saying so.
async fn node_detached(detached: &mut Option<tokio::sync::watch::Receiver<bool>>) {
    match detached {
        Some(rx) => {
            if rx.wait_for(|d| *d).await.is_err() {
                std::future::pending::<()>().await;
            }
        }
        None => std::future::pending::<()>().await,
    }
}

/// Serve requests, and stream once subscribed, until either side stops — or until the node
/// detaches (`detached`, ADR-026 L-3): a request in flight then, or the next one, is answered
/// [`Frame::NodeDetached`] and the connection ends, so a client holding a session sees its node
/// go and is never left on a dead one (L-7).
async fn serve_requests(
    mut stream: UnixStream,
    handle: &NodeHandle,
    held: &mut Held,
    mut detached: Option<(
        crate::node::paths::NodeName,
        tokio::sync::watch::Receiver<bool>,
    )>,
    extension: Option<std::sync::Arc<dyn Extension>>,
) -> Result<()> {
    let (node, mut watch) = match detached.take() {
        Some((node, rx)) => (Some(node), Some(rx)),
        None => (None, None),
    };
    let gone = |node: &Option<crate::node::paths::NodeName>| {
        node.clone()
            .map(|node| Frame::NodeDetached { node }.to_bytes())
    };
    // Serve requests until the client hangs up, or until it subscribes — which is
    // terminal, because from then on the connection is a one-way stream.
    loop {
        let next = tokio::select! {
            next = read_frame(&mut stream) => next?,
            () = node_detached(&mut watch) => {
                if let Some(b) = gone(&node) {
                    let _ = write_frame(&mut stream, &b).await;
                }
                return Ok(());
            }
        };
        let Some(body) = next else {
            return Ok(());
        };
        // **Wiped as soon as it is decoded** (V210-94): a request can carry a room or identity
        // passphrase, and the frame is needed for nothing past its decoding. Freed as it was, it
        // kept a copy in memory after the node locked; held to the end of the request — which for
        // a join is the end of the join — it was still there when the lock reported done.
        // Measured through the shipped binary both times: one copy of a join's room passphrase.
        let body = zeroize::Zeroizing::new(body);
        // ADR-026 S-5: a request the daemon serves itself takes the connection for good.
        if let Some(ext) = extension.as_ref().filter(|e| e.claims(&body)) {
            let serving = ext.serve(body.to_vec(), stream, handle.clone());
            tokio::select! {
                () = serving => {}
                () = node_detached(&mut watch) => {}
            }
            return Ok(());
        }
        // PRD-001 R20: resolving a `.vox` name serves on; `vox up` holds the connection.
        if let Some(req) = crate::node::nameipc::NameRequest::parse(&body) {
            let served = tokio::select! {
                served = crate::node::nameipc::serve(&mut stream, handle, req) => served?,
                () = node_detached(&mut watch) => false,
            };
            if served {
                continue;
            }
            return Ok(());
        }
        // PRD-001 R35: `vox status`. Answered, and the connection serves on.
        if crate::node::status::is_request(&body) {
            crate::node::status::serve(&mut stream, handle).await?;
            continue;
        }
        // ADR-026 C-7: what a client that draws the node's rooms needs, the TUI first. Answered,
        // and the connection serves on.
        if crate::node::snapshot::is_request(&body) {
            write_frame(&mut stream, &crate::node::snapshot::answer(handle)).await?;
            continue;
        }
        // V030-11: `vox tunnel close`. The live tunnels are kept in this process, so it is
        // answered here, and the connection serves on.
        if let Some(which) = crate::node::status::close_request(&body) {
            // Only this node's own tunnels: a process may host several (ADR-026 P-1).
            let me = handle
                .view()
                .identity
                .map(|i| i.fingerprint)
                .unwrap_or_default();
            crate::node::status::serve_close(&mut stream, &me, &which).await?;
            continue;
        }
        // Protocol 6: an app request turns the connection into an app connection for
        // the rest of its life (ADR-022 decision 7, `node::appipc`).
        if let Some(app) = crate::node::appipc::AppRequest::parse(&body) {
            return match app {
                Ok(app) => tokio::select! {
                    r = crate::node::appipc::serve(stream, handle.clone(), app) => r,
                    () = node_detached(&mut watch) => Ok(()),
                },
                Err(e) => {
                    write_frame(
                        &mut stream,
                        &Frame::Error {
                            reason: e.to_string(),
                        }
                        .to_bytes(),
                    )
                    .await
                }
            };
        }
        let request = Request::from_bytes(&body);
        drop(body);
        let request = match request {
            Ok(r) => r,
            Err(e) => {
                // A request this build does not understand ends the connection
                // rather than being skipped: a client that cannot be understood
                // must not be left believing it was served.
                let _ = write_frame(
                    &mut stream,
                    &Frame::Error {
                        reason: e.to_string(),
                    }
                    .to_bytes(),
                )
                .await;
                return Ok(());
            }
        };
        if matches!(request, Request::Subscribe) {
            // Subscribe BEFORE acknowledging, so nothing emitted between the
            // request and the first read is missed.
            let events = handle.subscribe();
            write_frame(&mut stream, &Frame::Ok.to_bytes()).await?;
            // **What it missed, said first** (#407): a board connection made before this client
            // subscribed — at its attach, say — was noted then, to nobody. The same note, now.
            for (peer, note) in handle.view().boards_connected {
                let frame =
                    Frame::Event(crate::node::api::NodeEvent::ConnectionNote { peer, note });
                write_frame(&mut stream, &frame.to_bytes()).await?;
            }
            return tokio::select! {
                r = pump(stream, events) => r,
                () = node_detached(&mut watch) => Ok(()),
            };
        }
        let intent = Held::intent(&request);
        let reply = tokio::select! {
            reply = serve_request(handle, request) => reply,
            // **A client that hangs up mid-request is noticed then, not when the request ends**
            // (ADR-026 L-3): a `vox connect` stopped during its join kept its connection — and the
            // hold it carries on its node — until the join finished, so an implicit node's detach,
            // and the goodbye its connections owe their peers, waited on a join nobody wanted.
            // The request is abandoned; what it started in the node goes on, or stops with the
            // node.
            () = subscriber_gone(&stream) => return Ok(()),
            () = node_detached(&mut watch) => {
                if let Some(b) = gone(&node) {
                    let _ = write_frame(&mut stream, &b).await;
                }
                return Ok(());
            }
        };
        held.note(intent, &reply);
        write_frame(&mut stream, &reply.to_bytes()).await?;
    }
}

// ---- the account socket (ADR-026 §4) ---------------------------------------------------------

/// A connection's right to act as one attached node, as the daemon's router grants it for a
/// `Use` (ADR-026 C-2).
pub struct Lease {
    /// The node.
    pub node: crate::node::paths::NodeName,
    /// Its handle.
    pub handle: NodeHandle,
    /// Turns `true` when the node detaches (L-3).
    pub detached: tokio::sync::watch::Receiver<bool>,
    /// What the connection holds of the node (L-3, L-7): dropped when the connection ends, after
    /// what it opened is withdrawn, which may detach a node attached implicitly.
    pub hold: Option<Box<dyn std::any::Any + Send + Sync>>,
    /// A request the daemon serves itself, beyond the node's vocabulary, if it has one.
    pub extension: Option<std::sync::Arc<dyn Extension>>,
    /// What attaching the node said, when this `Use` attached it ([`DaemonFrame::Using`]).
    ///
    /// [`DaemonFrame::Using`]: crate::node::daemonipc::DaemonFrame::Using
    pub notes: Vec<String>,
}

/// A request the daemon's own build serves on a node's connection, beyond what this crate knows:
/// `vox lan up`, whose device comes from a root helper the daemon asks as its user (ADR-026 S-5).
/// It takes the connection for the rest of its life, as an app request does.
pub trait Extension: Send + Sync + 'static {
    /// Whether `body`, a frame the client sent, is this extension's request.
    fn claims(&self, body: &[u8]) -> bool;
    /// Serve the request in `body` on `stream` as the node `handle`, until the client goes.
    fn serve(
        &self,
        body: Vec<u8>,
        stream: UnixStream,
        handle: NodeHandle,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>;
}

/// What the account socket asks of the daemon: implemented by its router.
pub trait Dispatch: Send + Sync + 'static {
    /// The hello every connection is greeted with ([`crate::node::daemonipc::DaemonFrame::Hello`]).
    fn hello(&self) -> crate::node::daemonipc::DaemonFrame;
    /// Grant a `Use`, or refuse it.
    fn use_node(
        &self,
        using: crate::node::daemonipc::UseNode,
    ) -> impl std::future::Future<Output = std::result::Result<Lease, crate::node::daemonipc::Refusal>>
           + Send;
    /// Answer a daemon request (not `Subscribe`, which the socket serves from [`Dispatch::events`]).
    fn daemon(
        &self,
        request: crate::node::daemonipc::DaemonRequest,
    ) -> impl std::future::Future<Output = crate::node::daemonipc::DaemonFrame> + Send;
    /// A new subscription to the daemon's events.
    fn events(&self) -> tokio::sync::broadcast::Receiver<crate::node::daemonipc::DaemonEvent>;
    /// Where the socket counts its open connections, if the daemon wants them counted (an
    /// auto-started daemon exits once it has no node and no connection, ADR-026 L-8).
    fn connections(&self) -> Option<std::sync::Arc<std::sync::atomic::AtomicUsize>> {
        None
    }
}

/// One counted connection: counted while it lives.
struct Counted(Option<std::sync::Arc<std::sync::atomic::AtomicUsize>>);

impl Counted {
    fn new(n: Option<std::sync::Arc<std::sync::atomic::AtomicUsize>>) -> Self {
        if let Some(n) = &n {
            n.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
        Self(n)
    }
}

impl Drop for Counted {
    fn drop(&mut self) {
        if let Some(n) = &self.0 {
            n.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
        }
    }
}

/// Bind the account's one control socket at `path` (ADR-026 C-1): mode `0600`, every peer checked
/// as this user and never uid 0, each connection served by `dispatch`.
///
/// # Errors
/// If the socket cannot be placed.
pub fn bind_account<D: Dispatch>(dispatch: std::sync::Arc<D>, path: PathBuf) -> Result<IpcServer> {
    // `.daemon/` is the daemon's own, made private here if the lock has not made it yet. **Not
    // the shared fallback** (`<tmp>/vox-<uid>`, for a data root whose socket path is too long):
    // `create_private_dir` follows a symlink and changes the mode of whatever it points at, and
    // anyone can plant one there. `place_socket` creates or refuses that one itself, by lstat.
    if let Some(dir) = path.parent() {
        if !crate::node::paths::is_socket_fallback_dir(dir) {
            crate::node::paths::create_private_dir(dir)?;
        }
    }
    let listener = place_socket(&path)?;
    let me = crate::node::paths::my_uid();
    let task = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                // **An accept error is not the end of the socket** (V210-72). They are
                // transient — the process or the system out of descriptors (EMFILE, ENFILE), a
                // connection aborted before it was taken (ECONNABORTED), no buffer space — and
                // returning here would end the control socket for good while the daemon ran on.
                // The pause keeps an exhausted descriptor table from being spun on; the
                // connection waits in the backlog meanwhile.
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                continue;
            };
            if !admitted(stream.peer_cred().ok().map(|c| c.uid()), me) {
                continue;
            }
            let dispatch = std::sync::Arc::clone(&dispatch);
            let counted = Counted::new(dispatch.connections());
            tokio::spawn(async move {
                let _ = serve_account(stream, dispatch).await;
                drop(counted);
            });
        }
    });
    Ok(IpcServer { path, task })
}

/// Whether a peer of uid `peer` may use the account socket of a daemon running as `me`: only the
/// same user, and **never root** (ADR-026 C-1, S-5), even a daemon run as root.
fn admitted(peer: Option<u32>, me: u32) -> bool {
    peer.is_some_and(|p| p == me && p != 0)
}

/// One connection to the account socket: the daemon's hello, the client's opening, then the
/// node's requests or the daemon's answer.
async fn serve_account<D: Dispatch>(
    mut stream: UnixStream,
    dispatch: std::sync::Arc<D>,
) -> Result<()> {
    use crate::node::daemonipc::{DaemonFrame, DaemonRequest, Opening};
    write_frame(&mut stream, &dispatch.hello().to_bytes()).await?;
    let Some(body) = read_frame(&mut stream).await? else {
        return Ok(());
    };
    // Wiped once decoded: an opening can carry passphrases (C-6).
    let body = zeroize::Zeroizing::new(body);
    let opening = Opening::from_bytes(&body);
    drop(body);
    match opening {
        Err(e) => {
            write_frame(
                &mut stream,
                &Frame::Error {
                    reason: e.to_string(),
                }
                .to_bytes(),
            )
            .await
        }
        Ok(Opening::Use(using)) => match dispatch.use_node(using).await {
            Err(refusal) => {
                write_frame(&mut stream, &DaemonFrame::Refused(refusal).to_bytes()).await
            }
            Ok(lease) => serve_node(stream, lease).await,
        },
        Ok(Opening::Daemon(DaemonRequest::Subscribe)) => {
            let mut events = dispatch.events();
            write_frame(&mut stream, &DaemonFrame::Ok.to_bytes()).await?;
            loop {
                // Noticed even with no event to send (see `pump`).
                let next = tokio::select! {
                    next = events.recv() => next,
                    () = subscriber_gone(&stream) => return Ok(()),
                };
                match next {
                    Ok(ev) => {
                        write_frame(&mut stream, &DaemonFrame::Event(ev).to_bytes()).await?;
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => return Ok(()),
                }
            }
        }
        Ok(Opening::Daemon(request)) => {
            let answer = dispatch.daemon(request).await;
            write_frame(&mut stream, &answer.to_bytes()).await
        }
    }
}

/// Serve a granted `Use`: say `Using`, then the node's requests until the client goes or the node
/// detaches; then withdraw what the connection opened and let go of the node.
///
/// # Errors
/// If the `Using` cannot be written.
pub async fn serve_node(mut stream: UnixStream, lease: Lease) -> Result<()> {
    let Lease {
        node,
        handle,
        detached,
        hold,
        extension,
        notes,
    } = lease;
    let using = crate::node::daemonipc::DaemonFrame::Using {
        node: node.clone(),
        me: handle.view().identity.map(|i| i.fingerprint),
        notes,
    };
    let wrote = write_frame(&mut stream, &using.to_bytes()).await;
    let mut held = Held::default();
    if wrote.is_ok() {
        let _ = serve_requests(
            stream,
            &handle,
            &mut held,
            Some((node, detached.clone())),
            extension,
        )
        .await;
    }
    // A detached node has nothing left to withdraw from: its actor has stopped.
    if !*detached.borrow() {
        held.release(&handle).await;
    }
    drop(hold);
    wrote
}

/// Apply `command` and answer `Ok`, or the outcome as an error.
async fn plain(handle: &NodeHandle, command: crate::node::api::NodeCommand) -> Frame {
    match handle.apply(command).await {
        crate::node::api::Outcome::Done => Frame::Ok,
        other => Frame::Error {
            reason: other.to_string(),
        },
    }
}

/// Prove the caller holds the identity passphrase, or say why not. A right one is an entry of it,
/// so the node's keyring window starts again (V210-159).
async fn verify_operator(
    handle: &NodeHandle,
    mut passphrase: zeroize::Zeroizing<String>,
) -> std::result::Result<(), Frame> {
    match handle
        .apply(crate::node::api::NodeCommand::VerifyPassphrase {
            passphrase: crate::node::api::Secret::new(
                std::mem::take(&mut *passphrase).into_bytes(),
            ),
        })
        .await
    {
        crate::node::api::Outcome::Done => Ok(()),
        crate::node::api::Outcome::Failed(crate::node::api::Fault::WrongPassphrase) => {
            Err(Frame::Error {
                reason: "the identity passphrase does not match; the trust keyring is only \
                         editable by whoever holds it"
                    .to_owned(),
            })
        }
        // Only a wrong passphrase is one. A node with no identity, or shutting down, or a check
        // that failed inside, was reported as a mistyped passphrase, and the person retyped a
        // right one (V210-83).
        other => Err(Frame::Error {
            reason: other.to_string(),
        }),
    }
}

/// [`verify_operator`] for a passphrase that was given; for none (the empty string), the node's
/// keyring window decides.
///
/// **The empty string is also a passphrase** (V030-36): an identity may have none. So an empty
/// one is checked too, and a match counts as the passphrase entered, opening the window; a
/// mismatch is "none given", not a wrong passphrase. Without that, an identity with no
/// passphrase could never change its keyring once the window had passed.
///
/// Answers whether the passphrase was proved: a proved change is made as
/// [`NodeCommand::Proved`](crate::node::api::NodeCommand::Proved), which the window does not
/// refuse.
async fn verify_given(
    handle: &NodeHandle,
    passphrase: zeroize::Zeroizing<String>,
) -> std::result::Result<bool, Frame> {
    if passphrase.is_empty() {
        return Ok(verify_operator(handle, passphrase).await.is_ok());
    }
    verify_operator(handle, passphrase).await.map(|()| true)
}

/// **For proofs only.** When set, a keyring change whose passphrase was just proved waits this
/// many milliseconds between the check and the change, which stands for a daemon too busy to
/// make it at once, past the keyring window. Nothing a person runs sets it; unset, nothing
/// changes. Not compiled in without the `test-knobs` feature.
#[cfg(feature = "test-knobs")]
pub const TEST_PROVED_CHANGE_DELAY_ENV: &str = "VOX_TEST_PROVED_CHANGE_DELAY_MS";

/// `change`, as [`NodeCommand::Proved`](crate::node::api::NodeCommand::Proved) when its
/// passphrase was just proved.
async fn proved_if(
    proved: bool,
    change: crate::node::api::NodeCommand,
) -> crate::node::api::NodeCommand {
    if !proved {
        return change;
    }
    #[cfg(feature = "test-knobs")]
    if let Some(ms) = std::env::var(TEST_PROVED_CHANGE_DELAY_ENV)
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
    {
        tokio::time::sleep(std::time::Duration::from_millis(ms)).await;
    }
    crate::node::api::NodeCommand::Proved {
        change: Box::new(change),
    }
}

/// One page of a collection reply: entries in id order, strictly after `after`, at most
/// [`PAGE_ENTRIES`] of them and at most [`ROWS_BUDGET`] bytes, and at least one while any
/// remain.
///
/// **Every collection reply is paged** (V210-16). `Rooms` used to be the whole list in one
/// frame, and the client refuses a frame over `MAX_FRAME`: past about 1,540 rooms at the
/// longest local name, `vox room list` and every command that resolves a room by name
/// stopped working, and rooms are unbounded. `Trusted` is bounded — the keyring holds at
/// most `MAX_TRUSTED` (1,024) entries, about 100 KiB — and is paged the same way so that
/// no collection reply depends on a cap elsewhere staying small.
/// Ordering by id rather than by position means a page boundary survives a room being
/// added or removed between pages: the next page starts at the first id past the cursor.
fn page<T>(
    mut items: Vec<T>,
    after: Option<Digest32>,
    key: impl Fn(&T) -> (Digest32, usize),
) -> Vec<T> {
    items.sort_by_key(|t| key(t).0);
    let mut out = Vec::new();
    let mut bytes = 0usize;
    for t in items {
        let (id, len) = key(&t);
        if after.is_some_and(|a| id <= a) {
            continue;
        }
        let cost = len + ENTRY_OVERHEAD;
        if !out.is_empty() && (out.len() >= PAGE_ENTRIES || bytes + cost > rows_budget()) {
            break;
        }
        bytes += cost;
        out.push(t);
    }
    out
}

/// `text` on one line, so a detail line in a [`Frame::Error`] stays one line.
fn one_line(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Answer one request against the node.
///
/// Every failure comes back as [`Frame::Error`] rather than ending the
/// connection: a client that asked for a room it does not have should be told so
/// and be able to ask something else.
async fn serve_request(handle: &NodeHandle, request: Request) -> Frame {
    match request {
        // Handled by the caller; the connection becomes a stream.
        Request::Subscribe => Frame::Ok,
        Request::Ping => match handle.apply(crate::node::api::NodeCommand::Ping).await {
            crate::node::api::Outcome::Done => Frame::Ok,
            other => Frame::Error {
                reason: other.to_string(),
            },
        },
        // A keyring change (V210-159). A passphrase given is checked first, and the command is
        // only issued if it passes; a right one is also an entry of it, so the window starts
        // again. None given is the empty string, and the node then allows the change only
        // within its window since the passphrase was last entered, and otherwise refuses it
        // with `Fault::PassphraseNeeded`, which the client answers by asking for it.
        Request::Trust {
            target,
            petname,
            identity_passphrase,
            full_history,
            drive,
        } => match verify_given(handle, identity_passphrase).await {
            Err(f) => f,
            Ok(proved) => match handle
                .apply(
                    proved_if(
                        proved,
                        crate::node::api::NodeCommand::TrustWith {
                            fingerprint: target,
                            petname,
                            history: if full_history {
                                crate::node::trust::HistoryGrant::Full
                            } else {
                                crate::node::trust::HistoryGrant::Now
                            },
                            capability: Some(if drive {
                                crate::node::trust::Capability::ReadDrive
                            } else {
                                crate::node::trust::Capability::Read
                            }),
                        },
                    )
                    .await,
                )
                .await
            {
                crate::node::api::Outcome::Done => Frame::Ok,
                other => Frame::Error {
                    reason: other.to_string(),
                },
            },
        },
        // Not gated on the passphrase (ADR-028 K-11): the room's governance says who may.
        Request::RenameRoom { channel_id, name } => match handle
            .apply(crate::node::api::NodeCommand::RenameRoom { channel_id, name })
            .await
        {
            crate::node::api::Outcome::Done => Frame::Ok,
            other => Frame::Error {
                reason: other.to_string(),
            },
        },
        // Not gated on the passphrase (ADR-028 K-11): the node's governance says who may.
        Request::SetRetention { channel_id, ttl } => match handle
            .apply(crate::node::api::NodeCommand::SetRetention { channel_id, ttl })
            .await
        {
            crate::node::api::Outcome::Done => Frame::Ok,
            crate::node::api::Outcome::OwnRetention { own, room } => {
                Frame::OwnRetention { own, room }
            }
            other => Frame::Error {
                reason: other.to_string(),
            },
        },
        Request::Untrust {
            target,
            identity_passphrase,
        } => match verify_given(handle, identity_passphrase).await {
            Err(f) => f,
            Ok(proved) => match handle
                .apply(
                    proved_if(
                        proved,
                        crate::node::api::NodeCommand::Untrust {
                            fingerprint: target,
                        },
                    )
                    .await,
                )
                .await
            {
                crate::node::api::Outcome::Done => Frame::Ok,
                other => Frame::Error {
                    reason: other.to_string(),
                },
            },
        },
        Request::Rename {
            target,
            petname,
            identity_passphrase,
        } => match verify_given(handle, identity_passphrase).await {
            Err(f) => f,
            Ok(proved) => match handle
                .apply(
                    proved_if(
                        proved,
                        crate::node::api::NodeCommand::Rename {
                            fingerprint: target,
                            petname,
                        },
                    )
                    .await,
                )
                .await
            {
                crate::node::api::Outcome::Done => Frame::Ok,
                other => Frame::Error {
                    reason: other.to_string(),
                },
            },
        },
        // **A read, so no passphrase** (V210-162, V210-165): the names this node gave its
        // members are how every surface on this account names an author, the agent drain
        // included, and the OS account is the boundary. Only a change to the keyring is gated.
        Request::TrustList { after, .. } => {
            let view = handle.view();
            let rows = view
                .trusted
                .into_iter()
                .map(|(id, petname)| {
                    let capability = if view.drive.contains(&id) {
                        crate::node::trust::Capability::ReadDrive
                    } else {
                        crate::node::trust::Capability::Read
                    };
                    (id, petname, capability)
                })
                .collect();
            Frame::Trusted {
                entries: page(rows, after, |(id, petname, _)| (*id, petname.len())),
            }
        }
        // A keyring change (ADR-028 K-14), gated as `Request::Trust` is.
        Request::SetCapability {
            target,
            drive,
            identity_passphrase,
        } => match verify_given(handle, identity_passphrase).await {
            Err(f) => f,
            Ok(proved) => match handle
                .apply(
                    proved_if(
                        proved,
                        crate::node::api::NodeCommand::SetCapability {
                            fingerprint: target,
                            capability: if drive {
                                crate::node::trust::Capability::ReadDrive
                            } else {
                                crate::node::trust::Capability::Read
                            },
                        },
                    )
                    .await,
                )
                .await
            {
                crate::node::api::Outcome::Done => Frame::Ok,
                other => Frame::Error {
                    reason: other.to_string(),
                },
            },
        },
        Request::MarkRead {
            channel_id,
            entries,
        } => match handle
            .apply(crate::node::api::NodeCommand::MarkRead {
                channel_id,
                entries,
            })
            .await
        {
            crate::node::api::Outcome::Done => Frame::Ok,
            other => Frame::Error {
                reason: other.to_string(),
            },
        },
        Request::Post {
            channel_id,
            text,
            card,
        } => {
            // **A link card is fetched here, by the sender's node, once** (ADR-028 F-10), and
            // travels in the message: no reader's node ever contacts the linked site.
            let text = if card {
                crate::node::card::attach(&text).await
            } else {
                text
            };
            // **The session's name, filled by its node** (ADR-029 MD-2): whatever verb or client
            // posted, a message from a registered session carries the name its harness gives.
            let text = crate::node::sessions::fill_name(handle.paths(), &text);
            // **A post too long says how long, against what, and why** (#549): a post from a
            // session carries the session's id and name around its words, so words that fit
            // alone may not fit with them. "That is longer than this field allows" named no field.
            let max = crate::node::content::MAX_TEXT_LEN;
            if text.len() > max {
                let from_session = vox_agentcomms::envelope::Envelope::parse(&text)
                    .is_ok_and(|e| !e.from.trim().is_empty());
                return Frame::Error {
                    reason: format!(
                        "this post is {} bytes as the room keeps it{}; a post holds at most {max} \
                         bytes (64 KiB), so it must be {} bytes shorter",
                        text.len(),
                        if from_session {
                            ", with the id and name of the session posting it"
                        } else {
                            ""
                        },
                        text.len() - max
                    ),
                };
            }
            // A room just joined is written to once its first sync with another member has ended
            // (V210-164), usually within a second: `vox room join … && vox room post …` waits for
            // that rather than failing.
            let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
            loop {
                match handle
                    .apply(crate::node::api::NodeCommand::SendText {
                        channel_id,
                        text: text.clone(),
                    })
                    .await
                {
                    crate::node::api::Outcome::Done => break Frame::Ok,
                    crate::node::api::Outcome::Failed(crate::node::api::Fault::RoomNotSynced)
                        if tokio::time::Instant::now() < deadline =>
                    {
                        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                    }
                    other => {
                        break Frame::Error {
                            reason: other.to_string(),
                        }
                    }
                }
            }
        }
        Request::Read {
            channel_id,
            since,
            after,
            limit,
        } => {
            let view = handle.view();
            let Some(detail) = view
                .open_channels
                .iter()
                .find(|d| d.channel_id == channel_id)
            else {
                return Frame::Error {
                    reason: "room not open".into(),
                };
            };
            // The cursor is an entry hash the client already has; everything that
            // **arrived** after it is what it has not seen. A cursor this node does not
            // hold is an error rather than "from the start", which would silently
            // re-deliver the whole room.
            //
            // Arrival, not position: the timeline is in the room's order (ADR-023
            // decision 1), where a late arrival lands *above* rows already shown, and
            // "everything below the cursor" would skip it for good. So a read from a
            // cursor is a feed: what this node rendered after the cursor, in the order it
            // rendered them, which makes the last line always the right next cursor. A
            // read with no cursor is the room, in the room's order, and `after` is where
            // its next page starts in that order.
            let candidates: Vec<&MessageRow> = match (since, after) {
                (Some(_), Some(_)) => {
                    return Frame::Error {
                        reason: "a read takes a cursor or a page mark, not both".into(),
                    }
                }
                (Some(cursor), None) => {
                    // A message not received yet has no arrival to read on from (V030-10): as a
                    // cursor its `0` would re-deliver the whole room.
                    // Searched from the end: a tail's cursor is the last row it read, at or near
                    // the end (V210-113).
                    let Some(mark) = detail
                        .timeline
                        .iter()
                        .rev()
                        .find(|r| r.entry_hash == cursor && !r.owed)
                        .map(|r| r.arrival)
                    else {
                        return Frame::Error {
                            reason: "cursor not in this room's timeline".into(),
                        };
                    };
                    let mut newer: Vec<&MessageRow> = detail
                        .timeline
                        .iter()
                        .filter(|r| r.arrival > mark)
                        .collect();
                    newer.sort_by_key(|r| r.arrival);
                    newer
                }
                (None, None) => detail.timeline.iter().collect(),
                (None, Some(mark)) => {
                    let Some(i) = detail.timeline.iter().position(|r| r.entry_hash == mark) else {
                        return Frame::Error {
                            reason: "page mark not in this room's timeline".into(),
                        };
                    };
                    detail.timeline.iter_from(i + 1).collect()
                }
            };
            // **One reply is bounded by bytes, never the whole room.** A reply was every row
            // after `since`, in one frame, and the client refuses a frame over `MAX_FRAME`:
            // so a room past 256 KiB of history could not be read, tailed, posted to with
            // `--op` or board'ed at all ("declared size exceeds hard limit: ipc frame
            // length"). A reply now stops at `ROWS_BUDGET`, always carrying at least one
            // row, and `IpcClient::read_rows` asks again from the last row it got.
            let limit = usize::try_from(limit).unwrap_or(usize::MAX);
            let mut rows: Vec<MessageRow> = Vec::new();
            let mut bytes = 0usize;
            for r in candidates {
                if limit > 0 && rows.len() >= limit {
                    break;
                }
                let cost = r.text.len() + ROW_OVERHEAD;
                if !rows.is_empty() && bytes + cost > rows_budget() {
                    break;
                }
                bytes += cost;
                rows.push(r.clone());
            }
            Frame::Rows { rows }
        }
        Request::Order { channel_id } => {
            let view = handle.view();
            match view
                .open_channels
                .iter()
                .find(|d| d.channel_id == channel_id)
            {
                Some(detail) => Frame::Order {
                    entries: detail.order.clone(),
                },
                None => Frame::Error {
                    reason: "room not open".into(),
                },
            }
        }
        // V210-120: only the rows asked for, found through the room's index of structured posts,
        // so a client after a room's coordination posts no longer reads every row of the room.
        Request::Structured {
            channel_id,
            types,
            ops,
            since,
        } => {
            let view = handle.view();
            let Some(detail) = view
                .open_channels
                .iter()
                .find(|d| d.channel_id == channel_id)
            else {
                return Frame::Error {
                    reason: "room not open".into(),
                };
            };
            // Arrival order, as a read from a cursor is (ADR-023 decision 1): a late post lands
            // above rows already shown, so "the posts below the cursor" would skip it for good. On
            // a room where nothing arrived late this is the timeline's own order.
            let mut matched: Vec<&MessageRow> = detail
                .structured
                .positions(&types, &ops)
                .into_iter()
                .filter_map(|i| detail.timeline.get(i as usize))
                .collect();
            matched.sort_by_key(|r| r.arrival);
            if let Some(cursor) = since {
                let Some(mark) = matched
                    .iter()
                    .rev()
                    .find(|r| r.entry_hash == cursor && !r.owed)
                    .map(|r| r.arrival)
                else {
                    return Frame::Error {
                        reason: "cursor not among this room's structured posts".into(),
                    };
                };
                matched.retain(|r| r.arrival > mark);
            }
            let mut rows: Vec<MessageRow> = Vec::new();
            let mut bytes = 0usize;
            for r in matched {
                let cost = r.text.len() + ROW_OVERHEAD;
                if !rows.is_empty() && bytes + cost > rows_budget() {
                    break;
                }
                bytes += cost;
                rows.push(r.clone());
            }
            Frame::Rows { rows }
        }
        Request::Count { channel_id, since } => {
            let view = handle.view();
            let Some(detail) = view
                .open_channels
                .iter()
                .find(|d| d.channel_id == channel_id)
            else {
                return Frame::Error {
                    reason: "room not open".into(),
                };
            };
            // Counted by arrival, as a read from the cursor delivers (ADR-023 decision 1), and
            // `last` is the row that arrived last, the cursor such a read ends on. A message not
            // received yet (V030-10) has no arrival and is neither.
            let len = detail.timeline.len();
            let last = detail
                .timeline
                .iter()
                .filter(|r| !r.owed)
                .max_by_key(|r| r.arrival)
                .map(|r| r.entry_hash);
            match since {
                None => Frame::Count {
                    n: len as u64,
                    last,
                },
                // From the newest row back: a reader's cursor is usually near the end.
                Some(cursor) => match detail
                    .timeline
                    .iter()
                    .rev()
                    .find(|r| r.entry_hash == cursor && !r.owed)
                    .map(|r| r.arrival)
                {
                    Some(mark) => Frame::Count {
                        n: detail.timeline.iter().filter(|r| r.arrival > mark).count() as u64,
                        last,
                    },
                    None => Frame::Error {
                        reason: "cursor not in this room's timeline".into(),
                    },
                },
            }
        }
        // Searched from the newest row back: what a client looks up (a reply's parent) is
        // usually recent.
        // The rows the view says are unread here, as the timeline holds them (ADR-028 R-8).
        Request::Unread { channel_id } => {
            let view = handle.view();
            let Some(detail) = view
                .open_channels
                .iter()
                .find(|d| d.channel_id == channel_id)
            else {
                return Frame::Error {
                    reason: "room not open".into(),
                };
            };
            let mut want: std::collections::BTreeSet<Digest32> =
                detail.unread.iter().copied().collect();
            let mut rows: Vec<MessageRow> = Vec::new();
            for r in detail.timeline.iter().rev() {
                if want.is_empty() {
                    break;
                }
                if want.remove(&r.entry_hash) {
                    rows.push(r.clone());
                }
            }
            rows.reverse();
            Frame::Rows { rows }
        }
        Request::Find {
            channel_id,
            entries,
        } => {
            let view = handle.view();
            let Some(detail) = view
                .open_channels
                .iter()
                .find(|d| d.channel_id == channel_id)
            else {
                return Frame::Error {
                    reason: "room not open".into(),
                };
            };
            let mut want: std::collections::BTreeSet<Digest32> = entries.into_iter().collect();
            let mut rows: Vec<MessageRow> = Vec::new();
            for r in detail.timeline.iter().rev() {
                if want.is_empty() {
                    break;
                }
                if want.remove(&r.entry_hash) {
                    rows.push(r.clone());
                }
            }
            rows.reverse();
            Frame::Rows { rows }
        }
        // Open or not by the node's own count, not by whether the view has caught up with an
        // open (V210-149): the one-shot form asks the same question the same way.
        Request::Share {
            channel_id,
            path,
            envelope,
            count,
            for_secs,
        } => match handle
            .shares()
            .start(crate::node::shares::ShareRequest {
                channel_id,
                path: PathBuf::from(path),
                envelope,
                count,
                for_secs,
                session: None,
            })
            .await
        {
            Ok(row) => Frame::Shares { shares: vec![row] },
            Err(reason) => Frame::Error { reason },
        },
        Request::SessionShare {
            channel_id,
            path,
            envelope,
            to,
        } => match handle
            .shares()
            .start(crate::node::shares::ShareRequest {
                channel_id,
                path: PathBuf::from(path),
                envelope,
                // Into a Session: one fetch, by its node.
                count: u64::from(matches!(to, SessionTo::Node(_))),
                for_secs: 0,
                session: Some(match to {
                    SessionTo::Session(session_id) => {
                        crate::node::shares::SessionShare::Out { session_id }
                    }
                    SessionTo::Node(node) => crate::node::shares::SessionShare::In { node },
                }),
            })
            .await
        {
            Ok(row) => Frame::Shares { shares: vec![row] },
            Err(reason) => Frame::Error { reason },
        },
        Request::ShareStop {
            channel_id,
            selector,
        } => Frame::Shares {
            shares: handle.shares().stop(&channel_id, &selector).await,
        },
        Request::ShareList { channel_id } => Frame::Shares {
            shares: handle.shares().list(&channel_id).await,
        },
        Request::AppendSession {
            channel_id,
            session_id,
            body,
        } => match handle
            .apply(crate::node::api::NodeCommand::AppendSession {
                channel_id,
                session_id,
                body,
            })
            .await
        {
            crate::node::api::Outcome::Appended(entry) => Frame::Appended { entry },
            other => Frame::Error {
                reason: other.to_string(),
            },
        },
        Request::SessionEntries { channel_id } => match handle.session_rows(channel_id).await {
            Some(rows) => Frame::SessionEntries { rows },
            None => Frame::Error {
                reason: "room not open".into(),
            },
        },
        Request::Decisions { limit } => Frame::Decisions {
            events: handle
                .decisions()
                .recent(usize::try_from(limit).unwrap_or(usize::MAX), None),
        },
        Request::Offers => Frame::Offers {
            offers: handle.view().offers.clone(),
        },
        Request::DismissOffer { member } => match handle
            .apply(crate::node::api::NodeCommand::DismissOffer { member })
            .await
        {
            crate::node::api::Outcome::Done => Frame::Ok,
            other => Frame::Error {
                reason: other.to_string(),
            },
        },
        Request::Sessions { channel_id } => {
            if !handle
                .view()
                .open_channels
                .iter()
                .any(|d| d.channel_id == channel_id)
            {
                return Frame::Error {
                    reason: "room not open".into(),
                };
            }
            Frame::Sessions {
                sessions: crate::node::sessions::of_room(handle, &channel_id),
            }
        }
        Request::Services { channel_id } => match handle.open_detail(channel_id).await {
            Some(detail) => Frame::Services {
                room: crate::node::resolver::room_shown_here(
                    detail.name.as_deref(),
                    &channel_id,
                    handle.view().channels.iter().map(|c| c.name.as_deref()),
                ),
                services: detail
                    .services
                    .iter()
                    .map(|(tag, local)| (tag.clone(), local.to_string()))
                    .collect(),
                shared: handle.shared_in(channel_id).await.unwrap_or_default(),
            },
            None => Frame::Error {
                reason: "room not open".into(),
            },
        },
        Request::Agree {
            channel_id,
            entry,
            types,
        } => {
            let (report, wait) = tokio::sync::oneshot::channel();
            match handle
                .apply(crate::node::api::NodeCommand::Agree {
                    channel_id,
                    entry,
                    types,
                    report,
                })
                .await
            {
                crate::node::api::Outcome::Done => match wait.await {
                    Ok(report) => Frame::Agreement { report },
                    Err(_) => Frame::Error {
                        reason: "the node stopped before its members answered".into(),
                    },
                },
                other => Frame::Error {
                    reason: other.to_string(),
                },
            }
        }
        // **Not paged, and bounded by the product's scale.** A room is at most 500 members
        // (PRD-001's family scale); a member is a 32-byte key, so a roster is ~17 KiB of a
        // 256 KiB frame. A frame would hold ~7,700; paging this is owed only if that scale
        // ever rises past a few thousand (V210-16).
        Request::Roster { channel_id } => {
            let view = handle.view();
            match view
                .open_channels
                .iter()
                .find(|d| d.channel_id == channel_id)
            {
                Some(detail) => Frame::Members {
                    members: detail.members.clone(),
                },
                None => Frame::Error {
                    reason: "room not open".into(),
                },
            }
        }
        // Bounded like the roster: two sets of at most a room's members.
        Request::Consents { channel_id } => {
            let view = handle.view();
            match view
                .open_channels
                .iter()
                .find(|d| d.channel_id == channel_id)
            {
                Some(detail) => Frame::Consents {
                    outbound: detail.consented.clone(),
                    inbound: detail.consenting.clone(),
                },
                None => Frame::Error {
                    reason: "room not open".into(),
                },
            }
        }
        Request::AddService {
            channel_id,
            service_tag,
            local,
            persist,
        } => {
            let Ok(local) = local.parse() else {
                return Frame::Error {
                    reason: format!("not a local address: {local:?}"),
                };
            };
            // A share says what it is (ADR-028 S-2), detected here, off the node's actor; a
            // transient offer (a file being handed over) is no share and is not probed.
            let udp = crate::tunnel::udp::is_udp(&service_tag);
            let kind = if persist {
                crate::node::probe::detect(local, udp).await
            } else {
                crate::governance::share::ServiceKind::plain(udp)
            };
            match handle
                .apply(crate::node::api::NodeCommand::AddService {
                    channel_id,
                    service_tag,
                    local,
                    kind,
                    // Offered over this socket, it lasts as long as the client's connection
                    // (`Held`), and so never outlives this node's run either — unless the client
                    // asked for it kept, as `vox service add` does (V030-06).
                    persist,
                })
                .await
            {
                crate::node::api::Outcome::Done => Frame::Ok,
                other => Frame::Error {
                    reason: other.to_string(),
                },
            }
        }
        Request::RemoveService {
            channel_id,
            service_tag,
        } => match handle
            .apply(crate::node::api::NodeCommand::RemoveService {
                channel_id,
                service_tag,
            })
            .await
        {
            crate::node::api::Outcome::Done => Frame::Ok,
            other => Frame::Error {
                reason: other.to_string(),
            },
        },
        Request::Forward {
            channel_id,
            host,
            service_tag,
            local,
        } => {
            let Ok(local) = local.parse() else {
                return Frame::Error {
                    reason: format!("not a local address: {local:?}"),
                };
            };
            // The answer names the forward this request opened. Reading it from the event
            // stream instead took *any* forward's `Forwarding`, so two requests at once could be
            // handed the same address (see `Outcome::Bound`).
            match handle
                .apply(crate::node::api::NodeCommand::Forward {
                    channel_id,
                    host,
                    service_tag,
                    local,
                })
                .await
            {
                crate::node::api::Outcome::Bound(bound) => Frame::Bound {
                    local: bound.to_string(),
                },
                other => Frame::Error {
                    reason: other.to_string(),
                },
            }
        }
        Request::StopForward { local } => {
            let Ok(local) = local.parse() else {
                return Frame::Error {
                    reason: format!("not a local address: {local:?}"),
                };
            };
            match handle
                .apply(crate::node::api::NodeCommand::StopForward { local })
                .await
            {
                crate::node::api::Outcome::Done => Frame::Ok,
                other => Frame::Error {
                    reason: other.to_string(),
                },
            }
        }
        Request::Join {
            link,
            mut passphrase,
        } => {
            // Subscribe before asking: a failed join's steps and responders' reasons are raised
            // as events just before the outcome is answered, and one emitted between the command
            // and the wait would be lost.
            let mut events = handle.subscribe();
            match handle
                .apply(crate::node::api::NodeCommand::JoinChannel {
                    link,
                    passphrase: crate::node::api::Secret::new(
                        std::mem::take(&mut *passphrase).into_bytes(),
                    ),
                })
                .await
            {
                crate::node::api::Outcome::Done => Frame::Ok,
                // The outcome is named, not reduced to "it failed". `Unreachable` and a
                // refused passphrase call for completely different responses from whoever
                // is holding the link, and this is the only place that knows which it was.
                // The fault's name, which `vox room join` turns into the same guidance `vox
                // connect` gives (`tunnel_cli::join_advice`, V29-12).
                //
                // **And where it stopped (#192).** The join records each step it took and what
                // each responder said; `vox room join` printed neither, so a red that happened
                // once could not be placed. They follow the fault's name, one per line:
                // `steps: …`, then `said: …`.
                other => {
                    // The name `vox room join` reads back with `Fault::from_name` (V210-114).
                    let mut reason = match other {
                        crate::node::api::Outcome::Failed(fault) => {
                            format!("Failed({})", fault.name())
                        }
                        other => other.to_string(),
                    };
                    let (mut steps, mut said) = (None, None);
                    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(1);
                    while steps.is_none() || said.is_none() {
                        match tokio::time::timeout_at(deadline, events.next()).await {
                            Ok(Some(EventStreamItem::Event(NodeEvent::JoinSteps {
                                joined: false,
                                steps: s,
                            }))) if steps.is_none() => steps = Some(s),
                            Ok(Some(EventStreamItem::Event(NodeEvent::JoinFailed {
                                reason: r,
                            }))) if said.is_none() => said = Some(r),
                            Ok(Some(_)) => {}
                            Ok(None) | Err(_) => break,
                        }
                    }
                    for (label, text) in [("steps", steps), ("said", said)] {
                        if let Some(text) = text.filter(|t| !t.is_empty()) {
                            reason.push_str(&format!("\n{label}: {}", one_line(&text)));
                        }
                    }
                    Frame::Error { reason }
                }
            }
        }
        Request::Create {
            name,
            mut passphrase,
        } => match handle
            .apply(crate::node::api::NodeCommand::CreateChannel {
                name,
                passphrase: crate::node::api::Secret::new(
                    std::mem::take(&mut *passphrase).into_bytes(),
                ),
            })
            .await
        {
            crate::node::api::Outcome::Done => Frame::Ok,
            other => Frame::Error {
                reason: other.to_string(),
            },
        },
        Request::OpenRoom {
            channel_id,
            mut passphrase,
        } => {
            plain(
                handle,
                crate::node::api::NodeCommand::OpenChannel {
                    channel_id,
                    passphrase: crate::node::api::Secret::new(
                        std::mem::take(&mut *passphrase).into_bytes(),
                    ),
                },
            )
            .await
        }
        Request::CloseRoom { channel_id } => {
            plain(
                handle,
                crate::node::api::NodeCommand::CloseChannel { channel_id },
            )
            .await
        }
        Request::Leave { channel_id } => {
            plain(
                handle,
                crate::node::api::NodeCommand::LeaveRoom { channel_id },
            )
            .await
        }
        Request::End { channel_id } => {
            plain(
                handle,
                crate::node::api::NodeCommand::EndRoom { channel_id },
            )
            .await
        }
        Request::SetAdmin {
            channel_id,
            member,
            admin,
        } => {
            plain(
                handle,
                crate::node::api::NodeCommand::SetAdmin {
                    channel_id,
                    member,
                    admin,
                },
            )
            .await
        }
        Request::Admins { channel_id } => {
            let view = handle.view();
            match view
                .open_channels
                .iter()
                .find(|d| d.channel_id == channel_id)
            {
                Some(detail) => Frame::Members {
                    members: detail.admins.clone(),
                },
                None => Frame::Error {
                    reason: "room not open".into(),
                },
            }
        }
        Request::IdleEnd {
            channel_id,
            idle_secs,
        } => {
            plain(
                handle,
                crate::node::api::NodeCommand::ChooseIdleEnd {
                    channel_id,
                    idle_secs,
                },
            )
            .await
        }
        Request::Invite { channel_id } => {
            // Subscribe before asking: the link arrives as an event, and one emitted
            // between the command and the wait would be lost.
            let mut events = handle.subscribe();
            match handle
                .apply(crate::node::api::NodeCommand::Invite { channel_id })
                .await
            {
                crate::node::api::Outcome::Done => {}
                other => {
                    // **With why** (V210-96): an address withheld because it would lead nowhere
                    // says so, naming each anchor and what kept the room off it, in place of the
                    // fault's general advice — which speaks of an anchor even when none was named.
                    let mut reason = other.to_string();
                    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(1);
                    while let Ok(Some(item)) =
                        tokio::time::timeout_at(deadline, events.next()).await
                    {
                        if let EventStreamItem::Event(NodeEvent::AddressWithheld {
                            channel_id: c,
                            reason: why,
                        }) = item
                        {
                            if c == channel_id {
                                reason = format!("the address was not handed out: {why}");
                                break;
                            }
                        }
                    }
                    return Frame::Error { reason };
                }
            }
            match tokio::time::timeout(std::time::Duration::from_secs(10), async {
                loop {
                    match events.next().await {
                        Some(EventStreamItem::Event(NodeEvent::InviteLink {
                            channel_id: c,
                            url,
                        })) if c == channel_id => return Some(url),
                        Some(_) => {}
                        None => return None,
                    }
                }
            })
            .await
            {
                Ok(Some(url)) => {
                    // And what it carries, which the node says right after it (V210-96).
                    let mut note = String::new();
                    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(1);
                    while let Ok(Some(item)) =
                        tokio::time::timeout_at(deadline, events.next()).await
                    {
                        if let EventStreamItem::Event(NodeEvent::AddressNote {
                            channel_id: c,
                            note: said,
                        }) = item
                        {
                            if c == channel_id {
                                note = said;
                                break;
                            }
                        }
                    }
                    Frame::Link { url, note }
                }
                Ok(None) => Frame::Error {
                    reason: "the node stopped before the link was minted".into(),
                },
                Err(_) => Frame::Error {
                    reason: "the node did not mint a link".into(),
                },
            }
        }
        Request::Rooms { after } => {
            let view = handle.view();
            let rooms = view
                .channels
                .iter()
                .map(|c| {
                    (
                        c.channel_id,
                        c.name.clone().unwrap_or_default(),
                        c.open,
                        c.over.clone().unwrap_or_default(),
                    )
                })
                .collect();
            Frame::Rooms {
                rooms: page(rooms, after, |(id, name, _, over)| {
                    (*id, name.len() + over.len())
                }),
            }
        }
    }
}

/// Forward a subscription to a client until the client goes away or the node
/// stops. Any write failure ends **this** connection and nothing else — a client
/// that died mid-stream shows up as `BrokenPipe` here (measured).
async fn pump(mut stream: UnixStream, mut events: EventStream) -> Result<()> {
    loop {
        // **A subscriber that hangs up is noticed on a quiet node too**: waiting only on events
        // left its connection — and the hold it carries on its node (ADR-026 L-3) — open until
        // the node next said something, which on a quiet node is never, so an auto-started daemon
        // never reached its idle exit (L-8).
        let item = tokio::select! {
            item = events.next() => item,
            () = subscriber_gone(&stream) => return Ok(()),
        };
        let Some(item) = item else {
            return Ok(());
        };
        let frame = match item {
            EventStreamItem::Event(ev) => Frame::Event(ev),
            EventStreamItem::Lagged(missed) => Frame::Lagged { missed },
        };
        if write_frame(&mut stream, &frame.to_bytes()).await.is_err() {
            return Ok(());
        }
    }
}

/// Resolves once the client of a subscription has gone: its end of `stream` is closed or failed.
/// A subscriber sends nothing after subscribing; anything it does send is read and dropped.
pub(crate) async fn subscriber_gone(stream: &UnixStream) {
    let mut buf = [0u8; 256];
    loop {
        if stream.readable().await.is_err() {
            return;
        }
        match stream.try_read(&mut buf) {
            Ok(0) => return,
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(_) => return,
        }
    }
}

// ---- client ----------------------------------------------------------------

/// A connected client of a node's control socket.
#[derive(Debug)]
pub struct IpcClient {
    stream: UnixStream,
    me: Option<Digest32>,
    /// Where the node listens, so a request that waits can check it is still answering.
    path: PathBuf,
    /// The node this connection acts as on the daemon's socket (ADR-026 C-2), which a check on a
    /// waiting request names in its own `Use`; `None` for a node's own socket.
    node: Option<crate::node::paths::NodeName>,
    /// What attaching the node said, when this connection's `Use` attached it.
    notes: Vec<String>,
}

/// Where a client of the daemon reaches its node (ADR-026 C-2): the account's one socket, and the
/// `Use` every connection to it opens with. A CLI process acts as one node, so every connection it
/// makes carries the same `Use`.
#[derive(Clone)]
pub struct NodeSocket {
    /// `<data root>/.daemon/vox.sock`.
    pub path: PathBuf,
    /// What each connection opens with.
    pub using: crate::node::daemonipc::UseNode,
    /// Called once if the daemon has not greeted within a second
    /// ([`crate::node::daemonipc::DaemonClient::open_noting`]); the caller says the wait where its
    /// user sees it.
    pub waiting: Option<fn()>,
}

impl std::fmt::Debug for NodeSocket {
    // Not derived: the `Use` may carry a passphrase.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeSocket")
            .field("path", &self.path)
            .field("node", &self.using.node)
            .field("attach", &self.using.attach)
            .finish_non_exhaustive()
    }
}

impl NodeSocket {
    /// A one-shot verb's socket: the node must be attached already (ADR-026 L-2).
    #[must_use]
    pub fn one_shot(path: PathBuf, node: crate::node::paths::NodeName) -> Self {
        Self {
            path,
            using: crate::node::daemonipc::UseNode {
                node,
                attach: crate::node::daemonipc::AttachMode::No,
                passphrase: None,
                anchors: Vec::new(),
            },
            waiting: None,
        }
    }

    /// The same node, for a connection that must not attach it: what a check on a waiting request
    /// opens, and every connection after the first of a held verb, whose first holds it.
    #[must_use]
    pub fn attached_only(&self) -> Self {
        Self {
            waiting: self.waiting,
            ..Self::one_shot(self.path.clone(), self.using.node.clone())
        }
    }
}

/// Open a connection to the daemon at `at.path` acting as `at.using.node`: read the daemon's hello,
/// send the `Use`, and read `Using`. Returns the connection, ready for node-level requests, and the
/// node's fingerprint.
///
/// # Errors
/// As [`crate::node::daemonipc::DaemonClient::open`]; [`IpcHandshake::Refused`], in the daemon's
/// words, when it refuses the `Use`; [`IpcHandshake::NotHello`] for any other answer.
pub async fn open_as(at: &NodeSocket) -> Result<(UnixStream, Option<Digest32>)> {
    open_as_noting(at).await.map(|(s, me, _)| (s, me))
}

/// [`open_as`], with what attaching the node said when this `Use` attached it.
///
/// # Errors
/// As [`open_as`].
pub async fn open_as_noting(
    at: &NodeSocket,
) -> Result<(UnixStream, Option<Digest32>, Vec<String>)> {
    use crate::node::daemonipc::{DaemonClient, DaemonFrame, Opening};
    let DaemonClient { mut stream, .. } = DaemonClient::open_noting(&at.path, at.waiting).await?;
    // Wiped once sent: it may carry the identity passphrase (C-6).
    let opening = zeroize::Zeroizing::new(Opening::Use(at.using.clone()).to_bytes());
    if let Err(e) = write_frame(&mut stream, &opening).await {
        return Err(named(&at.path, e).await);
    }
    drop(opening);
    let Some(answer) = read_frame(&mut stream).await? else {
        return Err(hung_up(&at.path).await);
    };
    match DaemonFrame::from_bytes(&answer)? {
        DaemonFrame::Using { me, notes, .. } => Ok((stream, me, notes)),
        DaemonFrame::Refused(r) => Err(Error::Ipc(IpcHandshake::Refused {
            reason: r.to_string(),
        })),
        _ => Err(Error::Ipc(IpcHandshake::NotHello)),
    }
}

/// Connect to the control socket at `path` only if it is this user's own (V210-72).
///
/// A client sends the node passphrases, so it checks before connecting that `path` is a
/// socket owned by this uid — not a symlink, not another user's — and after connecting
/// that the process serving it runs as this uid too. Another user can satisfy neither.
///
/// # Errors
/// [`IpcHandshake::Unreachable`] if nothing is there or nothing listens;
/// [`IpcHandshake::NotYours`] if it, or what serves it, belongs to someone else.
pub async fn connect_own(path: &Path) -> Result<UnixStream> {
    // **Root is refused before anything is tried** (ADR-026 C-1): the daemon admits no uid 0, so a
    // root client was dropped without a word, and `vox serve` waited out its start bound and blamed
    // the daemon's start.
    if crate::node::paths::my_uid() == 0 {
        return Err(Error::Ipc(IpcHandshake::Root));
    }
    let unreachable = |e: std::io::Error| {
        Error::Ipc(IpcHandshake::Unreachable {
            reason: e.to_string(),
        })
    };
    std::fs::symlink_metadata(path).map_err(unreachable)?;
    crate::node::paths::check_socket_owner(path).map_err(|e| {
        Error::Ipc(IpcHandshake::NotYours {
            detail: match e {
                Error::Path { detail, .. } => detail,
                other => other.to_string(),
            },
        })
    })?;
    let stream = UnixStream::connect(path).await.map_err(unreachable)?;
    let me = crate::node::paths::my_uid();
    match stream.peer_cred() {
        Ok(c) if c.uid() == me => Ok(stream),
        Ok(c) => Err(Error::Ipc(IpcHandshake::NotYours {
            detail: format!(
                "{} is served by uid {}, not by you (uid {me})",
                path.display(),
                c.uid()
            ),
        })),
        // **A peer that has already hung up cannot be asked who it is** (V210-72): macOS's
        // LOCAL_PEERCRED answers ENOTCONN once the server has closed, and that was reported as
        // a refusal where the truth is "the node closed the connection before greeting". Only
        // a peer that is provably gone falls through — nothing sent on this connection can
        // reach anyone — and the caller then reports what it reads. A live peer that will not
        // say who it is stays refused.
        Err(_) if peer_is_gone(&stream) => Ok(stream),
        Err(e) => Err(Error::Ipc(IpcHandshake::NotYours {
            detail: format!("cannot tell who serves {}: {e}", path.display()),
        })),
    }
}

/// Whether the other end of `stream` has hung up: the socket reports a hang-up, or a peek
/// finds the end of the stream. Neither consumes anything the peer sent before it went.
fn peer_is_gone(stream: &UnixStream) -> bool {
    use rustix::event::{poll, PollFd, PollFlags, Timespec};
    use rustix::net::{recv, RecvFlags};
    let mut fds = [PollFd::new(stream, PollFlags::IN)];
    let now = Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    if poll(&mut fds, Some(&now)).is_ok() && fds[0].revents().contains(PollFlags::HUP) {
        return true;
    }
    let mut byte = [0u8; 1];
    matches!(
        recv(stream, &mut byte, RecvFlags::PEEK | RecvFlags::DONTWAIT),
        Ok((_, 0))
    )
}

impl IpcClient {
    /// This client's own identity fingerprint, as the node reported it at hello,
    /// or `None` if the node has no identity yet.
    ///
    /// This is what lets a client tell its own claims from everyone else's.
    #[must_use]
    pub fn me(&self) -> Option<Digest32> {
        self.me
    }

    /// Connect to the daemon's socket at `path` and act as the node `using.node` (ADR-026 C-2):
    /// read the daemon's hello, send the `Use`, and read its answer. `Ok(Err(refusal))` is the
    /// daemon's answer, not a failure to reach it: a node not attached for a one-shot verb, a
    /// wrong passphrase.
    ///
    /// # Errors
    /// As [`crate::node::daemonipc::DaemonClient::open`], or if the daemon answers the `Use`
    /// with anything but `Using` or `Refused`.
    pub async fn open_node(
        path: &Path,
        using: crate::node::daemonipc::UseNode,
    ) -> Result<std::result::Result<Self, crate::node::daemonipc::Refusal>> {
        use crate::node::daemonipc::{DaemonClient, DaemonFrame, Opening};
        let DaemonClient { mut stream, .. } = DaemonClient::open(path).await?;
        write_frame(&mut stream, &Opening::Use(using).to_bytes()).await?;
        let Some(answer) = read_frame(&mut stream).await? else {
            return Err(Error::Ipc(IpcHandshake::ClosedBeforeHello));
        };
        match DaemonFrame::from_bytes(&answer)? {
            DaemonFrame::Using { me, node, notes } => Ok(Ok(Self {
                stream,
                me,
                path: path.to_owned(),
                node: Some(node),
                notes,
            })),
            DaemonFrame::Refused(r) => Ok(Err(r)),
            _ => Err(Error::Ipc(IpcHandshake::NotHello)),
        }
    }

    /// Wait until the daemon ends this connection: it closed it, or said the node detached
    /// (ADR-026 L-7). Only for a connection held without requests in flight.
    pub async fn closed(&mut self) {
        while let Ok(Some(body)) = read_frame(&mut self.stream).await {
            if matches!(Frame::from_bytes(&body), Ok(Frame::NodeDetached { .. })) {
                return;
            }
        }
    }

    /// Connect and check the protocol version, without subscribing.
    ///
    /// Use this for a client that issues requests. [`IpcClient::subscribe`] turns
    /// the connection into an event stream, after which no further request can be
    /// sent on it.
    pub async fn open(path: &Path) -> Result<Self> {
        // **Bounded** (V210-83): a node greets the moment it accepts, off its actor, and one
        // that does not is suspended or stuck. Every verb that attaches waited for ever on it.
        // The bound covers `connect_own` too, so the owner and peer checks (#263) stay first.
        let (stream, hello) = tokio::time::timeout(ANSWER_WITHIN, async {
            let mut stream = connect_own(path).await?;
            let hello = read_frame(&mut stream).await?;
            Ok::<_, Error>((stream, hello))
        })
        .await
        .map_err(|_| silent())??;
        let Some(hello) = hello else {
            return Err(Error::Ipc(IpcHandshake::ClosedBeforeHello));
        };
        let me = match Frame::from_bytes(&hello)? {
            Frame::Hello { protocol, me } if protocol == PROTOCOL_VERSION => me,
            Frame::Hello { protocol, .. } => {
                return Err(Error::Ipc(IpcHandshake::Protocol {
                    mine: PROTOCOL_VERSION,
                    theirs: protocol,
                }))
            }
            _ => return Err(Error::Ipc(IpcHandshake::NotHello)),
        };
        Ok(Self {
            stream,
            me,
            path: path.to_owned(),
            node: None,
            notes: Vec::new(),
        })
    }

    /// Connect to the daemon at `at` acting as its node ([`open_as`]).
    ///
    /// # Errors
    /// As [`open_as`].
    pub async fn open_at(at: &NodeSocket) -> Result<Self> {
        let (stream, me, notes) = open_as_noting(at).await?;
        Ok(Self {
            stream,
            me,
            path: at.path.clone(),
            node: Some(at.using.node.clone()),
            notes,
        })
    }

    /// What attaching the node said, when this connection's `Use` attached it: for a verb that
    /// holds a session to print in the person's own terminal (PRD-001 R23, R36).
    #[must_use]
    pub fn attach_notes(&self) -> &[String] {
        &self.notes
    }

    /// Send one request and read its answer.
    ///
    /// A [`Frame::Error`] is returned as `Ok(Frame::Error { .. })`, not as an
    /// `Err`: "this room is not open" is an answer, and the connection stays
    /// usable for the next question.
    ///
    /// **Bounded by the node's liveness, not by a length of time** (V210-83). Only the greeting
    /// was bounded, so a node suspended, or whose actor stuck, after it greeted left every request
    /// waiting for ever. A join or a passphrase check may rightly take minutes, so no fixed wait
    /// fits every request; instead, while one waits, the node is asked every [`ANSWER_WITHIN`]
    /// whether it is still greeting and its actor still taking commands ([`ACTOR_WITHIN`]), and
    /// the request fails, naming which, once it is not.
    pub async fn request(&mut self, req: &Request) -> Result<Frame> {
        let Self {
            stream, path, node, ..
        } = self;
        let exchange = async {
            // Wiped once sent: it may carry a passphrase (V210-94).
            if let Err(e) = write_frame(stream, &zeroize::Zeroizing::new(req.to_bytes())).await {
                return Err(named(path, e).await);
            }
            let Some(body) = read_frame(stream).await? else {
                return Err(hung_up(path).await);
            };
            Frame::from_bytes(&body)
        };
        while_answering(path, node.as_ref(), exchange).await
    }

    /// Send one request body this module has no [`Request`] for — a status, a tunnel close, a
    /// snapshot ([`crate::node::snapshot`]) — and return the one reply body, bounded as
    /// [`IpcClient::request`] is.
    ///
    /// # Errors
    /// If the node cannot be reached, or hangs up before it answers.
    pub async fn exchange(&mut self, body: &[u8]) -> Result<Vec<u8>> {
        let Self {
            stream, path, node, ..
        } = self;
        let exchange = async {
            if let Err(e) = write_frame(stream, body).await {
                return Err(named(path, e).await);
            }
            match read_frame(stream).await? {
                Some(reply) => Ok(reply),
                None => Err(hung_up(path).await),
            }
        };
        while_answering(path, node.as_ref(), exchange).await
    }

    /// Every row after `since`, however many replies that takes — as one
    /// [`Frame::Rows`], or the first reply that was not rows (an error).
    ///
    /// A reply is bounded by bytes (see [`ROWS_BUDGET`]), so a room's history comes in
    /// pages; this asks again from the last row until a reply is empty.
    ///
    /// # Errors
    /// If the node cannot be reached or answers with a malformed frame.
    pub async fn read_rows(
        &mut self,
        channel_id: Digest32,
        since: Option<Digest32>,
    ) -> Result<Frame> {
        // A read from a cursor is a feed by arrival, so its next page follows the last row
        // as a cursor. A read of the whole room is in the room's order, so its next page
        // follows the last row as a page mark: as a cursor it would become that feed, and
        // lose every late arrival above the page boundary.
        let mut all = Vec::new();
        let (mut cursor, mut mark) = (since, None);
        loop {
            match self
                .request(&Request::Read {
                    channel_id,
                    since: cursor,
                    after: mark,
                    limit: 0,
                })
                .await?
            {
                Frame::Rows { rows } => {
                    let Some(last) = rows.last() else {
                        return Ok(Frame::Rows { rows: all });
                    };
                    // A page that ends where the last one did would be asked for again
                    // forever; a node that ignored the cursor or the mark is an error, not a hang.
                    let marker = if since.is_some() {
                        &mut cursor
                    } else {
                        &mut mark
                    };
                    if *marker == Some(last.entry_hash) {
                        return Err(Error::MalformedIpc("ipc rows page did not advance"));
                    }
                    *marker = Some(last.entry_hash);
                    all.extend(rows);
                }
                other => return Ok(other),
            }
        }
    }

    /// A room's structured posts of `types`, and those whose operation id is in `ops`, however
    /// many replies that takes ([`Request::Structured`], V210-120). Rows matched by an id's hash
    /// alone are included: filter on the id.
    ///
    /// # Errors
    /// If the node cannot be reached or answers with a malformed frame.
    pub async fn read_structured(
        &mut self,
        channel_id: Digest32,
        types: &[&str],
        ops: &[String],
    ) -> Result<Frame> {
        let mut all = Vec::new();
        let mut cursor = None;
        loop {
            match self
                .request(&Request::Structured {
                    channel_id,
                    types: types.iter().map(|t| (*t).to_owned()).collect(),
                    ops: ops.to_vec(),
                    since: cursor,
                })
                .await?
            {
                Frame::Rows { rows } => {
                    let Some(last) = rows.last() else {
                        return Ok(Frame::Rows { rows: all });
                    };
                    if cursor == Some(last.entry_hash) {
                        return Err(Error::MalformedIpc("ipc rows page did not advance"));
                    }
                    cursor = Some(last.entry_hash);
                    all.extend(rows);
                }
                other => return Ok(other),
            }
        }
    }

    /// Every room this node holds, however many pages that takes — as one
    /// [`Frame::Rooms`], or the first reply that was not rooms (an error).
    ///
    /// # Errors
    /// If the node cannot be reached or answers with a malformed frame.
    pub async fn rooms(&mut self) -> Result<Frame> {
        let mut all = Vec::new();
        let mut after = None;
        loop {
            match self.request(&Request::Rooms { after }).await? {
                Frame::Rooms { rooms } => {
                    let Some(last) = rooms.last() else {
                        return Ok(Frame::Rooms { rooms: all });
                    };
                    if after.is_some_and(|a| last.0 <= a) {
                        return Err(Error::MalformedIpc("ipc rooms page did not advance"));
                    }
                    after = Some(last.0);
                    all.extend(rooms);
                }
                other => return Ok(other),
            }
        }
    }

    /// The whole trust keyring, however many pages that takes — as one
    /// [`Frame::Trusted`], or the first reply that was not (an error).
    ///
    /// # Errors
    /// If the node cannot be reached or answers with a malformed frame.
    pub async fn trusted(&mut self, identity_passphrase: &str) -> Result<Frame> {
        let mut all = Vec::new();
        let mut after = None;
        loop {
            match self
                .request(&Request::TrustList {
                    identity_passphrase: zeroize::Zeroizing::new(identity_passphrase.to_owned()),
                    after,
                })
                .await?
            {
                Frame::Trusted { entries } => {
                    let Some(last) = entries.last() else {
                        return Ok(Frame::Trusted { entries: all });
                    };
                    if after.is_some_and(|a| last.0 <= a) {
                        return Err(Error::MalformedIpc("ipc trusted page did not advance"));
                    }
                    after = Some(last.0);
                    all.extend(entries);
                }
                other => return Ok(other),
            }
        }
    }

    /// Turn this connection into an event stream. Terminal: no further request
    /// may be sent on it.
    pub async fn subscribe(&mut self) -> Result<()> {
        match self.request(&Request::Subscribe).await? {
            Frame::Ok => Ok(()),
            Frame::Error { reason } => {
                let _ = reason;
                Err(Error::MalformedIpc("ipc subscribe refused"))
            }
            _ => Err(Error::MalformedIpc("ipc unexpected subscribe reply")),
        }
    }

    /// Connect, check the protocol version, and subscribe — [`open`](Self::open)
    /// followed by [`subscribe`](Self::subscribe), for a client that only wants
    /// the event stream.
    pub async fn connect(path: &Path) -> Result<Self> {
        let mut client = Self::open(path).await?;
        client.subscribe().await?;
        Ok(client)
    }

    /// The next frame, or `None` once the node has gone.
    pub async fn next(&mut self) -> Result<Option<Frame>> {
        match read_frame(&mut self.stream).await? {
            Some(body) => Ok(Some(Frame::from_bytes(&body)?)),
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod account_socket_tests {
    /// The account socket admits its own user only, and never root, even a daemon run as root
    /// (ADR-026 C-1, S-5).
    #[test]
    fn only_the_same_user_and_never_root() {
        assert!(super::admitted(Some(501), 501));
        assert!(!super::admitted(Some(502), 501));
        assert!(!super::admitted(None, 501));
        assert!(
            !super::admitted(Some(0), 0),
            "PRODUCT: the account socket admitted uid 0"
        );
    }
}
