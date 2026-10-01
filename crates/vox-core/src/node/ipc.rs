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
//! [`Secret`](super::api::Secret) — passphrases — and reaches `CreateIdentity`,
//! `Revoke` and `PassphraseRotate`. An agent session runs model-authored code and
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
pub const PROTOCOL_VERSION: u64 = 5;

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
pub const TEST_MAX_FRAME_ENV: &str = "VOX_TEST_MAX_FRAME";

/// The smallest frame [`TEST_MAX_FRAME_ENV`] may set: half of it still carries the largest room
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
const T_UNLOCKED: u64 = 11;
const T_LOCKED: u64 = 12;
const T_CHANNEL_OPENED: u64 = 13;
const T_CHANNEL_CLOSED: u64 = 14;
const T_PEER_JOINED: u64 = 15;
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
const T_OK: u64 = 3;
const T_ERROR: u64 = 4;
const T_ROWS: u64 = 5;
const T_MEMBERS: u64 = 6;
const T_ROOMS: u64 = 7;

const T_BOUND: u64 = 8;
const T_LINK: u64 = 9;
/// Protocol 5. 8 and 9 were taken (`T_BOUND`, `T_LINK`), which a first attempt at this
/// collided with — the decoder then read a trusted list as a bound address and said
/// "malformed identity bundle", three layers from the cause.
const T_TRUSTED: u64 = 26;
// Client → node.
const T_SUBSCRIBE: u64 = 1;
const T_POST: u64 = 2;
const T_READ: u64 = 3;
const T_ROSTER: u64 = 4;
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
// So the door opens only for someone who can prove they hold the identity passphrase,
// which the operator does and the agent does not. The socket's file mode is still the
// outer boundary; this is the inner one.
const T_TRUST: u64 = 14;
const T_UNTRUST: u64 = 15;
const T_TRUST_LIST: u64 = 16;
// **Liveness** (V210-83). Answered by the actor and changes nothing, so a client waiting on a long
// request can tell a node at work from a suspended or stuck one. Not a protocol bump: a node that
// does not know it answers with an error, and any answer is proof of life.
const T_PING: u64 = 17;

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
    /// Append a message to a room.
    Post {
        /// The room.
        channel_id: Digest32,
        /// The message text (an agent-comms envelope is JSON in here).
        text: String,
    },
    /// Read a room's rendered timeline, optionally only what follows a cursor.
    Read {
        /// The room.
        channel_id: Digest32,
        /// Return only entries **after** this one. Absent reads from the start.
        since: Option<Digest32>,
        /// Cap on rows returned; 0 means no cap.
        limit: u64,
    },
    /// The members of a room.
    Roster {
        /// The room.
        channel_id: Digest32,
    },
    /// The rooms this node holds, in room-id order, after `after` — one page of them.
    /// [`IpcClient::rooms`] asks for every page.
    Rooms {
        /// The last room of the previous page, or `None` for the first.
        after: Option<Digest32>,
    },
    /// Offer a local TCP endpoint as a room-bound service (ADR-013), for as long as this
    /// connection stays open: it is withdrawn when the connection closes, however the client
    /// ends, and never persisted (V210-72). A [`Request::Forward`] likewise.
    AddService {
        /// The room.
        channel_id: Digest32,
        /// The service's tag, which is also how members name it.
        service_tag: String,
        /// The local endpoint to carry connections to.
        local: String,
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
        /// A local name for the room; never leaves this device.
        local_name: String,
        /// The room's passphrase, which the link does not carry.
        passphrase: String,
    },
    /// Create a room on this node.
    Create {
        /// A local name for the room; never leaves this device.
        local_name: String,
        /// The room's passphrase.
        passphrase: String,
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
    /// Add an identity to the trust keyring. Requires the identity passphrase.
    Trust {
        /// Who to trust, as a full fingerprint.
        target: Digest32,
        /// The petname to file it under.
        petname: String,
        /// The identity passphrase, proving this is the operator and not an agent.
        identity_passphrase: String,
    },
    /// Remove an identity from the trust keyring. Requires the identity passphrase.
    Untrust {
        /// Who to stop trusting.
        target: Digest32,
        /// The identity passphrase.
        identity_passphrase: String,
    },
    /// Read the trust keyring. Requires the identity passphrase.
    TrustList {
        /// The identity passphrase.
        identity_passphrase: String,
        /// The last fingerprint of the previous page, or `None` for the first.
        after: Option<Digest32>,
    },
    /// Answered `Ok` by the node's actor, changing nothing: proof it is taking commands.
    Ping,
}

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
            Request::Post { channel_id, text } => {
                e.array(3).uint(T_POST).bytes(channel_id).text(text);
            }
            Request::Read {
                channel_id,
                since,
                limit,
            } => {
                e.array(4)
                    .uint(T_READ)
                    .bytes(channel_id)
                    // An absent cursor is the empty byte string, so the arity is
                    // fixed — ADR-008's canonical encoding has no optionals.
                    .bytes(since.as_ref().map_or(&[][..], |d| &d[..]))
                    .uint(*limit);
            }
            Request::Roster { channel_id } => {
                e.array(2).uint(T_ROSTER).bytes(channel_id);
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
            } => {
                e.array(4)
                    .uint(T_ADD_SERVICE)
                    .bytes(channel_id)
                    .text(service_tag)
                    .text(local);
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
            Request::Join {
                link,
                local_name,
                passphrase,
            } => {
                e.array(4)
                    .uint(T_JOIN)
                    .text(link)
                    .text(local_name)
                    .text(passphrase);
            }
            Request::Create {
                local_name,
                passphrase,
            } => {
                e.array(3).uint(T_CREATE).text(local_name).text(passphrase);
            }
            Request::Invite { channel_id } => {
                e.array(2).uint(T_INVITE).bytes(channel_id);
            }
            Request::Trust {
                target,
                petname,
                identity_passphrase,
            } => {
                e.array(4)
                    .uint(T_TRUST)
                    .bytes(target)
                    .text(petname)
                    .text(identity_passphrase);
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
            (T_POST, 3) => {
                let channel_id = digest(&mut d)?;
                let text = d
                    .text()
                    .map_err(|_| Error::MalformedIpc("ipc post text"))?
                    .to_owned();
                d.finish()
                    .map_err(|_| Error::MalformedIpc("ipc request trailing"))?;
                Ok(Request::Post { channel_id, text })
            }
            (T_READ, 4) => {
                let channel_id = digest(&mut d)?;
                let cursor = d.bytes().map_err(|_| Error::MalformedIpc("ipc cursor"))?;
                let since = if cursor.is_empty() {
                    None
                } else {
                    Some(
                        Digest32::try_from(cursor)
                            .map_err(|_| Error::MalformedIpc("ipc cursor length"))?,
                    )
                };
                let limit = d.uint().map_err(|_| Error::MalformedIpc("ipc limit"))?;
                d.finish()
                    .map_err(|_| Error::MalformedIpc("ipc request trailing"))?;
                Ok(Request::Read {
                    channel_id,
                    since,
                    limit,
                })
            }
            (T_ROSTER, 2) => {
                let channel_id = digest(&mut d)?;
                d.finish()
                    .map_err(|_| Error::MalformedIpc("ipc request trailing"))?;
                Ok(Request::Roster { channel_id })
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
            (T_TRUST, 4) => {
                let target = digest(&mut d)?;
                let petname = text(&mut d, "ipc petname")?;
                let mut identity_passphrase = secret_text(&mut d, "ipc identity passphrase")?;
                d.finish()
                    .map_err(|_| Error::MalformedIpc("ipc request trailing"))?;
                Ok(Request::Trust {
                    target,
                    petname,
                    identity_passphrase: std::mem::take(&mut *identity_passphrase),
                })
            }
            (T_UNTRUST, 3) => {
                let target = digest(&mut d)?;
                let mut identity_passphrase = secret_text(&mut d, "ipc identity passphrase")?;
                d.finish()
                    .map_err(|_| Error::MalformedIpc("ipc request trailing"))?;
                Ok(Request::Untrust {
                    target,
                    identity_passphrase: std::mem::take(&mut *identity_passphrase),
                })
            }
            // The unpaged form, as for `Rooms` above.
            (T_TRUST_LIST, 2) => {
                let mut identity_passphrase = secret_text(&mut d, "ipc identity passphrase")?;
                d.finish()
                    .map_err(|_| Error::MalformedIpc("ipc request trailing"))?;
                Ok(Request::TrustList {
                    identity_passphrase: std::mem::take(&mut *identity_passphrase),
                    after: None,
                })
            }
            (T_TRUST_LIST, 3) => {
                let mut identity_passphrase = secret_text(&mut d, "ipc identity passphrase")?;
                let after = optional_digest(&mut d)?;
                d.finish()
                    .map_err(|_| Error::MalformedIpc("ipc request trailing"))?;
                Ok(Request::TrustList {
                    identity_passphrase: std::mem::take(&mut *identity_passphrase),
                    after,
                })
            }
            (T_ADD_SERVICE, 4) => {
                let channel_id = digest(&mut d)?;
                let service_tag = text(&mut d, "ipc service tag")?;
                let local = text(&mut d, "ipc local address")?;
                d.finish()
                    .map_err(|_| Error::MalformedIpc("ipc request trailing"))?;
                Ok(Request::AddService {
                    channel_id,
                    service_tag,
                    local,
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
            (T_JOIN, 4) => {
                let link = text(&mut d, "ipc join link")?;
                let local_name = text(&mut d, "ipc join name")?;
                let mut passphrase = secret_text(&mut d, "ipc join passphrase")?;
                d.finish()
                    .map_err(|_| Error::MalformedIpc("ipc request trailing"))?;
                Ok(Request::Join {
                    link,
                    local_name,
                    passphrase: std::mem::take(&mut *passphrase),
                })
            }
            (T_CREATE, 3) => {
                let local_name = text(&mut d, "ipc create name")?;
                let mut passphrase = secret_text(&mut d, "ipc create passphrase")?;
                d.finish()
                    .map_err(|_| Error::MalformedIpc("ipc request trailing"))?;
                Ok(Request::Create {
                    local_name,
                    passphrase: std::mem::take(&mut *passphrase),
                })
            }
            (T_INVITE, 2) => {
                let channel_id = digest(&mut d)?;
                d.finish()
                    .map_err(|_| Error::MalformedIpc("ipc request trailing"))?;
                Ok(Request::Invite { channel_id })
            }
            _ => Err(Error::UnknownIpcRequest),
        }
    }
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
    /// A request succeeded and carries nothing further.
    Ok,
    /// A request failed. The reason is for a person to read, not to branch on.
    Error {
        /// Why it failed.
        reason: String,
    },
    /// The rows a [`Request::Read`] asked for, oldest first.
    Rows {
        /// The rendered entries.
        rows: Vec<MessageRow>,
    },
    /// The members a [`Request::Roster`] asked for.
    Members {
        /// Member fingerprints, in the order the node holds them.
        members: Vec<Digest32>,
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
        /// `(fingerprint, petname)` in fingerprint order.
        entries: Vec<(Digest32, String)>,
    },
    /// The rooms a [`Request::Rooms`] asked for.
    Rooms {
        /// `(channel_id, local name, open)` per room.
        rooms: Vec<(Digest32, String, bool)>,
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
            Frame::Ok => {
                e.array(1).uint(T_OK);
            }
            Frame::Error { reason } => {
                e.array(2).uint(T_ERROR).text(reason);
            }
            Frame::Rows { rows } => {
                e.array(2).uint(T_ROWS).array(rows.len());
                for r in rows {
                    e.array(4)
                        .bytes(&r.entry_hash)
                        .bytes(&r.author)
                        .uint(r.created_millis)
                        .text(&r.text);
                }
            }
            Frame::Members { members } => {
                e.array(2).uint(T_MEMBERS).array(members.len());
                for m in members {
                    e.bytes(m);
                }
            }
            Frame::Bound { local } => {
                e.array(2).uint(T_BOUND).text(local);
            }
            Frame::Link { url, note } if note.is_empty() => {
                e.array(2).uint(T_LINK).text(url);
            }
            Frame::Link { url, note } => {
                e.array(3).uint(T_LINK).text(url).text(note);
            }
            Frame::Rooms { rooms } => {
                e.array(2).uint(T_ROOMS).array(rooms.len());
                for (id, name, open) in rooms {
                    e.array(3).bytes(id).text(name).uint(u64::from(*open));
                }
            }
            Frame::Trusted { entries } => {
                e.array(2).uint(T_TRUSTED).array(entries.len());
                for (id, petname) in entries {
                    e.array(2).bytes(id).text(petname);
                }
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

/// A passphrase field, decoded into a buffer that is wiped when dropped (V210-94): a request that
/// fails to decode after it is returns an error, and a plain `String` would free a copy unwiped.
/// Moved out with [`std::mem::take`] once the whole request has decoded.
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
            e.array(6)
                .uint(T_NEW_ENTRY)
                .bytes(channel_id)
                .bytes(&row.entry_hash)
                .bytes(&row.author)
                .uint(row.created_millis)
                .text(&row.text);
        }
        NodeEvent::Unlocked => {
            e.array(1).uint(T_UNLOCKED);
        }
        NodeEvent::WaitingForProfile => {
            e.array(1).uint(T_WAITING_FOR_PROFILE);
        }
        NodeEvent::Locked => {
            e.array(1).uint(T_LOCKED);
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
        (T_ROWS, 2) => {
            let n = d.array().map_err(|_| Error::MalformedIpc("ipc rows"))?;
            let mut rows = Vec::with_capacity(n.min(1024));
            for _ in 0..n {
                let arity = d.array().map_err(|_| Error::MalformedIpc("ipc row"))?;
                if arity != 4 {
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
                });
            }
            return Ok(Frame::Rows { rows });
        }
        (T_MEMBERS, 2) => {
            let n = d.array().map_err(|_| Error::MalformedIpc("ipc members"))?;
            let mut members = Vec::with_capacity(n.min(1024));
            for _ in 0..n {
                members.push(digest(d)?);
            }
            return Ok(Frame::Members { members });
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
                if arity != 3 {
                    return Err(Error::MalformedIpc("ipc room arity"));
                }
                let id = digest(d)?;
                let name = d
                    .text()
                    .map_err(|_| Error::MalformedIpc("ipc room name"))?
                    .to_owned();
                let open = d.uint().map_err(|_| Error::MalformedIpc("ipc room open"))? != 0;
                rooms.push((id, name, open));
            }
            return Ok(Frame::Rooms { rooms });
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
                if arity != 2 {
                    return Err(Error::MalformedIpc("ipc trusted row arity"));
                }
                let id = digest(d)?;
                let petname = d
                    .text()
                    .map_err(|_| Error::MalformedIpc("ipc trusted petname"))?
                    .to_owned();
                entries.push((id, petname));
            }
            return Ok(Frame::Trusted { entries });
        }
        (T_NEW_ENTRY, 6) => {
            let channel_id = digest(d)?;
            let entry_hash = digest(d)?;
            let author = digest(d)?;
            let created_millis = d.uint().map_err(|_| Error::MalformedIpc("ipc millis"))?;
            let text = d
                .text()
                .map_err(|_| Error::MalformedIpc("ipc text"))?
                .to_owned();
            NodeEvent::NewEntry {
                channel_id,
                row: MessageRow {
                    entry_hash,
                    author,
                    created_millis,
                    text,
                },
            }
        }
        (T_UNLOCKED, 1) => NodeEvent::Unlocked,
        (T_WAITING_FOR_PROFILE, 1) => NodeEvent::WaitingForProfile,
        (T_LOCKED, 1) => NodeEvent::Locked,
        (T_SHUTDOWN, 1) => NodeEvent::Shutdown,
        (T_CHANNEL_OPENED, 2) => NodeEvent::ChannelOpened {
            channel_id: digest(d)?,
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
        (T_CONNECTION_NOTE, 3) => NodeEvent::ConnectionNote {
            peer: digest(d)?,
            note: d
                .text()
                .map_err(|_| Error::MalformedIpc("ipc connection note"))?
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
        // unlink, which `bind_at` does anyway.
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
pub async fn hung_up(path: &Path) -> Error {
    let still_running = matches!(
        tokio::time::timeout(ANSWER_WITHIN, connect_own(path)).await,
        Ok(Ok(_))
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
                still_answering(path).await
            } => alive?,
        }
    }
}

/// Whether the node at `path` greets a new connection and its actor answers a ping, or why not.
async fn still_answering(path: &Path) -> Result<()> {
    let mut probe = match IpcClient::open(path).await {
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

/// Bind the control socket at `path` and serve `handle`'s event stream to every
/// client that connects.
///
/// The directory is made private to this user first ([`prepare_socket_dir`]), and one that
/// is not is refused: whoever owns the directory can replace the socket in it.
///
/// The stale socket file of a process that died is **unlinked first**: `bind`
/// fails with `AddrInUse` otherwise (measured), and inheriting that error would
/// report a dead predecessor as a live conflict. The socket is bound under a staging
/// name and chmod'd to `0600` there — `bind` itself yields `0755` from the umask (also
/// measured), so this is load-bearing, not decoration — and only then renamed to `path`,
/// so `path` is never a socket at any other mode (V210-72).
///
/// [`prepare_socket_dir`]: crate::node::paths::prepare_socket_dir
pub fn bind_at(handle: NodeHandle, path: PathBuf) -> Result<IpcServer> {
    crate::node::paths::prepare_socket_dir(&path)?;
    // Never longer than `path`, so it fits wherever `path` does.
    let staging = path.with_extension("new");
    for stale in [&staging, &path] {
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
                std::fs::rename(&staging, &path).map_err(|e| Error::Path {
                    op: "place control socket",
                    detail: format!("{}: {e}", path.display()),
                })
            })
    };
    if let Err(e) = placed {
        let _ = std::fs::remove_file(&staging);
        return Err(e);
    }

    let me = crate::node::paths::my_uid();
    let task = tokio::spawn(async move {
        loop {
            let stream = match listener.accept().await {
                Ok((stream, _)) => stream,
                // **An accept error is not the end of the socket** (V210-72). They are
                // transient — the process or the system out of descriptors (EMFILE,
                // ENFILE), a connection aborted before it was taken (ECONNABORTED), no
                // buffer space — and returning here ended the control socket for good
                // while the daemon ran on, and every client after was told nothing was
                // listening. The pause keeps an exhausted descriptor table from being
                // spun on; the connection waits in the backlog meanwhile.
                Err(_) => {
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    continue;
                }
            };
            // Only this user: the directory and the mode already say so, and the kernel's
            // word for who connected is checked as well, so neither is the only guard.
            if !stream.peer_cred().is_ok_and(|c| c.uid() == me) {
                continue;
            }
            // Each client gets its own task and its own subscription, so one
            // client's pace — or death — reaches no other and never the actor.
            let stream_handle = handle.clone();
            tokio::spawn(async move {
                serve_client(stream, stream_handle).await;
            });
        }
    });

    Ok(IpcServer { path, task })
}

/// Bind the control socket at this profile's conventional path.
pub fn bind(handle: NodeHandle, paths: &crate::node::paths::Paths) -> Result<IpcServer> {
    bind_at(handle, paths.socket_file())
}

/// What a client opened over its connection and has not closed: a file offer's service,
/// a get's forward.
///
/// **They last as long as the connection** (V210-72). `vox room send` and `vox room get`
/// withdrew them only on Ctrl-C, so a SIGTERM, a SIGHUP, a closed terminal or a crash left
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

/// One client, until it goes, and then whatever it left open is withdrawn.
async fn serve_client(stream: UnixStream, handle: NodeHandle) {
    let mut held = Held::default();
    let _ = serve_requests(stream, &handle, &mut held).await;
    held.release(&handle).await;
}

/// Greet, serve requests, and stream once subscribed, until either side stops.
async fn serve_requests(
    mut stream: UnixStream,
    handle: &NodeHandle,
    held: &mut Held,
) -> Result<()> {
    write_frame(
        &mut stream,
        &Frame::Hello {
            protocol: PROTOCOL_VERSION,
            me: handle.view().identity.map(|i| i.fingerprint),
        }
        .to_bytes(),
    )
    .await?;

    // Serve requests until the client hangs up, or until it subscribes — which is
    // terminal, because from then on the connection is a one-way stream.
    loop {
        let Some(body) = read_frame(&mut stream).await? else {
            return Ok(());
        };
        // **Wiped as soon as it is decoded** (V210-94): a request can carry a room or identity
        // passphrase, and the frame is needed for nothing past its decoding. Freed as it was, it
        // kept a copy in memory after the node locked; held to the end of the request — which for
        // a join is the end of the join — it was still there when the lock reported done.
        // Measured through the shipped binary both times: one copy of a join's room passphrase.
        let body = zeroize::Zeroizing::new(body);
        // ADR-025 S0b: `vox status --json`. Answered, and the connection serves on.
        if crate::node::status::is_request(&body) {
            let equivocations: Vec<(Digest32, Digest32, u64)> = handle
                .view()
                .open_channels
                .iter()
                .flat_map(|d| {
                    d.equivocations
                        .iter()
                        .map(move |(author, seq)| (d.channel_id, *author, *seq))
                })
                .collect();
            crate::node::status::serve(&mut stream, handle.sync_book(), &equivocations).await?;
            continue;
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
            return pump(stream, events).await;
        }
        let intent = Held::intent(&request);
        let reply = serve_request(handle, request).await;
        held.note(intent, &reply);
        write_frame(&mut stream, &reply.to_bytes()).await?;
    }
}

/// Prove the caller holds the identity passphrase, or say why not.
///
/// ADR-020 §7 keeps trust-keyring edits off this socket, on the grounds that an agent
/// session runs model-authored code and the socket is reachable by anything running as
/// the user. That reasoning is kept; this is the exception that does not weaken it. The
/// operator knows the identity passphrase and an agent does not, so requiring it here
/// lets the person who owns the profile use their own daemon without handing the agent
/// the ability to decide who may read them.
async fn verify_operator(
    handle: &NodeHandle,
    passphrase: String,
) -> std::result::Result<(), Frame> {
    match handle
        .apply(crate::node::api::NodeCommand::VerifyPassphrase {
            passphrase: crate::node::api::Secret::new(passphrase.into_bytes()),
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
        // The keyring, gated on the identity passphrase. The check is first and the
        // command is only issued if it passes, so a caller who cannot prove they are the
        // operator changes nothing and learns nothing.
        Request::Trust {
            target,
            petname,
            identity_passphrase,
        } => match verify_operator(handle, identity_passphrase).await {
            Err(f) => f,
            Ok(()) => match handle
                .apply(crate::node::api::NodeCommand::Trust {
                    fingerprint: target,
                    petname,
                })
                .await
            {
                crate::node::api::Outcome::Done => Frame::Ok,
                other => Frame::Error {
                    reason: other.to_string(),
                },
            },
        },
        Request::Untrust {
            target,
            identity_passphrase,
        } => match verify_operator(handle, identity_passphrase).await {
            Err(f) => f,
            Ok(()) => match handle
                .apply(crate::node::api::NodeCommand::Untrust {
                    fingerprint: target,
                })
                .await
            {
                crate::node::api::Outcome::Done => Frame::Ok,
                other => Frame::Error {
                    reason: other.to_string(),
                },
            },
        },
        Request::TrustList {
            identity_passphrase,
            after,
        } => match verify_operator(handle, identity_passphrase).await {
            Err(f) => f,
            Ok(()) => Frame::Trusted {
                entries: page(handle.view().trusted, after, |(id, petname)| {
                    (*id, petname.len())
                }),
            },
        },
        Request::Post { channel_id, text } => {
            match handle
                .apply(crate::node::api::NodeCommand::SendText { channel_id, text })
                .await
            {
                crate::node::api::Outcome::Done => Frame::Ok,
                other => Frame::Error {
                    reason: other.to_string(),
                },
            }
        }
        Request::Read {
            channel_id,
            since,
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
            // The cursor is an entry hash the client already has; everything
            // after it is what it has not seen. A cursor this node does not hold
            // is an error rather than "from the start", which would silently
            // re-deliver the whole room.
            let start = match since {
                None => 0,
                Some(cursor) => match detail.timeline.iter().position(|r| r.entry_hash == cursor) {
                    Some(i) => i + 1,
                    None => {
                        return Frame::Error {
                            reason: "cursor not in this room's timeline".into(),
                        }
                    }
                },
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
            for r in &detail.timeline[start.min(detail.timeline.len())..] {
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
        Request::AddService {
            channel_id,
            service_tag,
            local,
        } => {
            let Ok(local) = local.parse() else {
                return Frame::Error {
                    reason: format!("not a local address: {local:?}"),
                };
            };
            match handle
                .apply(crate::node::api::NodeCommand::AddService {
                    channel_id,
                    service_tag,
                    local,
                    // Offered over this socket, it lasts as long as the client's connection
                    // (`Held`), and so never outlives this node's run either.
                    persist: false,
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
            local_name,
            passphrase,
        } => {
            // Subscribe before asking: a failed join's steps and responders' reasons are raised
            // as events just before the outcome is answered, and one emitted between the command
            // and the wait would be lost.
            let mut events = handle.subscribe();
            match handle
                .apply(crate::node::api::NodeCommand::JoinChannel {
                    link,
                    local_name,
                    passphrase: crate::node::api::Secret::new(passphrase.into_bytes()),
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
                        other => format!("{other:?}"),
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
            local_name,
            passphrase,
        } => match handle
            .apply(crate::node::api::NodeCommand::CreateChannel {
                local_name,
                passphrase: crate::node::api::Secret::new(passphrase.into_bytes()),
            })
            .await
        {
            crate::node::api::Outcome::Done => Frame::Ok,
            other => Frame::Error {
                reason: other.to_string(),
            },
        },
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
                        c.local_name.clone().unwrap_or_default(),
                        c.open,
                    )
                })
                .collect();
            Frame::Rooms {
                rooms: page(rooms, after, |(id, name, _)| (*id, name.len())),
            }
        }
    }
}

/// Forward a subscription to a client until the client goes away or the node
/// stops. Any write failure ends **this** connection and nothing else — a client
/// that died mid-stream shows up as `BrokenPipe` here (measured).
async fn pump(mut stream: UnixStream, mut events: EventStream) -> Result<()> {
    while let Some(item) = events.next().await {
        let frame = match item {
            EventStreamItem::Event(ev) => Frame::Event(ev),
            EventStreamItem::Lagged(missed) => Frame::Lagged { missed },
        };
        if write_frame(&mut stream, &frame.to_bytes()).await.is_err() {
            return Ok(());
        }
    }
    Ok(())
}

// ---- client ----------------------------------------------------------------

/// A connected client of a node's control socket.
#[derive(Debug)]
pub struct IpcClient {
    stream: UnixStream,
    me: Option<Digest32>,
    /// Where the node listens, so a request that waits can check it is still answering.
    path: PathBuf,
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
        })
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
        let Self { stream, path, .. } = self;
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
        while_answering(path, exchange).await
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
        let mut all = Vec::new();
        let mut cursor = since;
        loop {
            match self
                .request(&Request::Read {
                    channel_id,
                    since: cursor,
                    limit: 0,
                })
                .await?
            {
                Frame::Rows { rows } => {
                    let Some(last) = rows.last() else {
                        return Ok(Frame::Rows { rows: all });
                    };
                    // A page that ends where the last one did would be asked for again
                    // forever; a node that ignored the cursor is an error, not a hang.
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
                    identity_passphrase: identity_passphrase.to_owned(),
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
