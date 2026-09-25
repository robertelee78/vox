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
//!   umask), so the explicit `chmod` to `0600` is REQUIRED, not belt-and-braces.
//! - A leftover socket file from a process that died makes `bind` fail with
//!   `AddrInUse` (errno 48), so the stale file is unlinked first — deliberately,
//!   rather than inheriting a confusing "address in use".
//! - A client that dies reads as a clean EOF and writing to it fails with
//!   `BrokenPipe`; both are isolated to that connection.

use std::path::{Path, PathBuf};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};

use crate::cbor::{Decoder, Encoder};
use crate::error::{Error, Result};
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
pub const PROTOCOL_VERSION: u64 = 7;

/// Largest frame accepted in either direction.
///
/// Comfortably above the largest event — `InviteLink`'s URL and a `NewEntry`'s
/// text are the only unbounded-ish fields, and message text is already capped at
/// [`crate::node::content::MAX_TEXT_LEN`] (64 KiB).
pub const MAX_FRAME: usize = 256 * 1024;

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
/// [`NodeEvent::JoinSteps`]: where a join's time went.
const T_JOIN_STEPS: u64 = 1718;
/// `NodeEvent::KeyNotTaken`.
const T_KEY_NOT_TAKEN: u64 = 1719;
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
/// Protocol 6: the room's whole order, as `(entry hash, clock)` pairs.
const T_ORDER_ROWS: u64 = 27;
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
// Setting a room's retention deletes what is already stored (ADR-023 decision 2), so it is an
// operator decision like the keyring and carries the identity passphrase the same way.
const T_RETENTION: u64 = 23;
// Protocol 6 — every entry the node holds for a room, in the room's one order
// (PRD-001 R13), readable or not. What "the same order on every node" is checked
// against, because a node's timeline shows only the rows it holds keys for.
const T_ORDER: u64 = 24;

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
    /// Every room this node holds.
    Rooms,
    /// Offer a local TCP endpoint as a room-bound service (ADR-013).
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
    /// Set a room's retention (ADR-023 decision 2). Requires the identity passphrase:
    /// shortening it deletes stored history, which is not an agent's call.
    SetRetention {
        /// The room.
        channel_id: Digest32,
        /// Seconds a message body is kept; `0` keeps it forever.
        ttl: u64,
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
    },
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
            Request::Order { channel_id } => {
                e.array(2).uint(T_ORDER).bytes(channel_id);
            }
            Request::Rooms => {
                e.array(1).uint(T_ROOMS_REQ);
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
            Request::SetRetention {
                channel_id,
                ttl,
                identity_passphrase,
            } => {
                e.array(4)
                    .uint(T_RETENTION)
                    .bytes(channel_id)
                    .uint(*ttl)
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
            } => {
                e.array(2).uint(T_TRUST_LIST).text(identity_passphrase);
            }
        }
        e.finish()
    }

    /// Parse one request body.
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(b);
        let n = d
            .array()
            .map_err(|_| Error::MalformedBundle("ipc request"))?;
        let tag = d
            .uint()
            .map_err(|_| Error::MalformedBundle("ipc request tag"))?;
        match (tag, n) {
            (T_SUBSCRIBE, 1) => {
                d.finish()
                    .map_err(|_| Error::MalformedBundle("ipc request trailing"))?;
                Ok(Request::Subscribe)
            }
            (T_POST, 3) => {
                let channel_id = digest(&mut d)?;
                let text = d
                    .text()
                    .map_err(|_| Error::MalformedBundle("ipc post text"))?
                    .to_owned();
                d.finish()
                    .map_err(|_| Error::MalformedBundle("ipc request trailing"))?;
                Ok(Request::Post { channel_id, text })
            }
            (T_READ, 4) => {
                let channel_id = digest(&mut d)?;
                let cursor = d
                    .bytes()
                    .map_err(|_| Error::MalformedBundle("ipc cursor"))?;
                let since = if cursor.is_empty() {
                    None
                } else {
                    Some(
                        Digest32::try_from(cursor)
                            .map_err(|_| Error::MalformedBundle("ipc cursor length"))?,
                    )
                };
                let limit = d.uint().map_err(|_| Error::MalformedBundle("ipc limit"))?;
                d.finish()
                    .map_err(|_| Error::MalformedBundle("ipc request trailing"))?;
                Ok(Request::Read {
                    channel_id,
                    since,
                    limit,
                })
            }
            (T_ROSTER, 2) => {
                let channel_id = digest(&mut d)?;
                d.finish()
                    .map_err(|_| Error::MalformedBundle("ipc request trailing"))?;
                Ok(Request::Roster { channel_id })
            }
            (T_ORDER, 2) => {
                let channel_id = digest(&mut d)?;
                d.finish()
                    .map_err(|_| Error::MalformedBundle("ipc request trailing"))?;
                Ok(Request::Order { channel_id })
            }
            (T_ROOMS_REQ, 1) => {
                d.finish()
                    .map_err(|_| Error::MalformedBundle("ipc request trailing"))?;
                Ok(Request::Rooms)
            }
            (T_TRUST, 4) => {
                let target = digest(&mut d)?;
                let petname = text(&mut d, "ipc petname")?;
                let identity_passphrase = text(&mut d, "ipc identity passphrase")?;
                d.finish()
                    .map_err(|_| Error::MalformedBundle("ipc request trailing"))?;
                Ok(Request::Trust {
                    target,
                    petname,
                    identity_passphrase,
                })
            }
            (T_RETENTION, 4) => {
                let channel_id = digest(&mut d)?;
                let ttl = d.uint().map_err(|_| Error::MalformedBundle("ipc ttl"))?;
                let identity_passphrase = text(&mut d, "ipc identity passphrase")?;
                d.finish()
                    .map_err(|_| Error::MalformedBundle("ipc request trailing"))?;
                Ok(Request::SetRetention {
                    channel_id,
                    ttl,
                    identity_passphrase,
                })
            }
            (T_UNTRUST, 3) => {
                let target = digest(&mut d)?;
                let identity_passphrase = text(&mut d, "ipc identity passphrase")?;
                d.finish()
                    .map_err(|_| Error::MalformedBundle("ipc request trailing"))?;
                Ok(Request::Untrust {
                    target,
                    identity_passphrase,
                })
            }
            (T_TRUST_LIST, 2) => {
                let identity_passphrase = text(&mut d, "ipc identity passphrase")?;
                d.finish()
                    .map_err(|_| Error::MalformedBundle("ipc request trailing"))?;
                Ok(Request::TrustList {
                    identity_passphrase,
                })
            }
            (T_ADD_SERVICE, 4) => {
                let channel_id = digest(&mut d)?;
                let service_tag = text(&mut d, "ipc service tag")?;
                let local = text(&mut d, "ipc local address")?;
                d.finish()
                    .map_err(|_| Error::MalformedBundle("ipc request trailing"))?;
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
                    .map_err(|_| Error::MalformedBundle("ipc request trailing"))?;
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
                    .map_err(|_| Error::MalformedBundle("ipc request trailing"))?;
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
                    .map_err(|_| Error::MalformedBundle("ipc request trailing"))?;
                Ok(Request::StopForward { local })
            }
            (T_JOIN, 4) => {
                let link = text(&mut d, "ipc join link")?;
                let local_name = text(&mut d, "ipc join name")?;
                let passphrase = text(&mut d, "ipc join passphrase")?;
                d.finish()
                    .map_err(|_| Error::MalformedBundle("ipc request trailing"))?;
                Ok(Request::Join {
                    link,
                    local_name,
                    passphrase,
                })
            }
            (T_CREATE, 3) => {
                let local_name = text(&mut d, "ipc create name")?;
                let passphrase = text(&mut d, "ipc create passphrase")?;
                d.finish()
                    .map_err(|_| Error::MalformedBundle("ipc request trailing"))?;
                Ok(Request::Create {
                    local_name,
                    passphrase,
                })
            }
            (T_INVITE, 2) => {
                let channel_id = digest(&mut d)?;
                d.finish()
                    .map_err(|_| Error::MalformedBundle("ipc request trailing"))?;
                Ok(Request::Invite { channel_id })
            }
            _ => Err(Error::MalformedBundle("ipc request unknown tag")),
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
                    e.array(6)
                        .bytes(&r.entry_hash)
                        .bytes(&r.author)
                        .uint(r.created_millis)
                        .text(&r.text)
                        .uint(r.arrival)
                        .uint(u64::from(r.late));
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
            Frame::Bound { local } => {
                e.array(2).uint(T_BOUND).text(local);
            }
            Frame::Link { url } => {
                e.array(2).uint(T_LINK).text(url);
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
        let n = d.array().map_err(|_| Error::MalformedBundle("ipc frame"))?;
        let tag = d
            .uint()
            .map_err(|_| Error::MalformedBundle("ipc frame tag"))?;
        let out = decode_body(&mut d, tag, n)?;
        d.finish()
            .map_err(|_| Error::MalformedBundle("ipc frame trailing"))?;
        Ok(out)
    }
}

fn digest(d: &mut Decoder<'_>) -> Result<Digest32> {
    let b = d
        .bytes()
        .map_err(|_| Error::MalformedBundle("ipc digest"))?;
    Digest32::try_from(b).map_err(|_| Error::MalformedBundle("ipc digest length"))
}

/// A CBOR text string, named so a decode failure says which field it was.
fn text(d: &mut Decoder<'_>, what: &'static str) -> Result<String> {
    Ok(d.text()
        .map_err(|_| Error::MalformedBundle(what))?
        .to_owned())
}

/// A 0/1 flag; any other value is malformed rather than read as true.
fn flag(d: &mut Decoder<'_>, what: &'static str) -> Result<bool> {
    match d.uint().map_err(|_| Error::MalformedBundle(what))? {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(Error::MalformedBundle(what)),
    }
}

fn addr(d: &mut Decoder<'_>) -> Result<std::net::SocketAddr> {
    d.text()
        .map_err(|_| Error::MalformedBundle("ipc addr"))?
        .parse()
        .map_err(|_| Error::MalformedBundle("ipc addr syntax"))
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
        NodeEvent::Unlocked => {
            e.array(1).uint(T_UNLOCKED);
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
        NodeEvent::JoinFailed { reason } => {
            e.array(2).uint(T_JOIN_FAILED).text(reason);
        }
        NodeEvent::JoinSteps { joined, steps } => {
            e.array(3)
                .uint(T_JOIN_STEPS)
                .uint(u64::from(*joined))
                .text(steps);
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
            let protocol = d.uint().map_err(|_| Error::MalformedBundle("ipc hello"))?;
            let fp = d
                .bytes()
                .map_err(|_| Error::MalformedBundle("ipc hello identity"))?;
            let me = if fp.is_empty() {
                None
            } else {
                Some(
                    Digest32::try_from(fp)
                        .map_err(|_| Error::MalformedBundle("ipc hello identity length"))?,
                )
            };
            return Ok(Frame::Hello { protocol, me });
        }
        (T_LAGGED, 2) => {
            return Ok(Frame::Lagged {
                missed: d.uint().map_err(|_| Error::MalformedBundle("ipc lagged"))?,
            })
        }
        (T_OK, 1) => return Ok(Frame::Ok),
        (T_ERROR, 2) => {
            return Ok(Frame::Error {
                reason: d
                    .text()
                    .map_err(|_| Error::MalformedBundle("ipc error reason"))?
                    .to_owned(),
            })
        }
        (T_ROWS, 2) => {
            let n = d.array().map_err(|_| Error::MalformedBundle("ipc rows"))?;
            let mut rows = Vec::with_capacity(n.min(1024));
            for _ in 0..n {
                let arity = d.array().map_err(|_| Error::MalformedBundle("ipc row"))?;
                if arity != 6 {
                    return Err(Error::MalformedBundle("ipc row arity"));
                }
                rows.push(MessageRow {
                    entry_hash: digest(d)?,
                    author: digest(d)?,
                    created_millis: d.uint().map_err(|_| Error::MalformedBundle("ipc millis"))?,
                    text: d
                        .text()
                        .map_err(|_| Error::MalformedBundle("ipc text"))?
                        .to_owned(),
                    arrival: d
                        .uint()
                        .map_err(|_| Error::MalformedBundle("ipc arrival"))?,
                    late: flag(d, "ipc late")?,
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
            let n = d
                .array()
                .map_err(|_| Error::MalformedBundle("ipc members"))?;
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
            });
        }
        (T_ROOMS, 2) => {
            let n = d.array().map_err(|_| Error::MalformedBundle("ipc rooms"))?;
            let mut rooms = Vec::with_capacity(n.min(1024));
            for _ in 0..n {
                let arity = d.array().map_err(|_| Error::MalformedBundle("ipc room"))?;
                if arity != 3 {
                    return Err(Error::MalformedBundle("ipc room arity"));
                }
                let id = digest(d)?;
                let name = d
                    .text()
                    .map_err(|_| Error::MalformedBundle("ipc room name"))?
                    .to_owned();
                let open = d
                    .uint()
                    .map_err(|_| Error::MalformedBundle("ipc room open"))?
                    != 0;
                rooms.push((id, name, open));
            }
            return Ok(Frame::Rooms { rooms });
        }
        (T_TRUSTED, 2) => {
            let count = d
                .array()
                .map_err(|_| Error::MalformedBundle("ipc trusted array"))?;
            let mut entries = Vec::with_capacity(count.min(1024));
            for _ in 0..count {
                let arity = d
                    .array()
                    .map_err(|_| Error::MalformedBundle("ipc trusted row"))?;
                if arity != 2 {
                    return Err(Error::MalformedBundle("ipc trusted row arity"));
                }
                let id = digest(d)?;
                let petname = d
                    .text()
                    .map_err(|_| Error::MalformedBundle("ipc trusted petname"))?
                    .to_owned();
                entries.push((id, petname));
            }
            return Ok(Frame::Trusted { entries });
        }
        (T_NEW_ENTRY, 8) => {
            let channel_id = digest(d)?;
            let entry_hash = digest(d)?;
            let author = digest(d)?;
            let created_millis = d.uint().map_err(|_| Error::MalformedBundle("ipc millis"))?;
            let text = d
                .text()
                .map_err(|_| Error::MalformedBundle("ipc text"))?
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
                },
            }
        }
        (T_UNLOCKED, 1) => NodeEvent::Unlocked,
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
                .map_err(|_| Error::MalformedBundle("ipc why"))?
                .to_owned(),
        },
        (T_SENDER_KEY, 4) => NodeEvent::SenderKeyReceived {
            channel_id: digest(d)?,
            peer: digest(d)?,
            backfilled: d.uint().map_err(|_| Error::MalformedBundle("ipc n"))?,
        },
        (T_FORWARDING, 5) => NodeEvent::Forwarding {
            channel_id: digest(d)?,
            host: digest(d)?,
            service_tag: d
                .text()
                .map_err(|_| Error::MalformedBundle("ipc tag"))?
                .to_owned(),
            local: addr(d)?,
        },
        (T_STALLED, 3) => NodeEvent::Stalled {
            what: d
                .text()
                .map_err(|_| Error::MalformedBundle("ipc stall what"))?
                .to_owned(),
            millis: d
                .uint()
                .map_err(|_| Error::MalformedBundle("ipc stall ms"))?,
        },
        (T_PUBLISH_REFUSED, 4) => NodeEvent::PublishRefused {
            channel_id: digest(d)?,
            what: d
                .text()
                .map_err(|_| Error::MalformedBundle("ipc publish what"))?
                .to_owned(),
            why: d
                .text()
                .map_err(|_| Error::MalformedBundle("ipc publish why"))?
                .to_owned(),
        },
        (T_JOIN_STEPS, 3) => NodeEvent::JoinSteps {
            joined: match d.uint()? {
                0 => false,
                1 => true,
                _ => return Err(Error::MalformedBundle("ipc join steps flag")),
            },
            steps: d
                .text()
                .map_err(|_| Error::MalformedBundle("ipc join steps"))?
                .to_owned(),
        },
        (T_JOIN_FAILED, 2) => NodeEvent::JoinFailed {
            reason: d
                .text()
                .map_err(|_| Error::MalformedBundle("ipc join reason"))?
                .to_owned(),
        },
        (T_STILL_RELAYED, 3) => NodeEvent::StillRelayed {
            peer: digest(d)?,
            reason: d
                .text()
                .map_err(|_| Error::MalformedBundle("ipc relayed reason"))?
                .to_owned(),
        },
        (T_PROXY_REFUSED, 2) => NodeEvent::ProxyRefused {
            reason: d
                .text()
                .map_err(|_| Error::MalformedBundle("ipc proxy refusal reason"))?
                .to_owned(),
        },
        (T_PEER_UNREACHABLE, 3) => NodeEvent::PeerUnreachable {
            peer: digest(d)?,
            why: d
                .text()
                .map_err(|_| Error::MalformedBundle("ipc unreachable reason"))?
                .to_owned(),
        },
        (T_REACH_WITHDRAWN, 3) => NodeEvent::ReachWithdrawn {
            channel_id: digest(d)?,
            port: u16::try_from(d.uint().map_err(|_| Error::MalformedBundle("ipc port"))?)
                .map_err(|_| Error::MalformedBundle("ipc port range"))?,
        },
        (T_INVITE_LINK, 3) => NodeEvent::InviteLink {
            channel_id: digest(d)?,
            url: d
                .text()
                .map_err(|_| Error::MalformedBundle("ipc url"))?
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
            generation: d.uint().map_err(|_| Error::MalformedBundle("ipc gen"))?,
            rekeyed: d
                .uint()
                .map_err(|_| Error::MalformedBundle("ipc rekeyed"))?,
        },
        (T_TUNNEL_SERVED, 4) => NodeEvent::TunnelServed {
            channel_id: digest(d)?,
            client: digest(d)?,
            service_tag: d
                .text()
                .map_err(|_| Error::MalformedBundle("ipc tag"))?
                .to_owned(),
        },
        (T_PROXY_UP, 4) => NodeEvent::ProxyUp {
            channel_id: digest(d)?,
            hostname: d
                .text()
                .map_err(|_| Error::MalformedBundle("ipc host"))?
                .to_owned(),
            bind: addr(d)?,
        },
        (T_SYNCED, 4) => NodeEvent::Synced {
            channel_id: digest(d)?,
            applied: d
                .uint()
                .map_err(|_| Error::MalformedBundle("ipc applied"))?,
            rendered: d
                .uint()
                .map_err(|_| Error::MalformedBundle("ipc rendered"))?,
        },
        _ => return Err(Error::MalformedBundle("ipc frame unknown tag")),
    };
    Ok(Frame::Event(ev))
}

// ---- transport -------------------------------------------------------------

/// Write one length-prefixed frame, mirroring [`crate::transport::framing`].
pub async fn write_frame(s: &mut UnixStream, body: &[u8]) -> Result<()> {
    let len =
        u32::try_from(body.len()).map_err(|_| Error::SizeLimitExceeded("ipc frame length"))?;
    s.write_all(&len.to_be_bytes())
        .await
        .map_err(|_| Error::MalformedBundle("ipc write len"))?;
    s.write_all(body)
        .await
        .map_err(|_| Error::MalformedBundle("ipc write body"))?;
    Ok(())
}

/// Read one length-prefixed frame of at most `MAX_FRAME` bytes. A clean EOF
/// exactly at a frame boundary is the peer hanging up → `Ok(None)`.
pub async fn read_frame(s: &mut UnixStream) -> Result<Option<Vec<u8>>> {
    let mut len_buf = [0u8; 4];
    match s.read_exact(&mut len_buf).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(_) => return Err(Error::MalformedBundle("ipc read len")),
    }
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_FRAME {
        return Err(Error::SizeLimitExceeded("ipc frame length"));
    }
    let mut body = vec![0u8; len];
    s.read_exact(&mut body)
        .await
        .map_err(|_| Error::MalformedBundle("ipc read body"))?;
    Ok(Some(body))
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

/// Bind the control socket at `path` and serve `handle`'s event stream to every
/// client that connects.
///
/// The stale socket file of a process that died is **unlinked first**: `bind`
/// fails with `AddrInUse` otherwise (measured), and inheriting that error would
/// report a dead predecessor as a live conflict. The socket is then chmod'd to
/// `0600` — `bind` itself yields `0755` from the umask (also measured), so this
/// is load-bearing, not decoration.
pub fn bind_at(handle: NodeHandle, path: PathBuf) -> Result<IpcServer> {
    if path.exists() {
        std::fs::remove_file(&path).map_err(|e| Error::Path {
            op: "unlink stale control socket",
            detail: format!("{}: {e}", path.display()),
        })?;
    }
    let listener = UnixListener::bind(&path).map_err(|e| Error::Path {
        op: "bind control socket",
        detail: format!("{}: {e}", path.display()),
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).map_err(|e| {
            Error::Path {
                op: "chmod control socket",
                detail: format!("{}: {e}", path.display()),
            }
        })?;
    }

    let task = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                // The listener is gone; nothing left to accept.
                return;
            };
            // Each client gets its own task and its own subscription, so one
            // client's pace — or death — reaches no other and never the actor.
            let stream_handle = handle.clone();
            tokio::spawn(async move {
                let _ = serve_client(stream, stream_handle).await;
            });
        }
    });

    Ok(IpcServer { path, task })
}

/// Bind the control socket at this profile's conventional path.
pub fn bind(handle: NodeHandle, paths: &crate::node::paths::Paths) -> Result<IpcServer> {
    bind_at(handle, paths.socket_file())
}

/// One client: greet, wait for `Subscribe`, then stream until either side stops.
async fn serve_client(mut stream: UnixStream, handle: NodeHandle) -> Result<()> {
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
        // PRD-001 R35: `vox status`. Answered, and the connection serves on.
        if crate::node::status::is_request(&body) {
            crate::node::status::serve(&mut stream, &handle).await?;
            continue;
        }
        // Protocol 6: an app request turns the connection into an app connection for
        // the rest of its life (ADR-022 decision 7, `node::appipc`).
        if let Some(app) = crate::node::appipc::AppRequest::parse(&body) {
            return match app {
                Ok(app) => crate::node::appipc::serve(stream, handle, app).await,
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
        let request = match Request::from_bytes(&body) {
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
        let reply = serve_request(&handle, request).await;
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
        _ => Err(Frame::Error {
            reason: "the identity passphrase does not match; the trust keyring is only \
                     editable by whoever holds it"
                .to_owned(),
        }),
    }
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
        Request::SetRetention {
            channel_id,
            ttl,
            identity_passphrase,
        } => match verify_operator(handle, identity_passphrase).await {
            Err(f) => f,
            Ok(()) => match handle
                .apply(crate::node::api::NodeCommand::SetRetention { channel_id, ttl })
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
        } => match verify_operator(handle, identity_passphrase).await {
            Err(f) => f,
            Ok(()) => Frame::Trusted {
                entries: handle.view().trusted,
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
            // read with no cursor is the room, in the room's order.
            let mut rows: Vec<MessageRow> = match since {
                None => detail.timeline.clone(),
                Some(cursor) => {
                    let Some(mark) = detail
                        .timeline
                        .iter()
                        .find(|r| r.entry_hash == cursor)
                        .map(|r| r.arrival)
                    else {
                        return Frame::Error {
                            reason: "cursor not in this room's timeline".into(),
                        };
                    };
                    let mut newer: Vec<MessageRow> = detail
                        .timeline
                        .iter()
                        .filter(|r| r.arrival > mark)
                        .cloned()
                        .collect();
                    newer.sort_by_key(|r| r.arrival);
                    newer
                }
            };
            if limit > 0 {
                rows.truncate(usize::try_from(limit).unwrap_or(usize::MAX));
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
            // Subscribe **before** asking, so the `Forwarding` event cannot be
            // emitted and missed between the command and the wait.
            let mut events = handle.subscribe();
            match handle
                .apply(crate::node::api::NodeCommand::Forward {
                    channel_id,
                    host,
                    service_tag,
                    local,
                })
                .await
            {
                crate::node::api::Outcome::Done => {}
                other => {
                    return Frame::Error {
                        reason: other.to_string(),
                    }
                }
            }
            let deadline = std::time::Duration::from_secs(10);
            match tokio::time::timeout(deadline, async {
                loop {
                    match events.next().await {
                        Some(EventStreamItem::Event(NodeEvent::Forwarding { local, .. })) => {
                            return Some(local)
                        }
                        Some(_) => {}
                        None => return None,
                    }
                }
            })
            .await
            {
                Ok(Some(bound)) => Frame::Bound {
                    local: bound.to_string(),
                },
                Ok(None) => Frame::Error {
                    reason: "the node stopped before the forward was bound".into(),
                },
                Err(_) => Frame::Error {
                    reason: "the forward did not report a bound address".into(),
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
        } => match handle
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
            crate::node::api::Outcome::Failed(fault) => Frame::Error {
                reason: fault.explain_join().to_owned(),
            },
        },
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
                    return Frame::Error {
                        reason: other.to_string(),
                    }
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
                Ok(Some(url)) => Frame::Link { url },
                Ok(None) => Frame::Error {
                    reason: "the node stopped before the link was minted".into(),
                },
                Err(_) => Frame::Error {
                    reason: "the node did not mint a link".into(),
                },
            }
        }
        Request::Rooms => {
            let view = handle.view();
            Frame::Rooms {
                rooms: view
                    .channels
                    .iter()
                    .map(|c| {
                        (
                            c.channel_id,
                            c.local_name.clone().unwrap_or_default(),
                            c.open,
                        )
                    })
                    .collect(),
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
        let mut stream = UnixStream::connect(path).await.map_err(|e| Error::Path {
            op: "connect control socket",
            detail: format!("{}: {e}", path.display()),
        })?;
        let Some(hello) = read_frame(&mut stream).await? else {
            return Err(Error::MalformedBundle("ipc closed before hello"));
        };
        let me = match Frame::from_bytes(&hello)? {
            Frame::Hello { protocol, me } if protocol == PROTOCOL_VERSION => me,
            Frame::Hello { .. } => return Err(Error::MalformedBundle("ipc protocol version")),
            _ => return Err(Error::MalformedBundle("ipc expected hello")),
        };
        Ok(Self { stream, me })
    }

    /// Send one request and read its answer.
    ///
    /// A [`Frame::Error`] is returned as `Ok(Frame::Error { .. })`, not as an
    /// `Err`: "this room is not open" is an answer, and the connection stays
    /// usable for the next question.
    pub async fn request(&mut self, req: &Request) -> Result<Frame> {
        write_frame(&mut self.stream, &req.to_bytes()).await?;
        let Some(body) = read_frame(&mut self.stream).await? else {
            return Err(Error::MalformedBundle("ipc closed before reply"));
        };
        Frame::from_bytes(&body)
    }

    /// Turn this connection into an event stream. Terminal: no further request
    /// may be sent on it.
    pub async fn subscribe(&mut self) -> Result<()> {
        match self.request(&Request::Subscribe).await? {
            Frame::Ok => Ok(()),
            Frame::Error { reason } => {
                let _ = reason;
                Err(Error::MalformedBundle("ipc subscribe refused"))
            }
            _ => Err(Error::MalformedBundle("ipc unexpected subscribe reply")),
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
