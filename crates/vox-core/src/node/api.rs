//! The node's typed boundary (ADR-016 §"The `Node`: one actor, one writer, one
//! secrets boundary").
//!
//! These are the only types that cross between the node and a client. They carry
//! **public facts and already-rendered text only** — fingerprints, names,
//! timestamps, decrypted message bodies, enum state — never a key, an SKDM, a
//! SEK, a `self_seed` or a passphrase. The one secret-bearing *input* (a
//! passphrase) is a [`Secret`], a zeroizing buffer the node wipes after use.
//! Outcomes are a closed enum ([`Outcome`] / [`Fault`]) with no free text, so the
//! status channel cannot leak plaintext or secret detail (the ADR-015 rule,
//! applied at the node).
//!
//! Clients project their own UI model from a [`NodeView`]: the Rust TUI maps it
//! to its `ViewModel`, the macOS client to its SwiftUI state. The node never
//! depends on a UI type.

use zeroize::Zeroizing;

use crate::hash::Digest32;

/// A secret input (passphrase bytes); zeroized on drop.
pub type Secret = Zeroizing<Vec<u8>>;

/// Public facts about the profile's identity (available while locked).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityInfo {
    /// The composite-identity fingerprint.
    pub fingerprint: Digest32,
    /// Creation time (seconds since the Unix epoch).
    pub created: u64,
}

/// A channel known to this profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelSummary {
    /// The channelID.
    pub channel_id: Digest32,
    /// The local name — known only once the channel is **open** (it lives inside
    /// the SEK-sealed manifest, ADR-010 double-lock), else `None`.
    pub local_name: Option<String>,
    /// Whether the channel is open (SEK unlocked) in this session.
    pub open: bool,
    /// Number of accepted log entries (0 while closed).
    pub entries: u64,
}

/// A rendered, render-gated message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageRow {
    /// The ADR-008 entry hash.
    pub entry_hash: Digest32,
    /// The author's fingerprint.
    pub author: Digest32,
    /// The author's recorded send time (seconds).
    pub created_secs: u64,
    /// The text.
    pub text: String,
}

/// An open channel's full state for display.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelDetail {
    /// The channelID.
    pub channel_id: Digest32,
    /// The local name.
    pub local_name: String,
    /// The current epoch.
    pub epoch: u64,
    /// Members, in fingerprint order.
    pub members: Vec<Digest32>,
    /// The render-gated timeline, oldest first.
    pub timeline: Vec<MessageRow>,
    /// The services this node offers in this channel: `(service_tag, local address)`
    /// in tag order (ADR-013 Bind config — host configuration, not authorization).
    pub services: Vec<(String, std::net::SocketAddr)>,
}

/// The node's latest-wins view (published over a `watch`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NodeView {
    /// The profile's identity, or `None` before one is created.
    pub identity: Option<IdentityInfo>,
    /// Whether the identity is locked (no signer in memory).
    pub locked: bool,
    /// Whether every open channel's SEK is `mlock`ed (`true` when none are open).
    /// `false` surfaces the documented zeroize-only degradation (ADR-010/015).
    pub mlock_active: bool,
    /// The endpoints this node is listening on, in ADR-012 multiaddr text form —
    /// empty when it is not networked or is locked (binding needs the identity).
    /// Public information: it is what an invite link advertises.
    pub listening: Vec<String>,
    /// Every channel in the profile, in channelID order.
    pub channels: Vec<ChannelSummary>,
    /// The open channels' detail, in channelID order.
    pub open_channels: Vec<ChannelDetail>,
    /// The live forwards, in bound-address order (ADR-013 Dial).
    pub forwards: Vec<ForwardInfo>,
    /// Every channel this node's **board** holds a genesis for — the channels it
    /// anchors, whether or not it is a member — in channelID order. What an anchor
    /// can say about itself: which rooms it serves and how many members it knows of
    /// each, never what any of them said.
    pub anchoring: Vec<AnchoredChannel>,
}

/// A live local port forwarded to a member's service (ADR-013).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardInfo {
    /// The channel the capability is claimed under.
    pub channel_id: Digest32,
    /// The member hosting the service.
    pub host: Digest32,
    /// The service tag.
    pub service_tag: String,
    /// The local address accepting connections.
    pub local: std::net::SocketAddr,
}

/// A channel this node's board serves (ADR-016 M15.2a).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchoredChannel {
    /// The channelID.
    pub channel_id: Digest32,
    /// Members the board knows by a live record: the creator, and everyone a member
    /// has vouched for.
    pub members: usize,
    /// Joiners with a live pre-join announcement.
    pub pending: usize,
    /// Entries in the ciphertext copy of the log this node keeps for the channel
    /// (`None` when it keeps none — a client's board, or an anchor not yet caught up).
    pub entries: Option<u64>,
}

/// A command from a client to the node.
#[derive(Debug)]
pub enum NodeCommand {
    /// Create the profile's identity (fails if one exists).
    CreateIdentity {
        /// The identity passphrase.
        passphrase: Secret,
    },
    /// Unlock the identity.
    Unlock {
        /// The identity passphrase.
        passphrase: Secret,
    },
    /// App-lock: drop the identity signer and every open channel's SEK.
    Lock,
    /// Create a channel (needs the unlocked identity).
    CreateChannel {
        /// The local (device-only) name.
        local_name: String,
        /// The channel passphrase (the second lock factor).
        passphrase: Secret,
    },
    /// Open a channel: double-lock unwrap of its SEK.
    OpenChannel {
        /// The channelID.
        channel_id: Digest32,
        /// The channel passphrase.
        passphrase: Secret,
    },
    /// Close an open channel (wipes its SEK).
    CloseChannel {
        /// The channelID.
        channel_id: Digest32,
    },
    /// Author a text message in an open channel.
    SendText {
        /// The channelID.
        channel_id: Digest32,
        /// The text.
        text: String,
    },
    /// Produce a `vox://` invite link for a channel this node holds open, naming
    /// this node as anchor and responder. The link arrives as
    /// [`NodeEvent::InviteLink`]; it carries no secret (ADR-016).
    Invite {
        /// The channel to invite to.
        channel_id: Digest32,
    },
    /// Join a channel from an invite link. The passphrase is collected by the client
    /// out of band and is **never** in the link.
    JoinChannel {
        /// The `vox://` link.
        link: String,
        /// The local (device-only) name to give the channel.
        local_name: String,
        /// The channel passphrase.
        passphrase: Secret,
    },
    /// Consent to `target` reading this identity's messages in a channel (ADR-007:
    /// per-sender, human-initiated). Delivers this identity's sender key to the
    /// target and records the grant on the log.
    Consent {
        /// The channel.
        channel_id: Digest32,
        /// The member being consented to.
        target: Digest32,
    },
    /// Revoke `target`'s consent to read this identity's messages in a channel
    /// (ADR-007 §Revocation). Rotates this identity's sender key to a generation
    /// `target` holds no key for, records the revocation on the log, and re-keys the
    /// members who keep consent.
    ///
    /// The forward guarantee is immediate and cryptographic: it does not wait on
    /// anyone being reachable. What `target` already received is not recalled and
    /// cannot be (ADR-007 §"Enforcement honesty").
    Revoke {
        /// The channel.
        channel_id: Digest32,
        /// The member whose consent is withdrawn.
        target: Digest32,
    },
    /// Create a **service room** and offer one local TCP service in it, in one act
    /// (ADR-017 decisions 3 and 4) — what `vox serve <port>` does.
    ///
    /// The room's genesis confers `dial:<port>` on every member, so joining it *is* the
    /// authorization and the host never waits to grant anyone anything; the service is
    /// declared in the same step, because a room created for a service that does not
    /// exist yet is a room that lies. Nothing is exposed implicitly: the port named here
    /// is the only thing reachable, and only by members.
    ///
    /// Fails without creating anything if the room cannot be created *or* the service
    /// cannot be offered — a half-made service room would hand out an address for
    /// nothing.
    Serve {
        /// The local (device-only) name for the room.
        local_name: String,
        /// The room passphrase — machine-generated by the caller
        /// ([`crate::node::passphrase::generate`]), never chosen.
        passphrase: Secret,
        /// The service's port, which is also its tag (ADR-017: the port names the
        /// service).
        port: u16,
        /// The local endpoint to carry connections to. Defaults to
        /// `127.0.0.1:<port>` — the same port, which is the case worth optimising.
        at: Option<std::net::SocketAddr>,
    },
    /// Bring up the local entry point for a room's services: a SOCKS5 proxy on `bind`
    /// that resolves that room's `.vox` name and carries connections to its host
    /// (ADR-017 decision 5) — what `vox up` runs.
    ///
    /// Needs no privilege: loopback, a port above 1024, no device, no route and no
    /// resolver entry. A tool reaches it the way a Tor user reaches `SocksPort` — `ssh`
    /// through a `ProxyCommand`, most others through `ALL_PROXY=socks5h://…`.
    ///
    /// The room must be open, because its `.vox` name is derived from the genesis inside
    /// the sealed store (ADR-010's double lock), and only a room this node holds has a
    /// name at all.
    Up {
        /// The room whose services this proxy carries.
        channel_id: Digest32,
        /// Where to listen. Loopback only; `0` picks a port.
        bind: std::net::SocketAddr,
    },
    /// Offer a local TCP service to a channel (ADR-013 Bind). Host configuration:
    /// what a peer may *reach* is the `dial:` capability on the log, granted with
    /// [`NodeCommand::GrantTunnel`]. Requires `bind:<service_tag>` in that channel.
    AddService {
        /// The channel the service is offered in.
        channel_id: Digest32,
        /// The service tag peers dial (the `<tag>` of `dial:<tag>`).
        service_tag: String,
        /// The local address the service listens on.
        local: std::net::SocketAddr,
    },
    /// Stop offering a service.
    RemoveService {
        /// The channel.
        channel_id: Digest32,
        /// The service tag.
        service_tag: String,
    },
    /// Grant a member the capability to dial (and optionally to offer) a service in a
    /// channel, as an ADR-007 admin certificate on the log — a fact every member
    /// converges on, not local configuration (ADR-013).
    GrantTunnel {
        /// The channel.
        channel_id: Digest32,
        /// The member being granted.
        target: Digest32,
        /// The service tag.
        service_tag: String,
        /// Also grant `bind:<tag>`, so the member may offer the service too.
        may_bind: bool,
        /// When the grant stops counting (unix seconds).
        expiry: u64,
    },
    /// Forward a local TCP port to a member's service over the overlay (ADR-013
    /// Dial). Answers [`NodeEvent::Forwarding`] with the port actually bound.
    Forward {
        /// The channel whose capability this claims.
        channel_id: Digest32,
        /// The member hosting the service.
        host: Digest32,
        /// The service tag to reach.
        service_tag: String,
        /// Where to listen locally (port 0 picks one).
        local: std::net::SocketAddr,
    },
    /// Stop a forward and release its port.
    StopForward {
        /// The local address the forward is listening on.
        local: std::net::SocketAddr,
    },
    /// Reconcile a channel's log with the members this node can reach (ADR-008
    /// frontier sync).
    Sync {
        /// The channel.
        channel_id: Digest32,
    },
    /// Stop the actor (locks first).
    Shutdown,
}

/// Why a command did not succeed — closed, machine-stable, redaction-safe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Fault {
    /// The profile has no identity yet.
    NoIdentity,
    /// The profile already has an identity.
    IdentityExists,
    /// The identity is locked.
    Locked,
    /// Wrong passphrase (identity or channel), or a tampered vault/wrap.
    WrongPassphrase,
    /// No such channel in this profile.
    UnknownChannel,
    /// The channel is not open.
    ChannelNotOpen,
    /// An input exceeded its bound (name or text length).
    TooLong,
    /// The store failed; the channel may be poisoned until reopened.
    Storage,
    /// The node is shutting down.
    ShuttingDown,
    /// This node is not networked, or is locked, so it cannot reach anyone.
    NotNetworked,
    /// An invite link would not parse, or named a channel/anchor this node cannot
    /// use.
    BadLink,
    /// A peer could not be reached (no live endpoint, or the dial failed).
    Unreachable,
    /// The remote refused: a join was refused, or a record was rejected.
    Refused,
    /// There is no consent to withdraw: the target was never consented to, or the
    /// consent has already been revoked (ADR-007 — consent is single-writer, so this
    /// is a settled fact, not a race).
    NotConsented,
    /// An internal invariant failed (a bug, never user input).
    Internal,
}

/// The result of a command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// The command succeeded.
    Done,
    /// The command failed for the given reason.
    Failed(Fault),
}

impl Outcome {
    /// Whether the command succeeded.
    #[must_use]
    pub fn is_done(self) -> bool {
        matches!(self, Outcome::Done)
    }
}

/// An ordered node → client event (never coalesced).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum NodeEvent {
    /// A new rendered entry in a channel.
    NewEntry {
        /// The channel.
        channel_id: Digest32,
        /// The rendered entry.
        row: MessageRow,
    },
    /// The identity was unlocked.
    Unlocked,
    /// The identity (and every open channel) was locked.
    Locked,
    /// A channel was opened.
    ChannelOpened {
        /// The channel.
        channel_id: Digest32,
    },
    /// A channel was closed.
    ChannelClosed {
        /// The channel.
        channel_id: Digest32,
    },
    /// A peer completed an ADR-005 join against this node, which verified its
    /// identity and admitted it as a log author. It can read nothing until this
    /// user consents (ADR-007).
    PeerJoined {
        /// The channel joined.
        channel_id: Digest32,
        /// The joiner's verified identity fingerprint.
        peer: Digest32,
    },
    /// A peer's sender key arrived, so that peer's messages become readable. Any
    /// message already held as ciphertext was backfilled.
    SenderKeyReceived {
        /// The channel.
        channel_id: Digest32,
        /// The author who released the key.
        peer: Digest32,
        /// How many already-stored messages became readable.
        backfilled: u64,
    },
    /// A forward is live: the local port is accepting connections for a member's
    /// service (ADR-013).
    Forwarding {
        /// The channel the capability is claimed under.
        channel_id: Digest32,
        /// The member hosting the service.
        host: Digest32,
        /// The service tag.
        service_tag: String,
        /// The local address actually bound (a requested port 0 is resolved here).
        local: std::net::SocketAddr,
    },
    /// An invite link for a channel (public: it carries no secret).
    InviteLink {
        /// The channel.
        channel_id: Digest32,
        /// The `vox://` URL.
        url: String,
    },
    /// This node joined a channel.
    Joined {
        /// The channel joined.
        channel_id: Digest32,
        /// The member that answered the join.
        responder: Digest32,
    },
    /// This identity consented to `target`, which may now read its messages.
    Consented {
        /// The channel.
        channel_id: Digest32,
        /// The member consented to.
        target: Digest32,
    },
    /// This identity revoked `target`, rotating its sender key to a generation
    /// `target` cannot read. `rekeyed` counts the remaining consenters that were
    /// re-keyed immediately; the rest are re-keyed as they become reachable.
    Revoked {
        /// The channel.
        channel_id: Digest32,
        /// The member whose consent was withdrawn.
        target: Digest32,
        /// The new sender-key generation.
        generation: u64,
        /// How many remaining consenters were re-keyed at once.
        rekeyed: u64,
    },
    /// A member reached one of this node's services, and was authorized to.
    ///
    /// The host cannot learn this from the service's own logs: every Vox client reaches
    /// a local service from loopback, so `sshd` records `127.0.0.1` for all of them
    /// (ADR-017 decision 6). The identity is known at the gate — transport-authenticated
    /// and checked against the room's evaluator — so it is reported here.
    ///
    /// Grants only. A refused dial emits nothing, exactly as it tells the dialer
    /// nothing (dark services, ADR-013).
    TunnelServed {
        /// The room whose capability authorized it.
        channel_id: Digest32,
        /// The member that reached the service.
        client: Digest32,
        /// The service reached — for a port-named service (ADR-017), the port.
        service_tag: String,
    },
    /// The local entry point is up: a SOCKS5 proxy carrying one room's services.
    ProxyUp {
        /// The room it carries.
        channel_id: Digest32,
        /// The `.vox` hostname its services answer on.
        hostname: String,
        /// Where it is listening.
        bind: std::net::SocketAddr,
    },
    /// A sync session applied entries to a channel's log.
    Synced {
        /// The channel.
        channel_id: Digest32,
        /// Entries applied to the log.
        applied: u64,
        /// How many of those became readable.
        rendered: u64,
    },
    /// The actor has stopped.
    Shutdown,
}
