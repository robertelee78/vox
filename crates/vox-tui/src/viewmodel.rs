//! The typed core↔UI boundary (ADR-015 §"Typed core↔UI boundary").
//!
//! core→UI carries **latest-wins state** ([`ViewModel`]); UI→core carries
//! [`Command`]s.
//!
//! ## Binding contract: no secrets cross here
//! Every type in this module carries **only rendered/redacted view data** —
//! identity *fingerprints* (public), nicknames, already-decrypted display text,
//! and enum state. It deliberately holds **no** raw keys, SKDMs, passphrases, the
//! SEK, or `self_seed`; those never leave `vox-core` secret types. The composer
//! passphrase a [`Command`] must carry on create/join is wrapped in
//! [`secrecy::SecretString`] so it is redacted in logs and zeroized on drop — the
//! single, deliberate exception, and even it is a transient input, never retained
//! in a [`ViewModel`].

use secrecy::SecretString;
use vox_core::hash::Digest32;

/// Where a member stands with you here: trust is yours to give, per member (ADR-020 §3). Your node
/// takes a member's key only if your trust keyring names it, and releases yours only to such a
/// member (V210-148). Read off the keyring and the room's log; nothing in the TUI sets it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Trust {
    /// The member is you.
    You,
    /// Your keyring names the member: your node takes its key and releases yours to it.
    Trusted {
        /// Whether it holds your key here, so it can read what you write.
        reads_you: bool,
    },
    /// Your keyring does not name the member: your node refuses its key, so you cannot read it.
    NotTrusted {
        /// Whether it still holds your key here.
        reads_you: bool,
    },
}

/// A member as surfaced to the UI (ADR-015 member pane). Fingerprints and nicknames
/// only — no key material.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemberView {
    /// The member's composite-identity fingerprint (public).
    pub id: Digest32,
    /// A local, user-assigned nickname (or a short fingerprint if unset).
    pub nickname: String,
    /// Where the member stands with you.
    pub trust: Trust,
}

/// A timeline entry as surfaced to the UI. Carries decrypted display text only when
/// the entry is render-gated *to you*; otherwise an honest non-leaking marker.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MessageView {
    /// The author's composite-identity fingerprint (public).
    pub author: Digest32,
    /// The author's local nickname.
    pub author_nick: String,
    /// Who an addressed message is to, as this node names each (PRD-001 R15): `to you, bob`,
    /// or empty for a message to the whole room.
    pub addressed: String,
    /// Wall-clock send time (epoch-seconds) as recorded in the entry.
    pub timestamp: u64,
    /// The rendered body if decryptable to you, else `None` (shown as a marker).
    pub body: Option<String>,
    /// It arrived after rows below it had already been shown: a member who was offline,
    /// or a sync that caught up (ADR-023 decision 1). Shown in its true place, marked.
    pub late: bool,
    /// Under a message this node sent, who has read it, by this node's names for them, as the
    /// read records it can open say (ADR-028 R-6, RR-3): `ann, bea`; empty when it knows of no
    /// reader. A member that does not trust this node is never here, read or not.
    pub read_by: String,
}

impl MessageView {
    /// `true` if this entry decrypted to displayable text for you.
    #[must_use]
    pub fn is_decryptable(&self) -> bool {
        self.body.is_some()
    }
}

/// Per-channel reachability, surfaced honestly (ADR-015 emergent availability).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Reachability {
    /// At least one peer (or your node) is reachable; sync can make progress.
    Online,
    /// A two-member channel where the other side (or your node) must be online.
    NeedsPeerOrNode,
    /// No reachable peer; outbound is queued, nothing arrives. The safe default.
    #[default]
    Offline,
}

/// A channel summary for the home list (ADR-015 home = channel list).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChannelSummary {
    /// Whether the channel is **open** (its SEK unlocked) in this session. A closed
    /// channel's local name is under the channel lock (ADR-010 double-lock), so it
    /// is listed by a short id until opened.
    pub open: bool,
    /// The channelID (`SHA-256(genesis)`).
    pub channel_id: Digest32,
    /// The local, user-assigned channel name.
    pub local_name: String,
    /// Count of unread decryptable entries.
    pub unread: usize,
    /// Channel reachability.
    pub reachability: Reachability,
}

/// The fully-rendered active-channel view.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct ChannelView {
    /// The channelID.
    pub channel_id: Digest32,
    /// The local channel name.
    pub local_name: String,
    /// The members, in display order.
    pub members: Vec<MemberView>,
    /// The render-gated timeline, oldest-first. Shared with the core, which adds a new
    /// message's row to it rather than projecting the whole room again on every frame
    /// (V210-120).
    pub timeline: std::sync::Arc<Vec<MessageView>>,
    /// One notice per member this node holds back for equivocating here (V210-63, V210-66), by
    /// the name this operator gave them; drawn above the timeline, **each on its own line**.
    pub held_back: Vec<String>,
    /// The services shared in the room (V030-25), each as `<address> by <who>`: its address in
    /// this operator's own aliases (fingerprints where it has none), and who shared it.
    pub shared: Vec<String>,
    /// This channel's reachability.
    pub reachability: Reachability,
}

/// Overall sync status surfaced in the status bar: what the node can say, which is how many
/// peers it holds a connection to (V210-82). It keeps no gauge of sessions in flight or of being
/// caught up, so the bar claims neither.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum SyncStatus {
    /// Not connected to any peer/node.
    #[default]
    Idle,
    /// Connected to this many peers (at least one), with which rooms sync.
    Connected(usize),
}

/// The latest-wins UI state (core→UI over a `watch`). Cloneable and free of
/// secrets, so it is safe to broadcast.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct ViewModel {
    /// The home channel list.
    pub channels: Vec<ChannelSummary>,
    /// The active channel, if one is open.
    pub active: Option<ChannelView>,
    /// Overall sync status.
    pub sync: SyncStatus,
    /// Whether the node this TUI acts as is attached to the daemon and this TUI uses it. There is
    /// no locked state (ADR-026 N-2): a node not attached waits for its passphrase to attach it.
    pub attached: bool,
    /// The node this TUI acts as: whose rooms are on screen (ADR-026 S-4).
    pub node: String,
    /// The nodes attached to the daemon now, by name, kept from its attach and detach events
    /// (ADR-015 9.1).
    pub nodes: Vec<String>,
    /// How many seconds a keyring change still goes without the identity passphrase, or `None`
    /// when the next one will ask for it (ADR-028 K-9).
    pub keyring_open_secs: Option<u64>,
    /// Whether `mlock` is in effect; `false` surfaces the documented zeroize-only
    /// degradation warning (ADR-015 memory-protection honesty).
    pub mlock_active: bool,
    /// Whether the profile has an identity at all (`false` ⇒ onboarding: create one).
    pub has_identity: bool,
    /// A short, non-secret line the core wants shown: the most recent invite link,
    /// join, consent or sync notice. Public facts only — never plaintext or key
    /// material (ADR-015's rule for the status channel), and never free-form text
    /// derived from a message.
    pub notice: Option<String>,
    /// Every live tunnel, as `vox status` lists them (V030-11).
    pub tunnels: Vec<vox_core::transport::quic::LiveTunnel>,
    /// The tunnels that ended for a reason a person should see, with that reason (V030-11).
    pub closed_tunnels: Vec<vox_core::transport::quic::ClosedTunnel>,
}

/// The bounded set of user-facing errors the UI surfaces (ADR-015 §"Error & offline
/// UX"). Each renders to a fixed human string — there is no free-form text path, so
/// an error can never carry plaintext, a key, or a passphrase into the UI/logs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UiError {
    /// Wrong room passphrase on join.
    WrongPassphrase,
    /// The identity opened, but what it sealed in the store would not (V210-40).
    SealedUnreadable,
    /// Join proof-of-work is still being computed (Equihash delay).
    JoinPowDelay,
    /// This device took longer to solve a join's proof of work than the member waits (V210-87).
    JoinPowTooSlow,
    /// Every member that answered a join was busy answering others (V210-92).
    JoinMembersBusy,
    /// The room is at its cap, so the join was refused (V210-128).
    JoinRoomFull,
    /// A member accepted the passphrase and then could not admit this identity (V210-128).
    JoinNotAdmitted,
    /// Join proof-of-possession / identity mismatch.
    JoinProofMismatch,
    /// No reachable peer / your node — "both must be online" for a 2-member channel.
    Unreachable,
    /// The channel epoch advanced (passphrase rotation); re-sync needed.
    EpochMismatch,
    /// You have no consent from a member yet ("you'll see them once they consent").
    MissingConsent,
    /// A received entry/structure was malformed (maps ADR-008 wire codes).
    Malformed,
    /// A transport/connection error.
    Transport,
    /// The profile has no identity yet (create one with `:init`).
    NoIdentity,
    /// The profile already has an identity.
    IdentityExists,
    /// The profile had no identity when this TUI started, and another vox created one since:
    /// nothing was created here (V210-100, the CLI's V210-91 refusal).
    IdentityMadeElsewhere,
    /// Another vox holds this node open for writing.
    ProfileBusy,
    /// The node this TUI acts as is not attached: give its passphrase (`:attach`).
    NotAttached,
    /// The channel is not open (select it and enter its passphrase).
    ChannelNotOpen,
    /// An input exceeded its bound (name or message length).
    TooLong,
    /// The trust keyring holds its maximum number of identities.
    KeyringFull,
    /// A write to this node's files failed for a reason the TUI has no fault for. A fault that
    /// names its file is shown in its own words instead (`live::failed`).
    Storage,
    /// The tunnel to close is no longer open (V030-11).
    NoSuchTunnel,
    /// The other side refused: the channel passphrase is wrong, or it is not
    /// accepting joins for that channel. Deliberately coarse — the responder does not
    /// say which, so neither does this (ADR-005).
    Refused,
    /// There is no consent to withdraw from that member.
    NotConsented,
    /// A consent named a member this node has not admitted to the room yet.
    NotAdmitted,
    /// The node is not networked, so it cannot reach anyone.
    NotNetworked,
    /// A local address the node needs (its listen port) is held by another program.
    AddressInUse,
    /// A local address the node was asked to listen on is not an address of this machine.
    AddressNotHere,
    /// A local address the node was asked to listen on could not be bound for another reason.
    BindFailed,
    /// A join named a room this profile already holds.
    AlreadyMember,
    /// The room has ended: it takes no new message (V030-08).
    RoomEnded,
    /// No other member could be told of the leave within 30 s; the node leaves once one can
    /// (V210-164).
    LeaveNotHeard,
    /// Something was written in the room after the leave, so this node is in it again (V210-164).
    LeaveUndone,
    /// Only the room's creator, or an admin it delegated, may do that (V030-08).
    NotCreator,
    /// The room was joined a moment ago and is still being read (V030-08).
    StillJoining,
    /// An unexpected internal error (never carries detail).
    Internal,
}

impl UiError {
    /// Map an ADR-008 wire error code (`0x01`–`0x08`) to a UI error. Unknown codes
    /// fall to [`UiError::Malformed`] (never an uninterpreted passthrough).
    #[must_use]
    pub fn from_wire_code(code: u8) -> Self {
        match code {
            0x05 => UiError::JoinProofMismatch,
            0x07 => UiError::EpochMismatch,
            _ => UiError::Malformed,
        }
    }

    /// The fixed, redaction-safe human string for this error.
    #[must_use]
    pub fn message(self) -> &'static str {
        match self {
            UiError::WrongPassphrase => "wrong passphrase",
            UiError::SealedUnreadable => {
                "passphrase right, but this node's keyring or prekeys will not open — altered, or another identity's"
            }
            UiError::JoinPowDelay => "join proof-of-work in progress…",
            UiError::JoinPowTooSlow => {
                "this device solved the join's proof of work too slowly for the member — try when it is less busy"
            }
            UiError::JoinMembersBusy => {
                "a member is busy answering other joins — try again shortly"
            }
            UiError::JoinRoomFull => {
                "the room is full — nobody else can join (your passphrase was accepted)"
            }
            UiError::JoinNotAdmitted => {
                "a member accepted your passphrase but could not admit you (it was locking or closing) — try again"
            }
            UiError::JoinProofMismatch => "join identity proof failed",
            UiError::Unreachable => "no reachable peer — the host or a member must be online",
            UiError::EpochMismatch => "the room's passphrase was changed — re-syncing",
            UiError::MissingConsent => "you'll see this member once they trust you",
            UiError::Malformed => "received a malformed entry (ignored)",
            UiError::Transport => "connection error",
            UiError::NoIdentity => "no identity yet — :init to create one",
            UiError::IdentityExists => "an identity already exists on this node",
            UiError::IdentityMadeElsewhere => {
                "another vox created this node's identity at the same time; nothing was created here — :attach with its passphrase"
            }
            UiError::ProfileBusy => {
                "another vox is still running as this node — stop it, then try again"
            }
            UiError::NotAttached => "this node is not attached — :attach and give its passphrase",
            UiError::ChannelNotOpen => "this room is not open — select it and enter its passphrase",
            UiError::TooLong => "too long",
            // The cap in force (#85), as `Fault::KeyringFull` names it.
            UiError::KeyringFull => {
                static TEXT: std::sync::OnceLock<String> = std::sync::OnceLock::new();
                TEXT.get_or_init(|| {
                    format!(
                        "your trust keyring is full ({}) — remove one first",
                        vox_core::node::trust::trust_cap_words()
                    )
                })
            }
            UiError::Storage => "could not write this node's files — check free disk space, and that the data directory is writable",
            UiError::NotConsented => "nothing to withdraw — you never trusted this member",
            UiError::NotAdmitted => "that member is not admitted here yet — try again once synced",
            UiError::NoSuchTunnel => "that tunnel is no longer open",
            UiError::Refused => "refused — check the room passphrase",
            UiError::NotNetworked => "this node is not on the network",
            UiError::AddressInUse => {
                "a local port it needs is held by another program — pick another --listen"
            }
            UiError::AddressNotHere => {
                "the --listen address is not an address of this machine — use one it has"
            }
            UiError::BindFailed => "the --listen address could not be listened on",
            UiError::AlreadyMember => "you already hold that room — it is in your list",
            UiError::RoomEnded => {
                "this room has ended — it takes no new message, and this node deletes it soon"
            }
            UiError::LeaveNotHeard => {
                "no other member could be told within 30s — the room goes once one can be"
            }
            UiError::LeaveUndone => "something was written here after :leave — you are in the room again",
            UiError::NotCreator => "only the room's creator, or an admin it delegated, may end it",
            UiError::StillJoining => "joined a moment ago and still reading the room — try again",
            UiError::Internal => "internal error",
        }
    }
}

impl std::fmt::Display for UiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.message())
    }
}

/// The bounded result of applying a [`Command`] (core→UI status line). A **typed**
/// status, not a free string, so a core implementation cannot surface arbitrary
/// plaintext/secret detail through the status channel (the same redaction guarantee
/// as [`UiError`]). Each variant maps to a fixed human string.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CommandStatus {
    /// The command succeeded.
    Done,
    /// The action needs a running node that is not attached.
    NeedsNode,
    /// Not connected; the action could not be performed.
    NotConnected,
    /// The action was accepted/queued (informational).
    Queued,
    /// A typed error occurred.
    Failed(UiError),
    /// The daemon's own sentence for a person, where its answer names no fault the UI knows: a
    /// refusal naming a node, a daemon that stopped. Never plaintext or key material: the daemon
    /// and the node word these for a person, from fixed texts and public facts.
    Said(String),
}

impl CommandStatus {
    /// The fixed, redaction-safe human string for this status.
    #[must_use]
    pub fn message(&self) -> String {
        match self {
            CommandStatus::Done => "done".to_owned(),
            CommandStatus::NeedsNode => "needs a running node (attach one to proceed)".to_owned(),
            CommandStatus::NotConnected => "not connected: action not performed".to_owned(),
            CommandStatus::Queued => "queued".to_owned(),
            CommandStatus::Failed(e) => e.message().to_owned(),
            CommandStatus::Said(s) => s.clone(),
        }
    }
}

/// A UI→core command (`mpsc`). The few secret-bearing inputs are wrapped in
/// [`SecretString`] and consumed immediately by the core (never stored in a
/// [`ViewModel`]).
#[derive(Debug)]
pub enum Command {
    /// Create this profile's identity (onboarding; masked prompt).
    CreateIdentity {
        /// The identity passphrase (redacted/zeroized).
        passphrase: SecretString,
    },
    /// Attach the node this TUI acts as, with its identity passphrase (masked prompt): the one
    /// time a node takes it (ADR-026 N-2).
    Attach {
        /// The identity passphrase (redacted/zeroized).
        passphrase: SecretString,
    },
    /// Act as another node of this account from now on (ADR-015 9.1, `:node <name>`).
    UseNode {
        /// Its name.
        name: String,
    },
    /// Open a closed channel: its passphrase is the second lock factor.
    OpenChannel {
        /// The channelID.
        channel_id: Digest32,
        /// The channel passphrase (redacted/zeroized).
        passphrase: SecretString,
    },
    /// Close an open channel (wipes its SEK from memory).
    CloseChannel {
        /// The channelID.
        channel_id: Digest32,
    },
    /// Leave a room (V210-164): the other members are told, then the room is deleted here.
    LeaveRoom {
        /// The channelID.
        channel_id: Digest32,
    },
    /// End a room for everyone (V030-08); its creator only.
    EndRoom {
        /// The channelID.
        channel_id: Digest32,
    },
    /// Close one live tunnel, by its number (V030-11). Nobody is untrusted and no service
    /// removed; its far end is told it was closed.
    CloseTunnel {
        /// The tunnel's number ([`vox_core::transport::quic::LiveTunnel::id`]).
        id: u64,
    },
    /// The UI's active channel changed (`None` = back at the channel list); the
    /// core projects `ViewModel::active` and unread counts from it.
    SelectChannel {
        /// The channel now on screen, if any.
        channel_id: Option<Digest32>,
    },
    /// Create a channel with a local name and an out-of-band passphrase.
    CreateChannel {
        /// The local name for the new channel.
        local_name: String,
        /// The channel passphrase (out-of-band; redacted/zeroized).
        passphrase: SecretString,
    },
    /// Join a channel from a `vox://` invite link plus the passphrase, which travels
    /// out of band and is deliberately **not** in the link (ADR-016).
    Join {
        /// The local name to give the joined channel.
        local_name: String,
        /// The `vox://` invite link.
        link: String,
        /// The channel passphrase (out-of-band; redacted/zeroized).
        passphrase: SecretString,
    },
    /// Ask for a `vox://` invite link for a channel this node holds open. The link
    /// comes back as a notice; it carries no secret.
    Invite {
        /// The channel to invite to.
        channel_id: Digest32,
    },
    /// Send text to a channel.
    SendText {
        /// The target channel.
        channel_id: Digest32,
        /// The plaintext to send (becomes ciphertext in the core).
        text: String,
    },
}
