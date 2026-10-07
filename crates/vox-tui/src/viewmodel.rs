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
        /// Whether it released its key to you here, which a node does only for a member its
        /// keyring trusts: so it trusts you too (ADR-028 L-4's `⇄`).
        trusts_you: bool,
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
    /// What your keyring entry for it grants, read or read + drive (ADR-028 K-14); `None` for
    /// you and for a member not in your keyring.
    pub capability: Option<vox_core::node::trust::Capability>,
}

/// One line the timeline tells about the room, not a message (ADR-028 E-5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NoticeView {
    /// When, milliseconds since the Unix epoch, as a message's `timestamp` is: the timeline orders
    /// by it, so it is never rounded (a change made just after a post, in the same second, drew
    /// above it).
    pub timestamp: u64,
    /// The whole line: `ann renamed the room to family`.
    pub text: String,
    /// The message it follows in the room's order, where it is drawn (#562); `None`, or a message
    /// not in the timeline, places it by `timestamp`.
    pub after: Option<Digest32>,
}

/// A timeline entry as surfaced to the UI. Carries decrypted display text only when
/// the entry is render-gated *to you*; otherwise an honest non-leaking marker.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MessageView {
    /// The message's entry hash.
    pub entry_hash: Digest32,
    /// The author's composite-identity fingerprint (public).
    pub author: Digest32,
    /// The author's local nickname.
    pub author_nick: String,
    /// Who an addressed message is to, as this node names each (PRD-001 R15): `to you, bob`,
    /// or empty for a message to the whole room.
    pub addressed: String,
    /// Wall-clock send time (epoch-milliseconds) as recorded in the entry; rounded only where it
    /// is shown.
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
    /// Under a share this node sent, who has pulled it whole, by this node's names for them, from
    /// its daemon's record of completed fetches (ADR-028 F-7): `agent-2`; empty when nobody has.
    pub pulled_by: String,
    /// Under a message this node sent that no member is known to have read, where it is (ADR-028
    /// R-6): "only on this machine", or "on N of M members' nodes" from what their nodes said they
    /// hold. Empty when the node does not say.
    pub whereabouts: String,
    /// The one message this replies to, quoted (ADR-028 R-9, #485): the entry its `re` names,
    /// never that one's own quote or the thread's root.
    pub quote: Option<QuoteView>,
    /// An image this message shares (ADR-028 F-9, F-11): drawn inline once verified.
    pub image: Option<ImageView>,
}

/// **An image a message shares** (ADR-028 F-11, #502): drawn only once this node's copy is verified.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImageView {
    /// Its file name, as announced.
    pub name: String,
    /// Its width and height in pixels, as announced.
    pub width: u64,
    /// Its height.
    pub height: u64,
    /// Where this node's copy stands: drawn only once it is verified and decoded.
    pub state: ImageState,
}

/// **Where a shared image stands on this node** (ADR-028 F-11): its copy is hashed and decoded
/// off the TUI's thread, and only an image that is both verified and decoded is drawn.
#[derive(Clone, Debug)]
pub enum ImageState {
    /// Not pulled here, its copy not yet checked, or its bytes not what was announced.
    Unverified,
    /// Verified, and decoded within the limits the sharer's daemon decodes with (and scaled to
    /// at most [`crate::images::DECODED_EDGE`] on its longest edge): ready to draw.
    Ready(std::sync::Arc<image::DynamicImage>),
    /// Verified, and not drawn here: why, in words.
    NotDrawn(&'static str),
}

impl PartialEq for ImageState {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Unverified, Self::Unverified) => true,
            (Self::Ready(a), Self::Ready(b)) => std::sync::Arc::ptr_eq(a, b),
            (Self::NotDrawn(a), Self::NotDrawn(b)) => a == b,
            _ => false,
        }
    }
}

impl Eq for ImageState {}

/// **A reply's quote: one level** (ADR-028 R-9, #485): the message its `re` names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuoteView {
    /// The quoted entry, which selecting the quote jumps to.
    pub entry_hash: Digest32,
    /// `alice: its first line`, or `None` while this room does not hold that entry.
    pub text: Option<String>,
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
    /// The room's shared name (ADR-028 R-1), or its short id while it has none or is closed.
    pub name: String,
    /// Unread messages addressed to this node (their `to` names it): the first level (ADR-028
    /// R-8, #484).
    pub to_you: usize,
    /// Other unread messages: the second level.
    pub unread: usize,
    /// Unread coordination traffic (presence, progress, claims), counted only: the third level.
    pub coordination: usize,
    /// Approvals and questions waiting on this node in Sessions it may drive here (ADR-029
    /// CL-2).
    pub waiting: usize,
    /// What the room needs from the person, which group the sidebar lists it under (ADR-028 W-2,
    /// #511).
    pub group: vox_agentcomms::attention::RoomGroup,
    /// Channel reachability.
    pub reachability: Reachability,
}

/// The fully-rendered active-channel view.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct ChannelView {
    /// The channelID.
    pub channel_id: Digest32,
    /// The room's shared name (ADR-028 R-1), or its short id while it has none.
    pub name: String,
    /// What a person is told happened to the room, in its order, each with who did it, by
    /// this node's name for them: `ann renamed the room to family` (ADR-028 E-5).
    pub notices: Vec<NoticeView>,
    /// The retention this node applies here, as a person reads it ("1 week", "forever"): what the
    /// room's header always shows (ADR-028 R-7).
    pub retention: String,
    /// The members, in display order.
    pub members: Vec<MemberView>,
    /// The render-gated timeline, oldest-first. Shared with the core, which adds a new
    /// message's row to it rather than projecting the whole room again on every frame
    /// (V210-120).
    pub timeline: std::sync::Arc<Vec<MessageView>>,
    /// One notice per member this node holds back for equivocating here (V210-63, V210-66), by
    /// the name this operator gave them; drawn above the timeline, **each on its own line**.
    pub held_back: Vec<String>,
    /// The services shared in the room (V030-25, ADR-028 S-3).
    pub shared: Vec<SharedView>,
    /// The room's Sessions, open and ended, newest opening first (ADR-029 CL-2).
    pub sessions: Vec<SessionView>,
    /// The lines of the Session on screen, for a member with drive (ADR-029 SC-1): one per
    /// activity, in the words `vox room session` prints. Empty while none is shown.
    pub session_lines: Vec<SessionLineView>,
    /// This channel's reachability.
    pub reachability: Reachability,
}

/// One service shared in a room, as the TUI shows it (ADR-028 S-3).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SharedView {
    /// `<address> by <who>  <kind>`: its readable address in this operator's own aliases
    /// (fingerprints where it has none), who shared it, and what it is.
    pub line: String,
    /// The command a copy gives, carrying the canonical address (S-1) so it works pasted on any
    /// member's machine: the first of its kind's commands.
    pub copy: String,
    /// What it needs that does not hold, each in words; empty when nothing is missing.
    pub missing: Vec<String>,
}

/// One Session in a room, as the TUI lists it (ADR-029 SE-3, CL-2).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SessionView {
    /// The node whose harness session it is.
    pub node: Digest32,
    /// The harness's own session id, as its node claims it (SE-2, MD-3).
    pub id: String,
    /// The session's current name, as its node claims it (MD-1); `None` when the harness gives
    /// none.
    pub name: Option<String>,
    /// `codex@device-2 · gso-cap · 3f0c25bf`: this node's alias for the session's node, the
    /// session's name, and its short id (SE-3).
    pub label: String,
    /// This node's alias for the session's node, as the label begins.
    pub node_alias: String,
    /// When it opened, milliseconds since the Unix epoch.
    pub opened: u64,
    /// When it ended, milliseconds since the Unix epoch; `None` while it is open (SE-5).
    pub ended: Option<u64>,
    /// Whether the session's node trusts this node with drive (SC-2, CL-3).
    pub can_drive: bool,
    /// An approval or a question in it waits on this node (CL-2).
    pub waiting: bool,
}

/// What a driver sends a Session (ADR-029 DR-1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DriveAct {
    /// Text typed into the session as its operator.
    Say(String),
    /// A slash command: `/compact`, `/clear`, `/rename <name>`.
    Slash(String),
    /// Interrupt it (its Esc).
    Interrupt,
    /// Stop it (its Ctrl-C).
    Stop,
    /// Approve the approval request with this ref (DR-1.4).
    Approve(String),
    /// Reject the approval request with this ref, with the reason the model is given, if any.
    Reject(String, Option<String>),
    /// Answer the question request with this ref: for each question, an option's number as shown
    /// or text typed as the answer (DR-1.5).
    Answer(String, Vec<(crate::session_drive_ui::Question, String)>),
    /// Send the session the file or folder at this path, with a note (DR-1.7).
    File(String, Option<String>),
}

/// One activity of a Session, as the reader sees it (ADR-029 SC-1).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SessionLineView {
    /// The one line.
    pub text: String,
    /// Its full input and output, labelled, in order: Details.
    pub details: Vec<(String, String)>,
    /// The harness's id for the request it is about (`ref`), empty for none.
    pub reference: String,
    /// What it waits for from a driver: an open approval or question, or `None` (DR-1.4, DR-1.5).
    pub waiting: Option<crate::session_cli::Waiting>,
    /// A waiting question's questions and their options, for an answer.
    pub questions: Vec<crate::session_drive_ui::Question>,
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
    /// Every node on this machine, by name, and whether it is attached (ADR-028 W-1, #511).
    pub machine_nodes: Vec<(String, bool)>,
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
    /// The trust keyring, `(fingerprint, alias)`, for the keyring view (ADR-028 W-1, K-1).
    pub keyring: Vec<(vox_core::hash::Digest32, String)>,
    /// The members offered to the keyring (ADR-028 K-15 – K-18), in fingerprint order.
    pub offers: Vec<vox_core::node::api::Offer>,
    /// What this node decided, newest first, from its decision record (ADR-028 D-3).
    pub decisions: Vec<vox_core::node::decisions::Event>,
    /// What listens on this machine, for sharing one into a room (ADR-028 S-4), as `vox serve`
    /// lists it; empty until the share flow asks.
    pub listening: Vec<ListeningView>,
    /// The service the share flow is about to offer, and what is said before it is (S-4).
    pub serve_preview: Option<ServePreview>,
}

/// One service listening on this machine, as the share flow lists it (ADR-028 S-4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListeningView {
    /// Its program, where it listens, and over what: `vox serve`'s line.
    pub line: String,
    /// Its port.
    pub port: u16,
    /// Whether it takes datagrams.
    pub udp: bool,
}

/// A service about to be offered in a room, and what the person is told first (ADR-028 S-4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServePreview {
    /// The room.
    pub channel_id: Digest32,
    /// The tag it is offered under: its suggested name, `udp/` before it for datagrams.
    pub tag: String,
    /// Where it listens, which the room's members are carried to.
    pub local: std::net::SocketAddr,
    /// What is said before it is offered: its address, who can reach it and who cannot, and
    /// each warning.
    pub lines: Vec<String>,
}

/// The bounded set of user-facing errors the UI surfaces (ADR-015 §"Error & offline
/// UX"). Each renders to a fixed human string — there is no free-form text path, so
/// an error can never carry plaintext, a key, or a passphrase into the UI/logs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UiError {
    /// Wrong room passphrase on join.
    WrongPassphrase,
    /// An identity was to be made with an empty passphrase (ADR-028 K-11).
    PassphraseEmpty,
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
            UiError::PassphraseEmpty => {
                "every node has an identity passphrase; an empty one is refused"
            }
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
    /// Drive the Session on screen (ADR-029 DR-1): what it is sent, said back in words.
    Drive {
        /// The room.
        channel_id: Digest32,
        /// The Session's node and the harness's session id.
        session: (Digest32, String),
        /// What it is sent.
        act: DriveAct,
    },
    /// The Session the room's timeline now shows, by its node and session id; `None` for General
    /// or All (ADR-029 CL-2).
    ShowSession {
        /// The room.
        channel_id: Digest32,
        /// The Session's node and the harness's session id.
        session: Option<(Digest32, String)>,
    },
    /// Create a room under its shared name (ADR-028 R-1) with an out-of-band passphrase.
    CreateChannel {
        /// The room's name, one DNS label.
        name: String,
        /// The channel passphrase (out-of-band; redacted/zeroized).
        passphrase: SecretString,
    },
    /// Join a channel from a `vox://` invite link plus the passphrase, which travels
    /// out of band and is deliberately **not** in the link (ADR-016).
    Join {
        /// The `vox://` invite link.
        link: String,
        /// The channel passphrase (out-of-band; redacted/zeroized).
        passphrase: SecretString,
    },
    /// Name a room for every member (ADR-028 R-1); its creator or an admin only.
    RenameRoom {
        /// The room.
        channel_id: Digest32,
        /// The new name, one DNS label. No passphrase is asked for (ADR-028 K-11).
        name: String,
    },
    /// Accept the offer of a node (ADR-028 K-16): add it to the keyring under a name, granting
    /// read, or read + drive, as `vox trust add` does.
    AcceptOffer {
        /// The node.
        target: Digest32,
        /// The person's name for it.
        petname: String,
        /// Whether it may drive this node's sessions too (ADR-028 K-14).
        drive: bool,
        /// The identity passphrase, empty while the keyring window is open (redacted/zeroized).
        identity_passphrase: SecretString,
    },
    /// Dismiss the offer of a node (ADR-028 K-18): on this node alone, and silently.
    DismissOffer {
        /// The node.
        member: Digest32,
    },
    /// Add a node to the keyring under a name (ADR-028 K-3, K-5), as `vox trust add` does, once
    /// the person has compared its fingerprint.
    Trust {
        /// The node.
        target: Digest32,
        /// The person's name for it.
        petname: String,
        /// The identity passphrase, empty while the keyring window is open (redacted/zeroized).
        identity_passphrase: SecretString,
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
    /// List what listens on this machine, for the share flow (ADR-028 S-4).
    ProbeListening,
    /// Say what offering the service listening on `port` in a room would do, before it is done
    /// (S-4): `udp` picks one of two on the same port; `None` takes the first.
    PreviewServe {
        /// The room.
        channel_id: Digest32,
        /// The service's port.
        port: u16,
        /// Datagrams or connections, when the person picked one.
        udp: Option<bool>,
    },
    /// Offer the previewed service in its room (S-4), as `vox service add` does.
    OfferService,
    /// Drop the share flow's preview.
    CancelServe,
    /// Share a file or folder in a room from the composer (ADR-028 F-1): its note the composer's
    /// words, addressed and urgent as the composer is, as `vox share` does.
    ShareFile {
        /// The room.
        channel_id: Digest32,
        /// The file or folder, as the person typed it.
        path: String,
        /// The note: the composer's words, if any.
        note: String,
        /// The members it is for.
        to: Vec<Digest32>,
        /// Whether it may interrupt their agents.
        urgent: bool,
    },
    /// Post `text` to a channel addressed, urgent, or both (ADR-028 W-4): the one way a
    /// structured message is posted, as `vox room post --to … --urgent` posts it.
    PostAddressed {
        /// The target channel.
        channel_id: Digest32,
        /// The message's words.
        text: String,
        /// The members it is to.
        to: Vec<Digest32>,
        /// Whether it may interrupt their agents.
        urgent: bool,
        /// The entry it replies to, if it is a reply.
        re: Option<Digest32>,
    },
    /// Send `text` to a channel as a reply to its entry `re` (ADR-028 R-9, #485).
    Reply {
        /// The target channel.
        channel_id: Digest32,
        /// The entry replied to.
        re: Digest32,
        /// The reply's words.
        text: String,
    },
}
