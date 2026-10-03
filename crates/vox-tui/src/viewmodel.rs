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
    /// Wall-clock send time (epoch-seconds) as recorded in the entry.
    pub timestamp: u64,
    /// The rendered body if decryptable to you, else `None` (shown as a marker).
    pub body: Option<String>,
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
    /// Whether the app is locked (SEK/identity zeroized, re-auth required).
    pub locked: bool,
    /// Whether a lock is under way and waiting for work that holds a secret (V210-94).
    pub locking: bool,
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
}

/// The bounded set of user-facing errors the UI surfaces (ADR-015 §"Error & offline
/// UX"). Each renders to a fixed human string — there is no free-form text path, so
/// an error can never carry plaintext, a key, or a passphrase into the UI/logs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UiError {
    /// Wrong channel passphrase on join.
    WrongPassphrase,
    /// The identity opened, but what it sealed in the store would not (V210-40).
    SealedUnreadable,
    /// Join proof-of-work is still being computed (Equihash delay).
    JoinPowDelay,
    /// This device took longer to solve a join's proof of work than the member waits (V210-87).
    JoinPowTooSlow,
    /// Every member that answered a join was busy answering others (V210-92).
    JoinMembersBusy,
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
    /// Another vox holds this profile open for writing.
    ProfileBusy,
    /// The app is locked (`:unlock`).
    Locked,
    /// The channel is not open (select it and enter its passphrase).
    ChannelNotOpen,
    /// An input exceeded its bound (name or message length).
    TooLong,
    /// The trust keyring holds its maximum number of identities.
    KeyringFull,
    /// Persisting to the store failed; reopen the channel.
    Storage,
    /// The other side refused: the channel passphrase is wrong, or it is not
    /// accepting joins for that channel. Deliberately coarse — the responder does not
    /// say which, so neither does this (ADR-005).
    Refused,
    /// There is no consent to withdraw from that member.
    NotConsented,
    /// A consent named a member this node has not admitted to the room yet.
    NotAdmitted,
    /// This client is not networked, or is locked, so it cannot reach anyone.
    NotNetworked,
    /// A local address the node needs (its listen port) is held by another program.
    AddressInUse,
    /// A local address the node was asked to listen on is not an address of this machine.
    AddressNotHere,
    /// A local address the node was asked to listen on could not be bound for another reason.
    BindFailed,
    /// A join named a room this profile already holds.
    AlreadyMember,
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
                "passphrase right, but this profile's keyring or prekeys will not open — altered, or another identity's"
            }
            UiError::JoinPowDelay => "join proof-of-work in progress…",
            UiError::JoinPowTooSlow => {
                "this device solved the join's proof of work too slowly for the member — try when it is less busy"
            }
            UiError::JoinMembersBusy => {
                "a member is busy answering other joins — try again shortly"
            }
            UiError::JoinProofMismatch => "join identity proof failed",
            UiError::Unreachable => "no reachable peer — the host or a member must be online",
            UiError::EpochMismatch => "channel epoch changed (passphrase rotated) — re-syncing",
            UiError::MissingConsent => "you'll see this member once they consent to you",
            UiError::Malformed => "received a malformed entry (ignored)",
            UiError::Transport => "connection error",
            UiError::NoIdentity => "no identity yet — :init to create one",
            UiError::IdentityExists => "an identity already exists in this profile",
            UiError::IdentityMadeElsewhere => {
                "another vox created this profile's identity at the same time; nothing was created here — restart vox tui to unlock it"
            }
            UiError::ProfileBusy => {
                "another vox holds this profile open — stop it, then try again"
            }
            UiError::Locked => "locked — :unlock",
            UiError::ChannelNotOpen => "channel is not open — select it and enter its passphrase",
            UiError::TooLong => "too long",
            UiError::KeyringFull => "your trust keyring is full (1,024) — remove one first",
            UiError::Storage => "could not save — reopen the channel",
            UiError::NotConsented => "nothing to revoke — this member was never consented to",
            UiError::NotAdmitted => "that member is not admitted here yet — try again once synced",
            UiError::Refused => "refused — check the channel passphrase",
            UiError::NotNetworked => "not connected (unlock first)",
            UiError::AddressInUse => {
                "a local port it needs is held by another program — pick another --listen"
            }
            UiError::AddressNotHere => {
                "the --listen address is not an address of this machine — use one it has"
            }
            UiError::BindFailed => "the --listen address could not be listened on",
            UiError::AlreadyMember => "you already hold that room — it is in your list",
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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommandStatus {
    /// The command succeeded.
    Done,
    /// The app was locked.
    Locked,
    /// The action needs a running node that is not attached.
    NeedsNode,
    /// Not connected; the action could not be performed.
    NotConnected,
    /// The action was accepted/queued (informational).
    Queued,
    /// A typed error occurred.
    Failed(UiError),
}

impl CommandStatus {
    /// The fixed, redaction-safe human string for this status.
    #[must_use]
    pub fn message(self) -> String {
        match self {
            CommandStatus::Done => "done".to_owned(),
            CommandStatus::Locked => "locked".to_owned(),
            CommandStatus::NeedsNode => "needs a running node (attach one to proceed)".to_owned(),
            CommandStatus::NotConnected => "not connected: action not performed".to_owned(),
            CommandStatus::Queued => "queued".to_owned(),
            CommandStatus::Failed(e) => e.message().to_owned(),
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
    /// Unlock the identity (masked prompt).
    Unlock {
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
    /// Lock the app now (zeroize SEK + identity root, require re-auth).
    Lock,
}
