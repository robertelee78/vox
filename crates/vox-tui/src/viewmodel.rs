//! The typed core↔UI boundary (ADR-015 §"Typed core↔UI boundary").
//!
//! core→UI carries **latest-wins state** ([`ViewModel`], delivered over a
//! `watch`) and **ordered events that must never coalesce** ([`Event`], over an
//! `mpsc`). UI→core carries [`Command`]s (over an `mpsc`).
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

/// Per-member key-verification state (ADR-007/ADR-015). Distinct from consent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verification {
    /// Trust-on-first-use: seen but not verified. The default for a new member.
    UnverifiedTofu,
    /// Verified via a successful QR scan or numeric safety-code compare.
    Verified,
    /// A previously-known key changed; the member must be re-verified before trust.
    KeyChanged,
}

/// Your **outbound** per-sender consent to a member (ADR-007): whether *they* may
/// read *your* messages. Independent of verification and of inbound visibility.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutboundConsent {
    /// You have consented; the member can read your messages.
    Granted,
    /// You have not consented (or revoked); the member cannot read your messages.
    Revoked,
}

/// Your **inbound** visibility preference for a member (ADR-007): whether you want
/// to render *their* messages. Independent of consent and verification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InboundVisibility {
    /// You render this member's messages.
    Visible,
    /// You have opted out of rendering this member's messages.
    Hidden,
}

/// A member as surfaced to the UI (ADR-015 member pane). Fingerprints and nicknames
/// only — no key material.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemberView {
    /// The member's composite-identity fingerprint (public).
    pub id: Digest32,
    /// A local, user-assigned nickname (or a short fingerprint if unset).
    pub nickname: String,
    /// Key-verification state.
    pub verification: Verification,
    /// Your outbound consent toward this member.
    pub outbound: OutboundConsent,
    /// Your inbound visibility for this member.
    pub inbound: InboundVisibility,
    /// `true` if you have Blocked this member (revoked outbound + hidden inbound).
    /// Block is **not** removal — the member stays listed (ADR-007/ADR-015).
    pub blocked: bool,
    /// The grouped-decimal safety code for verifying this member (ADR-015).
    pub safety_code: String,
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
    /// The render-gated timeline, oldest-first.
    pub timeline: Vec<MessageView>,
    /// This channel's reachability.
    pub reachability: Reachability,
}

/// Overall sync status surfaced in the status bar.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum SyncStatus {
    /// Not connected to any peer/node.
    #[default]
    Idle,
    /// Actively reconciling logs with a peer.
    Syncing,
    /// Up to date with all reachable peers.
    Synced,
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
    /// Whether `mlock` is in effect; `false` surfaces the documented zeroize-only
    /// degradation warning (ADR-015 memory-protection honesty).
    pub mlock_active: bool,
}

/// An ordered core→UI event that must never coalesce (`mpsc`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// A new decryptable entry arrived in a channel (drives unread + notifications).
    NewEntry {
        /// The channel the entry belongs to.
        channel_id: Digest32,
        /// The rendered entry.
        entry: MessageView,
    },
    /// A member's key changed — verification reset to `KeyChanged` (ADR-015).
    KeyChangeAlert {
        /// The affected channel.
        channel_id: Digest32,
        /// The member whose key changed.
        member: Digest32,
    },
    /// A recoverable error to surface in the alert log. A **typed** error, not a
    /// free string, so no plaintext/secret can ever leak through the error channel
    /// (ADR-015 log-redaction). Producers map their failure to a [`UiError`].
    Error(UiError),
}

/// The bounded set of user-facing errors the UI surfaces (ADR-015 §"Error & offline
/// UX"). Each renders to a fixed human string — there is no free-form text path, so
/// an error can never carry plaintext, a key, or a passphrase into the UI/logs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UiError {
    /// Wrong channel passphrase on join.
    WrongPassphrase,
    /// Join proof-of-work is still being computed (Equihash delay).
    JoinPowDelay,
    /// Join proof-of-possession / identity mismatch.
    JoinProofMismatch,
    /// No reachable peer / your node — "both must be online" for a 2-member channel.
    Unreachable,
    /// The channel epoch advanced (passphrase rotation); re-sync needed.
    EpochMismatch,
    /// A per-author quota was exceeded.
    QuotaExceeded,
    /// A member's key changed and must be re-verified before trust.
    KeyChanged,
    /// You have no consent from a member yet ("you'll see them once they consent").
    MissingConsent,
    /// A received entry/structure was malformed (maps ADR-008 wire codes).
    Malformed,
    /// A transport/connection error.
    Transport,
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
            0x06 => UiError::QuotaExceeded,
            0x07 => UiError::EpochMismatch,
            _ => UiError::Malformed,
        }
    }

    /// The fixed, redaction-safe human string for this error.
    #[must_use]
    pub fn message(self) -> &'static str {
        match self {
            UiError::WrongPassphrase => "wrong passphrase",
            UiError::JoinPowDelay => "join proof-of-work in progress…",
            UiError::JoinProofMismatch => "join identity proof failed",
            UiError::Unreachable => "no reachable peer — both must be online (or run your node)",
            UiError::EpochMismatch => "channel epoch changed (passphrase rotated) — re-syncing",
            UiError::QuotaExceeded => "rate/quota exceeded — try again shortly",
            UiError::KeyChanged => "a member's key changed — re-verify before trusting",
            UiError::MissingConsent => "you'll see this member once they consent to you",
            UiError::Malformed => "received a malformed entry (ignored)",
            UiError::Transport => "connection error",
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
    /// Create a channel with a local name and an out-of-band passphrase.
    CreateChannel {
        /// The local name for the new channel.
        local_name: String,
        /// The channel passphrase (out-of-band; redacted/zeroized).
        passphrase: SecretString,
        /// Whether authorship is deniable (genesis-immutable; default attributable).
        deniable: bool,
    },
    /// Join a channel by channelID + passphrase.
    Join {
        /// The local name to give the joined channel.
        local_name: String,
        /// The channelID being joined.
        channel_id: Digest32,
        /// The channel passphrase (out-of-band; redacted/zeroized).
        passphrase: SecretString,
    },
    /// Send text to a channel.
    SendText {
        /// The target channel.
        channel_id: Digest32,
        /// The plaintext to send (becomes ciphertext in the core).
        text: String,
    },
    /// Grant outbound consent to a member.
    GrantConsent {
        /// The channel context.
        channel_id: Digest32,
        /// The member to consent to.
        member: Digest32,
    },
    /// Revoke outbound consent from a member.
    RevokeConsent {
        /// The channel context.
        channel_id: Digest32,
        /// The member to revoke.
        member: Digest32,
    },
    /// Set inbound visibility for a member.
    SetVisibility {
        /// The channel context.
        channel_id: Digest32,
        /// The member.
        member: Digest32,
        /// The desired visibility.
        visibility: InboundVisibility,
    },
    /// Block a member (revoke outbound + hide inbound); not removal.
    Block {
        /// The channel context.
        channel_id: Digest32,
        /// The member to block.
        member: Digest32,
    },
    /// Unblock a member (restore your outbound consent + your inbound preference).
    Unblock {
        /// The channel context.
        channel_id: Digest32,
        /// The member to unblock.
        member: Digest32,
    },
    /// Mark a member verified after a successful scan/compare.
    MarkVerified {
        /// The channel context.
        channel_id: Digest32,
        /// The verified member.
        member: Digest32,
    },
    /// Lock the app now (zeroize SEK + identity root, require re-auth).
    Lock,
}

#[cfg(test)]
mod tests {
    use super::*;

    // The boundary types must be `Send + 'static` so they can cross the tokio
    // channels, and `ViewModel`/`Event` must be `Clone` (watch/broadcast).
    fn assert_send_static<T: Send + 'static>() {}
    fn assert_clone<T: Clone>() {}

    #[test]
    fn boundary_types_are_channel_safe() {
        assert_send_static::<ViewModel>();
        assert_send_static::<Event>();
        assert_send_static::<Command>();
        assert_clone::<ViewModel>();
        assert_clone::<Event>();
    }

    #[test]
    fn message_view_decryptability() {
        let mut m = MessageView {
            author: [1; 32],
            author_nick: "alice".into(),
            timestamp: 100,
            body: Some("hi".into()),
        };
        assert!(m.is_decryptable());
        m.body = None;
        assert!(!m.is_decryptable());
    }

    #[test]
    fn ui_error_messages_are_fixed_and_nonempty() {
        for e in [
            UiError::WrongPassphrase,
            UiError::JoinPowDelay,
            UiError::JoinProofMismatch,
            UiError::Unreachable,
            UiError::EpochMismatch,
            UiError::QuotaExceeded,
            UiError::KeyChanged,
            UiError::MissingConsent,
            UiError::Malformed,
            UiError::Transport,
            UiError::Internal,
        ] {
            assert!(!e.message().is_empty());
            assert_eq!(e.to_string(), e.message());
        }
        // Unknown wire codes never pass through uninterpreted.
        assert_eq!(UiError::from_wire_code(0xFF), UiError::Malformed);
        assert_eq!(UiError::from_wire_code(0x07), UiError::EpochMismatch);
    }

    #[test]
    fn default_view_model_is_empty_and_unlocked_idle() {
        let vm = ViewModel::default();
        assert!(vm.channels.is_empty());
        assert!(vm.active.is_none());
        assert_eq!(vm.sync, SyncStatus::Idle);
        assert!(!vm.locked);
    }
}
