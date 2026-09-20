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

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_send_static<T: Send + 'static>() {}
    fn assert_clone<T: Clone>() {}

    #[test]
    fn boundary_types_are_channel_safe_and_carry_no_secrets_by_type() {
        assert_send_static::<NodeView>();
        assert_send_static::<NodeCommand>();
        assert_send_static::<NodeEvent>();
        assert_send_static::<Outcome>();
        assert_clone::<NodeView>();
        assert_clone::<NodeEvent>();
        // Outcome is Copy: it can never carry a String or a buffer.
        fn assert_copy<T: Copy>() {}
        assert_copy::<Outcome>();
        assert_copy::<Fault>();
    }
}
