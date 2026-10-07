//! **What a room needs from the person** (ADR-028 R-8, W-2): the one rule both clients draw a
//! room's unread by, so the TUI and the macOS app never disagree about which room needs you.
//!
//! A client counts its unread messages by [`unread_level`] and lists the room under
//! [`group`]'s answer. Nothing here reads a log or keeps a count; it only says what one message
//! is to this node and what a room's counts make it.

use crate::claim::{CLAIM, HANDOFF, RELEASE, RENEW};
use crate::envelope::work::{ACCEPT, ACK, BLOCKED, DECLINE, FAILED, RESULT, STATUS, WORKING};
use crate::envelope::{Envelope, BYE, HELLO, PING, PONG};

/// The envelope types that are agents coordinating rather than talking (V030-18): presence,
/// progress and the claim protocol. A request or a question (`assign`, `ask`, `answer`,
/// `not-understood`) is conversation and is never counted away.
pub const CHATTER: &[&str] = &[
    HELLO, BYE, STATUS, WORKING, BLOCKED, RESULT, FAILED, ACCEPT, DECLINE, ACK, CLAIM, RELEASE,
    HANDOFF, RENEW, PING, PONG,
];

/// **The three unread levels** (ADR-028 R-8): what one unread message is to this node.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum UnreadLevel {
    /// Addressed to this node.
    ToYou,
    /// New, to the room.
    New,
    /// Coordination traffic, counted only (ADR-020 6.6).
    Coordination,
}

/// What the message `text` is to the node `me` (its fingerprint, base32, as `to` names it) when
/// unread: addressed to it, coordination traffic ([`CHATTER`]), or new. Text that is not an
/// envelope is a person talking, so it is new.
#[must_use]
pub fn unread_level(text: &str, me: Option<&str>) -> UnreadLevel {
    let Ok(e) = Envelope::parse(text) else {
        return UnreadLevel::New;
    };
    if me.is_some_and(|me| e.is_addressed_to(me)) {
        UnreadLevel::ToYou
    } else if CHATTER.contains(&e.kind.as_str()) {
        UnreadLevel::Coordination
    } else {
        UnreadLevel::New
    }
}

/// **What a room needs from the person** (ADR-028 W-2): the sidebar's groups, in the order it
/// lists them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RoomGroup {
    /// A message addressed to this node is unread.
    NeedsYou,
    /// New messages are unread.
    Active,
    /// Nothing is unread.
    Quiet,
}

impl RoomGroup {
    /// The group, as the sidebar heads it.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            RoomGroup::NeedsYou => "needs you",
            RoomGroup::Active => "active",
            RoomGroup::Quiet => "quiet",
        }
    }
}

/// The group a room's unread counts, by [`UnreadLevel`], put it in.
///
/// W-2 also makes a room active while a member holds a claim, and needs you for a trust offer or a
/// Session waiting on this node; those are not read here, so a room is grouped by its unread alone.
#[must_use]
pub fn group(to_you: usize, new: usize, coordination: usize) -> RoomGroup {
    if to_you > 0 {
        RoomGroup::NeedsYou
    } else if new > 0 || coordination > 0 {
        RoomGroup::Active
    } else {
        RoomGroup::Quiet
    }
}
