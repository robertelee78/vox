//! **Each member's lane state** (ADR-028 W-3): the one chip a lanes view heads a member's column
//! with, derived only from what the room already carries — its posts, the claims they fold to,
//! and whether the member's node is connected. Both clients read it from the node, so the TUI and
//! the macOS app never disagree about who needs the person.
//!
//! The unread half of "needs you" (a message addressed to this node that the person has not read)
//! needs this node's read records, and is not here yet: a member needs you here when its latest
//! `ask` or `blocked` to you is unanswered.

use crate::claim::{Fold, Outcome, Posted, State, CLAIM, RELEASE};
use crate::envelope::work::{ACCEPT, ASK, BLOCKED, RESULT, WORKING};
use crate::envelope::{BYE, HELLO};

/// A member's lane state (ADR-028 W-3), as one chip.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum LaneState {
    /// Its latest `ask` or `blocked` addressed to this node is unanswered.
    NeedsYou,
    /// It holds a claim, and its latest work post is `working` or `accept`.
    Working,
    /// A session of it announced itself (`hello`), and it holds no claim.
    Ready,
    /// Its latest work post is `result`, or it released its claim.
    Done,
    /// No session of it announced itself, or its node is not connected.
    Away,
}

impl LaneState {
    /// The chip's words.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            LaneState::NeedsYou => "needs you",
            LaneState::Working => "working",
            LaneState::Ready => "ready",
            LaneState::Done => "done",
            LaneState::Away => "away",
        }
    }
}

/// The work posts whose latest says what a member is doing.
const WORK_POSTS: &[&str] = &[WORKING, ACCEPT, RESULT];

/// The lane state of `member`, to the node `me`, from the room's `posts` (any order) and their
/// claim `fold` as of `now_millis`; `connected` is whether `member`'s node is reached now.
///
/// In order, the first that holds: **needs you**; **away**; **working**; **done**; **ready**;
/// else away. Away comes before the work states because the chip says whether the member is there
/// now; a question it left for you still needs you.
#[must_use]
pub fn lane(
    posts: &[Posted],
    fold: &Fold,
    me: &[u8; 32],
    member: &[u8; 32],
    connected: bool,
    now_millis: u64,
) -> LaneState {
    let mine = crate::claim::b32(me);
    let mut ordered: Vec<&Posted> = posts.iter().collect();
    ordered.sort_by_key(|p| (p.created_millis, p.entry_hash));
    let theirs = || ordered.iter().filter(|p| p.author == *member);

    // Its latest ask or blocked to me, unless a later post of mine answers it (`re`).
    let asked = theirs().rfind(|p| {
        [ASK, BLOCKED].contains(&p.envelope.kind.as_str()) && p.envelope.is_addressed_to(&mine)
    });
    if let Some(asked) = asked {
        let entry = crate::claim::b32(&asked.entry_hash);
        let answered = ordered.iter().any(|p| {
            p.author == *me
                && (p.created_millis, p.entry_hash) > (asked.created_millis, asked.entry_hash)
                && p.envelope.re.as_deref().map(str::trim) == Some(entry.as_str())
        });
        if !answered {
            return LaneState::NeedsYou;
        }
    }

    // Announced: some session's latest hello or bye is a hello.
    let mut sessions: std::collections::BTreeMap<&str, bool> = std::collections::BTreeMap::new();
    for p in theirs().filter(|p| [HELLO, BYE].contains(&p.envelope.kind.as_str())) {
        sessions.insert(p.envelope.from.as_str(), p.envelope.kind == HELLO);
    }
    if !connected || !sessions.values().any(|on| *on) {
        return LaneState::Away;
    }

    let holds = fold.resources.values().any(|s| match s {
        State::Held {
            owner,
            expires_millis,
            ..
        } => owner.author == *member && expires_millis.is_none_or(|e| e > now_millis),
        State::Pending { .. } => false,
    });
    let work = theirs()
        .rfind(|p| WORK_POSTS.contains(&p.envelope.kind.as_str()))
        .map(|p| p.envelope.kind.as_str());
    if holds && matches!(work, Some(WORKING | ACCEPT)) {
        return LaneState::Working;
    }
    // Its latest claim operation that took effect, a claim or a release.
    let released = theirs()
        .rfind(|p| {
            [CLAIM, RELEASE].contains(&p.envelope.kind.as_str())
                && matches!(fold.outcomes.get(&p.entry_hash), Some(Outcome::Applied))
        })
        .is_some_and(|p| p.envelope.kind == RELEASE);
    if work == Some(RESULT) || (released && !holds) {
        return LaneState::Done;
    }
    if holds {
        // Holding a claim with no work post saying it is under way: present, not ready for more.
        return LaneState::Working;
    }
    LaneState::Ready
}
