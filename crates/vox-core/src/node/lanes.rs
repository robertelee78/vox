//! Each member's lane state in a room (ADR-028 W-3), read off the room as this node holds it:
//! [`vox_agentcomms::lanes`] decides, from the room's posts and the claims they fold to; this
//! supplies them, with which members this node reaches now.

use vox_agentcomms::claim::{self, Posted};
use vox_agentcomms::envelope::Envelope;

use crate::hash::Digest32;
use crate::node::api::ChannelDetail;

/// The posts a lane is derived from: presence, work, the claim protocol, and every type a reply
/// to an `ask` or `blocked` is posted as (`answer`, most often).
const LANE_TYPES: &[&str] = {
    use vox_agentcomms::claim::{CLAIM, HANDOFF, RELEASE, RENEW};
    use vox_agentcomms::envelope::work::{
        ACCEPT, ACK, ANSWER, ASK, ASSIGN, BLOCKED, DECLINE, FAILED, NOT_UNDERSTOOD, RESULT, STATUS,
        WORKING,
    };
    use vox_agentcomms::envelope::{BYE, HELLO, SAY};
    &[
        HELLO,
        BYE,
        SAY,
        ASSIGN,
        ACCEPT,
        DECLINE,
        WORKING,
        BLOCKED,
        STATUS,
        RESULT,
        FAILED,
        ASK,
        ANSWER,
        ACK,
        NOT_UNDERSTOOD,
        CLAIM,
        RELEASE,
        HANDOFF,
        RENEW,
    ]
};

/// The version whose claim rules the fold applies: this binary's, as the clients stamp their
/// posts with (ADR-021 §5).
const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Every member of `room` other than `me`, in the room's member order, with its lane state's
/// words; `connected` is the peers this node reaches now.
#[must_use]
pub fn of_room(
    room: &ChannelDetail,
    me: &Digest32,
    connected: &[Digest32],
) -> Vec<(Digest32, String)> {
    // Read through the room's index of structured posts (V210-120), so a board costs the room's
    // agent traffic, not its history. A row not received yet carries no text of its author's.
    let types: Vec<String> = LANE_TYPES.iter().map(|t| (*t).to_owned()).collect();
    let posts: Vec<Posted> = room
        .structured
        .positions(&types, &[])
        .into_iter()
        .filter_map(|i| room.timeline.get(i as usize))
        .filter(|r| !r.owed)
        .filter_map(|r| {
            Some(Posted {
                entry_hash: r.entry_hash,
                author: r.author,
                created_millis: r.created_millis,
                envelope: Envelope::parse(&r.text).ok()?,
            })
        })
        .collect();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
    let fold = claim::fold(&posts, VERSION, now);
    room.members
        .iter()
        .filter(|m| *m != me)
        .map(|m| {
            let state =
                vox_agentcomms::lanes::lane(&posts, &fold, me, m, connected.contains(m), now);
            (*m, state.label().to_owned())
        })
        .collect()
}
