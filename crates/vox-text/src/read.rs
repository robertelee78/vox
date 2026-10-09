//! Where a message this node sent is, while no member is known to have read it (ADR-028 R-6),
//! word for word in the TUI and the app (CL-1).

/// Said under a message this node sent that no other member's node is known to hold.
pub const ONLY_HERE: &str = "only on this machine";

/// Where a message is, from how many of the room's `others` members' nodes said they hold it:
/// "only on this machine", or "on N of M members' nodes". Never from what was sent them.
#[must_use]
pub fn whereabouts(held: u64, others: u64) -> String {
    if held == 0 {
        ONLY_HERE.to_owned()
    } else {
        format!("on {held} of {others} members' nodes")
    }
}
