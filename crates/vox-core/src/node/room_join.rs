//! Joining a session's room without holding up its turn (ADR-029 RB-3): the room map names a room
//! the node is not yet a member of, and the join may take seconds, or minutes when no member is
//! online. The hook hands the daemon the room's link and passphrase; the daemon joins in the
//! background and opens the Session once the node is a member
//! ([`crate::node::sessions::open_when_member`]).
//!
//! **Stub (#538)**: the join itself is #550's (uxresearch). Until it lands, nothing is joined and
//! the status says so.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use zeroize::Zeroizing;

use crate::node::actor::NodeHandle;
use crate::node::sessions::Opening;

/// One node's joins under way: what each says, by room (its id in base32). Held by whatever
/// attached the node (the daemon), one per node: a process may host several (ADR-026 P-1).
#[derive(Debug, Default)]
pub struct Joins {
    status: Mutex<BTreeMap<String, String>>,
}

impl Joins {
    /// What the join of `room` last said: `joining <room>…`, or why it could not; `None` once
    /// joined, or never asked.
    #[must_use]
    pub fn status(&self, room: &str) -> Option<String> {
        self.status
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(room)
            .cloned()
    }

    /// Record what the join of `room` says now; `None` clears it.
    pub fn set_status(&self, room: &str, said: Option<String>) {
        let mut s = self
            .status
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match said {
            Some(text) => {
                s.insert(room.to_owned(), text);
            }
            None => {
                s.remove(room);
            }
        }
    }
}

/// Start joining `room` from `link` with `passphrase`, and open `session`'s Session once the node is
/// a member. Returns at once: how it goes is told to the session on its next turn
/// ([`Joins::status`]).
pub fn join_in_background(
    handle: &NodeHandle,
    joins: &Arc<Joins>,
    room: &str,
    link: &str,
    passphrase: Zeroizing<String>,
    session: Opening,
) {
    let _ = (handle, link, passphrase, session);
    joins.set_status(
        room,
        Some("joining a room from the room map is not built yet (#550)".into()),
    );
}
