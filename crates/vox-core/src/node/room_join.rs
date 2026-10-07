//! Joining a session's room without holding up its turn (ADR-029 RB-3): the room map names a room
//! the node is not yet a member of, and the join may take seconds, or minutes when no member is
//! online. The hook hands the daemon the room's link and passphrase; the daemon joins in the
//! background and opens the Session once the node is a member
//! ([`crate::node::sessions::open_when_member`]).
//!
//! A join that fails is told to the session on its next turn, with why, and tried again then: the
//! hook hands the daemon the map's link and passphrase on every turn of a session whose room the
//! node is not yet a member of. One join per room runs at a time.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use zeroize::Zeroizing;

use crate::node::actor::NodeHandle;
use crate::node::sessions::Opening;

/// One node's joins under way: what each says, by room (its id in base32). Held by whatever
/// attached the node (the daemon), one per node: a process may host several (ADR-026 P-1).
#[derive(Debug, Default)]
pub struct Joins {
    status: Mutex<BTreeMap<String, String>>,
    /// The rooms a join is running for now.
    running: Mutex<BTreeSet<String>>,
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

    /// Whether a join of `room` is running now: its Session is not open there yet.
    #[must_use]
    pub fn under_way(&self, room: &str) -> bool {
        self.running
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .contains(room)
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

/// How a status that says a join failed begins.
const FAILED: &str = "could not join room";

/// Start joining `room` from `link` with `passphrase`, and open `session`'s Session once the node is
/// a member. Returns at once: how it goes is told to the session on its next turn
/// ([`Joins::status`]). A join of `room` already running is left to finish; this one is dropped.
pub fn join_in_background(
    handle: &NodeHandle,
    joins: &Arc<Joins>,
    room: &str,
    link: &str,
    passphrase: Zeroizing<String>,
    session: Opening,
) {
    if !joins
        .running
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert(room.to_owned())
    {
        return;
    }
    // The room as a person reads it in a sentence: its id's start, as `vox room list` shows it.
    let named: String = room.chars().take(12).collect();
    // **A failure is told before it is tried again**: the next turn's registration starts the retry
    // and reads the status right after, so a retry that only said "joining" again would hide why the
    // last one failed from the session for ever.
    let failed = joins.status(room).filter(|s| s.starts_with(FAILED));
    joins.set_status(
        room,
        Some(match failed {
            Some(why) => format!("{why}; joining it again…"),
            None => format!("joining room {named}…"),
        }),
    );
    let (handle, joins, room, link) = (
        handle.clone(),
        Arc::clone(joins),
        room.to_owned(),
        link.to_owned(),
    );
    tokio::spawn(async move {
        let outcome = handle
            .apply(crate::node::api::NodeCommand::JoinChannel {
                link,
                passphrase: crate::node::api::Secret::new(passphrase.as_bytes().to_vec()),
            })
            .await;
        let said = match outcome {
            crate::node::api::Outcome::Done => match crate::node::link::b32_decode(&room, "room") {
                Ok(id) => crate::node::sessions::open_when_member(&handle, id, &session)
                    .await
                    .err()
                    .map(|e| {
                        format!("joined room {named}, and could not open this session there: {e}")
                    }),
                Err(e) => Some(format!("joined room {named}, and could not name it: {e}")),
            },
            other => Some(format!("{FAILED} {named}: {other}")),
        };
        joins.set_status(&room, said);
        joins
            .running
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&room);
    });
}
