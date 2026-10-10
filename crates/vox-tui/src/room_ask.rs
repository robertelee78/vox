//! **Vox asks the person which room a repo works in** (ADR-029 RB-5 – RB-7).
//!
//! A harness session started in a directory the room map does not name works in no room, and its
//! hook tells the agent to ask the operator. An agent that does not pass it on leaves the person
//! never knowing, so the daemon asks too: every registered session that works in no room, started
//! in a directory with no block in the room map, is an ask, one per directory. Nothing is stored
//! for it: it is read from the sessions' registrations and the map, so a bind, a no, or the
//! sessions ending clears it by itself.
//!
//! A session whose directory is bound to a room its node is not in (its join failed, or never
//! ran) cannot work there either, and is asked about the same way (RB-5a): one bind then serves
//! every harness's node in that directory.
//!
//! Vox.app shows an ask as a banner across its window with what to do about it; the TUI and `vox agent status`
//! show it with the commands that answer it at a terminal.

use std::collections::BTreeMap;

use vox_core::node::daemonipc::{AskingSession, DaemonClient, DaemonFrame, DaemonRequest, RoomAsk};
use vox_core::node::paths::{Account, NodeName};

use crate::app::AppError;

pub use vox_core::node::daemonipc::harness_words;

/// The asks of `account`'s data root, one per directory, ordered by directory; each one's sessions
/// oldest first. A room map that cannot be read gives none: the hook says why to the session.
///
/// `outside(node, room)` says whether `node` is attached, is not in `room` (its id in base32), and
/// is not joining it now: a session of such a node, started in a directory bound to `room`, cannot
/// work there, and is asked about too (RB-5a).
#[must_use]
pub fn asks(account: &Account, outside: &dyn Fn(&NodeName, &str) -> bool) -> Vec<RoomAsk> {
    let Ok(entries) = crate::room_map::read(&account.data_root) else {
        return Vec::new();
    };
    let mut by_dir: BTreeMap<(String, String), Vec<(u64, AskingSession)>> = BTreeMap::new();
    for node in account.nodes_on_disk() {
        let Ok(paths) = account.node_paths(&node) else {
            continue;
        };
        for reg in crate::wake::registered(&paths) {
            // A headless run has no person at it to ask, and a hook run by hand no harness.
            if !reg.interactive || reg.harness == "unknown" {
                continue;
            }
            let Some(start) = reg.start.as_deref().filter(|s| !s.is_empty()) else {
                continue;
            };
            let start = std::path::Path::new(start);
            let room = match crate::room_map::resolve(&entries, start) {
                // No room bound: asked while the session works in none.
                None if reg.room.is_none() => String::new(),
                None => continue,
                Some(e) if e.room == crate::room_map::DECLINED => continue,
                // Bound: asked while the session's node is not in that room, unless the session
                // was moved to another.
                Some(e) => {
                    let Ok(link) = vox_core::node::link::InviteLink::parse(&e.room) else {
                        continue;
                    };
                    let room = vox_core::node::link::b32_encode(&link.channel_id);
                    if reg.room.as_deref().is_some_and(|r| r != room) || !outside(&node, &room) {
                        continue;
                    }
                    room
                }
            };
            // As the map holds it: the directory itself, a symlink to it resolved.
            let dir = std::fs::canonicalize(start).unwrap_or_else(|_| start.to_path_buf());
            by_dir
                .entry((dir.display().to_string(), room))
                .or_default()
                .push((
                    reg.first_seen_ms,
                    AskingSession {
                        node: node.clone(),
                        session: reg.session.clone(),
                        harness: reg.harness.clone(),
                    },
                ));
        }
    }
    by_dir
        .into_iter()
        .map(|((dir, room), mut sessions)| {
            sessions.sort_by_key(|(first, _)| *first);
            RoomAsk {
                dir,
                room,
                sessions: sessions.into_iter().map(|(_, s)| s).collect(),
            }
        })
        .collect()
}

/// What answers an ask at a terminal, each with what it does: bind the directory or say no; or,
/// for a directory bound to a room the node is not in, join that room with the link the room map
/// holds (it asks for the room's passphrase there). Each is `(what it does, how, whether how is a
/// whole command to paste)`: a command only when every word of it is known here; else the way is
/// said in words (the room's link, before the person has it).
#[must_use]
pub fn answers(ask: &RoomAsk, data_root: &std::path::Path) -> Vec<(&'static str, String, bool)> {
    let Some(first) = ask.sessions.first() else {
        return Vec::new();
    };
    let node = first.node.as_str();
    if !ask.room.is_empty() {
        let link = crate::room_map::read(data_root).ok().and_then(|entries| {
            crate::room_map::resolve(&entries, std::path::Path::new(&ask.dir))
                .map(|e| e.room.clone())
        });
        return vec![match link {
            Some(link) => (
                "to join it",
                vox_text::shell::command(&["vox", "room", "join", &link, "--node", node]),
                true,
            ),
            None => (
                "to join it",
                format!("run vox room join with the room's link and --node {node}"),
                false,
            ),
        }];
    }
    vec![
        (
            "to bind it",
            format!(
                "run vox room join with the room's link, --node {node} and --bind {}",
                ask.dir
            ),
            false,
        ),
        (
            "to say no",
            vox_text::shell::command(&[
                "vox",
                "agent",
                "room",
                "--none",
                "--node",
                node,
                "--session",
                first.session.as_str(),
            ]),
            true,
        ),
    ]
}

/// One line per ask, as `vox agent status` prints it after its own: "Vox needs you: Claude Code in
/// /opt/vox has no room. …", with where it is answered. Nothing when there are none.
#[must_use]
pub fn needs_you(asks: &[RoomAsk], data_root: &std::path::Path) -> String {
    asks.iter()
        .map(|a| {
            let ways: Vec<String> = answers(a, data_root)
                .into_iter()
                .map(|(what, how, command)| {
                    if command {
                        format!("`{how}` {what}")
                    } else {
                        format!("{how} {what}")
                    }
                })
                .collect();
            let sentence = a.sentence();
            let sentence = sentence
                .trim_end_matches('?')
                .trim_end_matches(" Join it")
                .trim_end_matches('.');
            format!(
                "Vox needs you: {sentence}. Answer in Vox.app, or at a terminal: {}.\n",
                ways.join(", or ")
            )
        })
        .collect()
}

/// The daemon's asks, as a client reads them. No daemon running is no session registered, so no
/// ask.
///
/// # Errors
/// The daemon answered with something else, or the connection failed after it greeted.
pub async fn fetch(account: &Account) -> Result<Vec<RoomAsk>, AppError> {
    let Ok(mut d) = DaemonClient::open(&account.socket()).await else {
        return Ok(Vec::new());
    };
    match d
        .request(DaemonRequest::RoomAsks)
        .await
        .map_err(|e| AppError::Usage(e.to_string()))?
    {
        DaemonFrame::RoomAsks(asks) => Ok(asks),
        other => Err(crate::client::unexpected_daemon(&other)),
    }
}
