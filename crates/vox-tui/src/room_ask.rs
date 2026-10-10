//! **Vox asks the person which room a repo works in** (ADR-029 RB-5 – RB-7).
//!
//! A harness session started in a directory the room map does not name works in no room, and its
//! hook tells the agent to ask the operator. An agent that does not pass it on leaves the person
//! never knowing, so the daemon asks too: every registered session that works in no room, started
//! in a directory with no block in the room map, is an ask, one per directory. Nothing is stored
//! for it: it is read from the sessions' registrations and the map, so a bind, a no, or the
//! sessions ending clears it by itself.
//!
//! Vox.app shows an ask under needs you with what to do about it; the TUI and `vox agent status`
//! show it with the commands that answer it at a terminal.

use std::collections::BTreeMap;

use vox_core::node::daemonipc::{AskingSession, DaemonClient, DaemonFrame, DaemonRequest, RoomAsk};
use vox_core::node::paths::Account;

use crate::app::AppError;

pub use vox_core::node::daemonipc::harness_words;

/// The asks of `account`'s data root, one per directory, ordered by directory; each one's sessions
/// oldest first. A room map that cannot be read gives none: the hook says why to the session.
#[must_use]
pub fn asks(account: &Account) -> Vec<RoomAsk> {
    let Ok(entries) = crate::room_map::read(&account.data_root) else {
        return Vec::new();
    };
    let mut by_dir: BTreeMap<String, Vec<(u64, AskingSession)>> = BTreeMap::new();
    for node in account.nodes_on_disk() {
        let Ok(paths) = account.node_paths(&node) else {
            continue;
        };
        for reg in crate::wake::registered(&paths) {
            // A headless run has no person at it to ask, and a hook run by hand no harness.
            if reg.room.is_some() || !reg.interactive || reg.harness == "unknown" {
                continue;
            }
            let Some(start) = reg.start.as_deref().filter(|s| !s.is_empty()) else {
                continue;
            };
            let start = std::path::Path::new(start);
            if crate::room_map::lookup(&entries, start).is_some() {
                continue;
            }
            // As the map would hold it: the directory itself, a symlink to it resolved.
            let dir = std::fs::canonicalize(start).unwrap_or_else(|_| start.to_path_buf());
            by_dir.entry(dir.display().to_string()).or_default().push((
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
        .map(|(dir, mut sessions)| {
            sessions.sort_by_key(|(first, _)| *first);
            RoomAsk {
                dir,
                sessions: sessions.into_iter().map(|(_, s)| s).collect(),
            }
        })
        .collect()
}

/// What answers an ask at a terminal: bind it, or say no.
#[must_use]
pub fn commands(ask: &RoomAsk) -> [String; 2] {
    let node = ask.sessions.first().map_or("<node>", |s| s.node.as_str());
    let session = ask
        .sessions
        .first()
        .map_or("<session>", |s| s.session.as_str());
    [
        format!("vox room join <link> --node {node} --bind {}", ask.dir),
        format!("vox agent room --none --node {node} --session {session}"),
    ]
}

/// One line per ask, as `vox agent status` prints it after its own: "Vox needs you: Claude Code in
/// /opt/vox has no room. …", with where it is answered. Nothing when there are none.
#[must_use]
pub fn needs_you(asks: &[RoomAsk]) -> String {
    asks.iter()
        .map(|a| {
            let [bind, no] = commands(a);
            format!(
                "Vox needs you: {}. Answer in Vox.app, or at a terminal: `{bind}` to bind it, or \
                 `{no}` to say no.\n",
                a.sentence()
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
