//! Explicit typed Session selection without retaining the room's whole metadata list.

use super::SessionRow;
use crate::hash::Digest32;
use crate::node::ipc::{Frame, IpcClient};

async fn revision(client: &mut IpcClient, room: Digest32) -> Result<Digest32, String> {
    let reply = client
        .exchange(&crate::node::snapshot::request_body())
        .await
        .map_err(|e| format!("the node's Session state could not be read: {e}"))?;
    let Some(snapshot) = crate::node::snapshot::NodeSnapshot::from_bytes(&reply)
        .map_err(|e| format!("the node's Session state could not be read: {e}"))?
    else {
        return Err(match Frame::from_bytes(&reply) {
            Ok(Frame::Error { reason }) => reason,
            Ok(Frame::NodeDetached { node }) => format!("the connection to node {node} ended"),
            _ => "the node did not answer its Session state".into(),
        });
    };
    snapshot
        .open
        .into_iter()
        .find(|r| r.channel_id == room)
        .map(|r| r.session_revision)
        .ok_or_else(|| "the room is not open".into())
}

/// Resolve an explicit id, id prefix or name, preserving the shared resolver's precedence.
/// One logical metadata page and at most two candidate rows are retained. A legal member field
/// is kept whole; this does not impose an artificial metadata length limit.
///
/// # Errors
/// The listing failed or changed, the selection is ambiguous, absent, or ended when disallowed.
pub async fn resolve(
    client: &mut IpcClient,
    room: Digest32,
    node: Option<Digest32>,
    typed: &str,
    ended_ok: bool,
    label: impl Fn(&SessionRow) -> String,
) -> Result<SessionRow, String> {
    let typed = typed.trim();
    if typed.is_empty() {
        return Err(
            "name a Session: its id, the first 8 or more characters of it, or its name".into(),
        );
    }
    let stamp = revision(client, room).await?;
    let prefix = typed.chars().count() >= 8;
    let mut by_id = None;
    let mut by_name = None;
    let (mut id_count, mut name_count) = (0u64, 0u64);
    let mut after = None;
    loop {
        let reply = client
            .sessions_page(room, after)
            .await
            .map_err(|e| format!("the room's Sessions could not be read: {e}"))?;
        let (sessions, more) = match reply {
            Frame::SessionsPage {
                sessions,
                summaries,
                more,
            } if sessions.len() == summaries.len() => (sessions, more),
            Frame::Error { reason } => return Err(reason),
            Frame::NodeDetached { node } => {
                return Err(format!("the connection to node {node} ended"))
            }
            _ => return Err("the node did not answer the Session page".into()),
        };
        // A changing room cannot keep this explicit lookup following a growing tail forever.
        // Each bounded page belongs to the same observed projection generation.
        if revision(client, room).await? != stamp {
            return Err("the room's Sessions changed while selecting; try again".into());
        }
        let next = sessions.last().map(|s| s.opening);
        if more && (next.is_none() || next == after) {
            return Err("the Session page made no progress".into());
        }
        for row in sessions {
            if node.is_some_and(|node| row.node != node) {
                continue;
            }
            if row.id == typed || (prefix && row.id.starts_with(typed)) {
                id_count = id_count.saturating_add(1);
                if by_id.is_none() {
                    by_id = Some(row);
                }
            } else if row.name.as_deref() == Some(typed) {
                name_count = name_count.saturating_add(1);
                if by_name.is_none() {
                    by_name = Some(row);
                }
            }
        }
        if !more {
            break;
        }
        after = next;
    }
    let (count, selected) = if id_count != 0 {
        (id_count, by_id)
    } else {
        (name_count, by_name)
    };
    match (count, selected) {
        (0, _) => Err(format!("no Session in this room is named {typed}")),
        (1, Some(row)) if !row.open && !ended_ok => Err(format!("{} has ended", label(&row))),
        (1, Some(row)) => Ok(row),
        (n, _) => Err(format!(
            "{typed} names {n} Sessions; give a more specific Session id and node"
        )),
    }
}
