//! Explicit typed Session selection without retaining the room's whole metadata list.

use super::SessionRow;
use crate::hash::Digest32;
use crate::node::ipc::{Frame, IpcClient};

/// Current room Session token for a bounded multi-request selection.
///
/// # Errors
/// The selected node or room is unavailable, or its snapshot cannot be read.
pub async fn revision(client: &mut IpcClient, room: Digest32) -> Result<Digest32, String> {
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

async fn selection_revision(client: &mut IpcClient, room: Digest32) -> Result<Digest32, String> {
    match client
        .session_selection_revision(room)
        .await
        .map_err(|e| e.to_string())?
    {
        Frame::SessionSelectionRevision { revision } => Ok(revision),
        Frame::Error { reason } => Err(reason),
        Frame::NodeDetached { node } => Err(format!("the connection to node {node} ended")),
        _ => Err("the node did not answer its Session selection state".into()),
    }
}

#[cfg(feature = "test-knobs")]
async fn hold_selection_for_proof() -> Result<(), String> {
    let Some(path) = std::env::var_os("VOX_TEST_SESSION_SELECTION_HOLD_FILE")
        .filter(|path| !path.is_empty())
        .map(std::path::PathBuf::from)
    else {
        return Ok(());
    };
    let reached = path.with_extension("reached");
    std::fs::write(&reached, b"reached").map_err(|e| {
        format!(
            "Session selection proof could not mark {}: {e}",
            reached.display()
        )
    })?;
    while path.exists() {
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    Ok(())
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
    lookup(client, room, node, typed, ended_ok, label)
        .await?
        .ok_or_else(|| format!("no Session in this room is named {}", typed.trim()))
}

/// Resolve the newest opening of each id, returning absence only after the full bounded scan.
/// Read callers may then use the existing opening-not-received activity path.
///
/// # Errors
/// Refused, changed, ambiguous or ineligible metadata; these are never absence.
pub async fn lookup(
    client: &mut IpcClient,
    room: Digest32,
    node: Option<Digest32>,
    typed: &str,
    ended_ok: bool,
    label: impl Fn(&SessionRow) -> String,
) -> Result<Option<SessionRow>, String> {
    select(client, room, node, typed, ended_ok, label).await
}

/// Resolve the newest opening of each id for a message addressed to one node.
///
/// # Errors
/// No current open Session matches, the identity is ambiguous, or a read failed.
pub async fn addressable(
    client: &mut IpcClient,
    room: Digest32,
    node: Digest32,
    typed: &str,
    label: impl Fn(&SessionRow) -> String,
) -> Result<String, String> {
    select(client, room, Some(node), typed, false, label)
        .await?
        .map(|s| s.id)
        .ok_or_else(|| format!("no Session in this room is named {}", typed.trim()))
}

async fn select(
    client: &mut IpcClient,
    room: Digest32,
    node: Option<Digest32>,
    typed: &str,
    ended_ok: bool,
    label: impl Fn(&SessionRow) -> String,
) -> Result<Option<SessionRow>, String> {
    let typed = typed.trim();
    if typed.is_empty() {
        return Err(
            "name a Session: its id, the first 8 or more characters of it, or its name".into(),
        );
    }
    let stamp = selection_revision(client, room).await?;
    #[cfg(feature = "test-knobs")]
    hold_selection_for_proof().await?;
    let prefix = typed.chars().count() >= 8;
    let mut by_id = None;
    let mut by_name = None;
    let (mut id_count, mut name_count) = (0u64, 0u64);
    // An absence is proven only when every page could answer for the asked node (or, with
    // no node named, for every member) and none came from a fold still behind (ADR-037 R4).
    let mut unproven = false;
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
                refreshing,
                provisional,
            } if sessions.len() == summaries.len() => {
                unproven |= provisional
                    || node.map_or(!refreshing.is_empty(), |node| refreshing.contains(&node));
                (sessions, more)
            }
            Frame::Error { reason } => return Err(reason),
            Frame::NodeDetached { node } => {
                return Err(format!("the connection to node {node} ended"))
            }
            _ => return Err("the node did not answer the Session page".into()),
        };
        // A changing room cannot keep this explicit lookup following a growing tail forever.
        // Each bounded page belongs to the same observed projection generation.
        if selection_revision(client, room).await? != stamp {
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
            let id_match = row.id == typed || (prefix && row.id.starts_with(typed));
            let name_match = row.name.as_deref() == Some(typed);
            if id_match || name_match {
                match client
                    .session_lookup(room, row.node, row.id.clone())
                    .await
                    .map_err(|e| e.to_string())?
                {
                    Frame::SessionsPage {
                        sessions,
                        more: false,
                        ..
                    } if sessions.len() == 1 => {
                        if sessions[0].opening != row.opening {
                            continue;
                        }
                    }
                    Frame::Error { reason } => return Err(reason),
                    Frame::NodeDetached { node } => {
                        return Err(format!("the connection to node {node} ended"))
                    }
                    _ => return Err("the node did not answer the latest Session opening".into()),
                }
            }
            if id_match {
                id_count = id_count.saturating_add(1);
                if by_id.is_none() {
                    by_id = Some(row);
                }
            } else if name_match {
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
    let (count, selected, matched_id) = if id_count != 0 {
        (id_count, by_id, true)
    } else {
        (name_count, by_name, false)
    };
    let selected = if count == 1 {
        let row = selected.ok_or("the node did not answer the Session selection")?;
        match client
            .session_lookup(room, row.node, row.id.clone())
            .await
            .map_err(|e| e.to_string())?
        {
            Frame::SessionsPage {
                mut sessions,
                more: false,
                ..
            } if sessions.len() == 1 => {
                let current = sessions.remove(0);
                if current.node != row.node
                    || current.id != row.id
                    || current.opening != row.opening
                    || (matched_id
                        && !(current.id == typed || (prefix && current.id.starts_with(typed))))
                    || (!matched_id && current.name.as_deref() != Some(typed))
                {
                    return Err("the room's Sessions changed while selecting; try again".into());
                }
                Some(current)
            }
            Frame::Error { reason } => return Err(reason),
            Frame::NodeDetached { node } => {
                return Err(format!("the connection to node {node} ended"))
            }
            Frame::SessionsPage { .. } => {
                return Err("the room's Sessions changed while selecting; try again".into())
            }
            _ => return Err("the node did not answer the latest Session opening".into()),
        }
    } else {
        selected
    };
    if selection_revision(client, room).await? != stamp {
        return Err("the room's Sessions changed while selecting; try again".into());
    }
    match (count, selected) {
        // The node holds no such Session yet, and the pages could not prove it never will:
        // a refreshing member's or an unfolded Session is "not received yet", not absent.
        (0, _) if unproven => Err("that Session has not been received yet; fetching it now".into()),
        (0, _) => Ok(None),
        (1, Some(row)) if !row.open && !ended_ok => Err(format!("{} has ended", label(&row))),
        (1, Some(row)) => Ok(Some(row)),
        (n, _) => Err(format!(
            "{typed} names {n} Sessions; give a more specific Session id and node"
        )),
    }
}
