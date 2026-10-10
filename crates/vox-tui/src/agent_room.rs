//! `vox agent room <room>`: set the room a harness session works in, or move it (ADR-029 RB-5).
//!
//! A session started in a directory the room map does not name works in no room, and its hook
//! tells it this command. Run from the session, it names the session the way every `vox room`
//! verb does (`--session`, `VOX_SESSION`, then the harness's own id), and its node the way the
//! session's hook does (`--node`, else `VOX_NODE`): never a person's node. The room must be one
//! the node holds. The daemon ends the session's Session in the room it worked in, if any, and
//! opens one in the new room; a session works in one room at a time. It says what it is to do
//! before it asks, and what was done after (ADR-028 E-5). It never attaches the node and asks for
//! no identity passphrase (ADR-028 K-13): a node not attached is refused with the command to
//! attach it.
//!
//! **Saving it in the room map** (the decider, 2026-10-06): a session that had no room, set to one
//! here, is offered to save its start directory → that room in the room map, so the next session
//! started there works in it by itself. It says first what that changes: every node of this data
//! root can read the map, the room's passphrase included. On yes it writes the room's link, and
//! the room's passphrase typed at the terminal (never from the environment). Without a terminal it
//! asks nothing and says how the operator can. Moving a session from one room to another never
//! writes the map.

use vox_core::node::daemonipc::{DaemonClient, DaemonFrame, DaemonRequest};
use vox_core::node::paths::{Account, NodeName};

use crate::app::AppError;

/// `vox agent room`.
///
/// # Errors
/// No node or session named, a node not attached, a room the node does not hold, a session not
/// registered (its hook has not run), or the daemon's refusal.
pub async fn run(
    account: &Account,
    node: &NodeName,
    session_flag: Option<&str>,
    room: &str,
) -> Result<(), AppError> {
    let session = crate::coord::require_session(session_flag)?;
    let paths = account.node_paths(node)?;
    // The room, as the node holds it: an id, a unique start of one, or its name.
    let mut client = crate::room_cli::attach(&paths).await?;
    let channel_id = crate::room_cli::room_of(&mut client, room).await?;
    let room_b32 = vox_core::node::link::b32_encode(&channel_id);
    let short = |r: &str| r.chars().take(12).collect::<String>();
    let before = crate::wake::registration(&paths, &session).and_then(|r| r.room);
    let label: String = session.chars().take(8).collect();
    match before.as_deref() {
        Some(old) if old == room_b32 => {
            println!(
                "vox: session {label} of node {node} works in room {} already; it is not moved",
                short(&room_b32)
            );
            return offer_save(account, &paths, &mut client, node, &session, channel_id).await;
        }
        Some(old) => println!(
            "vox: about to move session {label} of node {node} from room {} to room {}: its \
             Session in {} is to end, and one is to open in {}",
            short(old),
            short(&room_b32),
            short(old),
            short(&room_b32)
        ),
        None => println!(
            "vox: about to set the room session {label} of node {node} works in: room {}, where \
             its Session is to open",
            short(&room_b32)
        ),
    }
    let mut d = DaemonClient::open(&account.socket())
        .await
        .map_err(|e| AppError::Usage(e.to_string()))?;
    match d
        .request(DaemonRequest::SessionRoom {
            node: node.clone(),
            session: session.clone(),
            room: room_b32.clone(),
        })
        .await
        .map_err(|e| AppError::Usage(e.to_string()))?
    {
        DaemonFrame::SessionRegistered { room, joining, .. } => {
            let now = room.unwrap_or_default();
            let moved = before.is_some();
            match before {
                Some(old) => println!(
                    "vox: session {label} now works in room {}; its Session in room {} ended",
                    short(&now),
                    short(&old)
                ),
                None => println!("vox: session {label} now works in room {}", short(&now)),
            }
            if let Some(j) = joining {
                println!("     {j}");
            }
            if moved {
                return Ok(());
            }
            offer_save(account, &paths, &mut client, node, &session, channel_id).await
        }
        DaemonFrame::Refused(r) => Err(AppError::Usage(r.to_string())),
        other => Err(AppError::Usage(format!(
            "the daemon answered the move with {other:?}"
        ))),
    }
}

/// `vox agent room --none`: the operator said no to binding this session's repo to a room
/// (ADR-029 RB-7). Its start directory is recorded in the room map with no room, so no session
/// started there is asked again; no passphrase or link is involved.
///
/// # Errors
/// No session named, a session not registered, or the map cannot be written.
pub fn decline(
    account: &Account,
    node: &NodeName,
    session_flag: Option<&str>,
) -> Result<(), AppError> {
    let session = crate::coord::require_session(session_flag)?;
    let paths = account.node_paths(node)?;
    let start = crate::wake::registration(&paths, &session)
        .and_then(|r| r.start)
        .ok_or_else(|| {
            AppError::Usage(format!(
                "session {session} of node {node} is not registered, or started nowhere Vox knows"
            ))
        })?;
    let start = std::path::PathBuf::from(start);
    if crate::room_map::decline(&account.data_root, &start)? {
        println!(
            "vox: {} is to stay tied to no room: no session started there is asked again; \
             remove its block from {} to be asked",
            start.display(),
            crate::room_map::path(&account.data_root).display()
        );
    } else {
        println!(
            "vox: the room map names {} already; nothing was changed",
            start.display()
        );
    }
    Ok(())
}

/// Offer to save the session's start directory → `channel_id` in the room map, when the map does
/// not name that directory yet.
async fn offer_save(
    account: &Account,
    paths: &vox_core::node::paths::Paths,
    client: &mut vox_core::node::ipc::IpcClient,
    node: &NodeName,
    session: &str,
    channel_id: vox_core::hash::Digest32,
) -> Result<(), AppError> {
    use std::io::{BufRead, IsTerminal, Write};
    let Some(start) = crate::wake::registration(paths, session).and_then(|r| r.start) else {
        return Ok(());
    };
    let start = std::path::PathBuf::from(start);
    let entries = crate::room_map::read(&account.data_root)?;
    if crate::room_map::resolve(&entries, &start).is_some() {
        return Ok(());
    }
    let room: String = vox_core::node::link::b32_encode(&channel_id)
        .chars()
        .take(12)
        .collect();
    let map = crate::room_map::path(&account.data_root);
    if !std::io::stdin().is_terminal() {
        println!(
            "vox: to also save {} → room {room} in the room map, so a session started there works \
             in it, run this in a terminal: vox agent room {room} --node {node} --session {session}",
            start.display()
        );
        return Ok(());
    }
    println!(
        "vox: saving {} → room {room} in the room map ({}) is to let every session started there \
         work in that room by itself; every node of this data root can read the map, the room's \
         passphrase included",
        start.display(),
        map.display()
    );
    print!(
        "Also save {} → room {room} in the room map? [y/N] ",
        start.display()
    );
    std::io::stdout().flush().map_err(AppError::Io)?;
    let mut answer = String::new();
    std::io::stdin()
        .lock()
        .read_line(&mut answer)
        .map_err(AppError::Io)?;
    if !matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
        println!("vox: the room map is not changed");
        return Ok(());
    }
    let link = match client
        .request(&vox_core::node::ipc::Request::Invite { channel_id })
        .await
    {
        Ok(vox_core::node::ipc::Frame::Link { url, .. }) => url,
        Ok(vox_core::node::ipc::Frame::Error { reason }) => {
            return Err(AppError::Usage(format!(
                "room {room}'s link could not be had, so nothing was saved: {reason}"
            )))
        }
        Ok(other) => return Err(crate::client::unexpected(&other)),
        Err(e) => return Err(AppError::Usage(e.to_string())),
    };
    let passphrase = zeroize::Zeroizing::new(crate::tunnel_cli::prompt_passphrase(&format!(
        "room {room}'s passphrase (Enter if it has none)"
    ))?);
    crate::room_map::add(&account.data_root, &start, &link, &passphrase)?;
    println!(
        "vox: saved {} → room {room} in the room map {}",
        start.display(),
        map.display()
    );
    Ok(())
}
