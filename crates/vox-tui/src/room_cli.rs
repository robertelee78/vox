//! ADR-020 §8 — `vox room`: the agent-facing verbs, over a **running** node.
//!
//! Every other `vox` verb spawns a node of its own. These do not, and that is the
//! point: agent comms puts several agent sessions on one harness node (ADR-020
//! §2, one identity per `(host, harness)`), so these connect to the control
//! socket of a node that is already running and already unlocked.
//!
//! Two consequences fall out of that, both intended:
//!
//! - **No passphrase anywhere.** There is nothing to unlock — the node holds the
//!   identity. An agent session never sees a secret, which is what makes it safe
//!   to hand these verbs to model-authored code.
//! - **No room is created or joined here.** These verbs speak in a room; putting
//!   the node in one is the operator's act.
//!
//! The socket answers a deliberately narrow request set and these verbs are
//! exactly it (`post`, `read`, `tail`, `roster`, `list`). There is no verb here
//! that creates an identity, unlocks, revokes, or edits the trust keyring —
//! `vox trust` is an operator surface and is not part of this module.

use std::io::Read as _;
use std::io::Write as _;

use vox_core::hash::Digest32;
use vox_core::node::ipc::{Frame, IpcClient, Request};
use vox_core::node::link::{b32_decode, b32_encode, B32_DIGEST_LEN};
use vox_core::node::paths::Paths;

use crate::app::AppError;
use crate::tunnel_cli::resolve_prefix;

/// Connect to the running node's control socket for this profile.
///
/// The failure an operator will actually hit is "no node is running", so it says
/// that rather than surfacing a connect error.
async fn attach(paths: &Paths) -> Result<IpcClient, AppError> {
    let sock = paths.socket_file();
    if !sock.exists() {
        return Err(AppError::Usage(format!(
            "no node is running for this profile ({}). Start one with `vox node`, \
             or run `vox tui`, and try again.",
            paths.socket_file().display()
        )));
    }
    IpcClient::open(&sock).await.map_err(|_| {
        AppError::Usage(format!(
            "a control socket exists at {} but nothing answered — the node may have \
             stopped without cleaning up. Starting a node again replaces it.",
            sock.display()
        ))
    })
}

/// Ask the node for its rooms, as `(id, local name, open)`.
async fn rooms_of(client: &mut IpcClient) -> Result<Vec<(Digest32, String, bool)>, AppError> {
    match client.request(&Request::Rooms).await {
        Ok(Frame::Rooms { rooms }) => Ok(rooms),
        Ok(Frame::Error { reason }) => Err(AppError::Usage(reason)),
        Ok(other) => Err(AppError::Usage(format!("unexpected reply: {other:?}"))),
        Err(e) => Err(AppError::Usage(e.to_string())),
    }
}

/// Resolve a room prefix against what the node holds, and insist it is open.
///
/// A closed room is reported as closed rather than "unknown": the two are
/// different problems and an operator fixes them differently.
async fn room_of(client: &mut IpcClient, prefix: &str) -> Result<Digest32, AppError> {
    let rooms = rooms_of(client).await?;
    if rooms.is_empty() {
        return Err(AppError::Usage(
            "this node holds no rooms yet — join or create one first".into(),
        ));
    }
    let ids: Vec<Digest32> = rooms.iter().map(|(id, _, _)| *id).collect();
    let id = resolve_prefix(prefix, &ids)?;
    if let Some((_, name, false)) = rooms.iter().find(|(r, _, _)| *r == id) {
        return Err(AppError::Usage(format!(
            "room {name:?} is not open on this node, so there is nothing to read or \
             post — open it in `vox tui`, or start the node with it open"
        )));
    }
    Ok(id)
}

/// Every `vox` verb identifies a room or a member by its **base32** rendering —
/// the same 52 characters that begin an invite link and a `.vox` name — and
/// [`resolve_prefix`] matches prefixes of exactly that. Printing anything else
/// here would produce an id that this CLI cannot resolve from its own output,
/// which is what the first run of the proof test caught.
fn id(d: &Digest32) -> String {
    b32_encode(d)
}

fn short(d: &Digest32) -> String {
    b32_encode(d).chars().take(12).collect()
}

/// `vox room list` — the rooms this node holds.
pub async fn list(paths: &Paths) -> Result<(), AppError> {
    let mut client = attach(paths).await?;
    let rooms = rooms_of(&mut client).await?;
    if rooms.is_empty() {
        println!("no rooms");
        return Ok(());
    }
    for (id, name, open) in rooms {
        println!(
            "{}  {}{}",
            short(&id),
            if name.is_empty() { "(unnamed)" } else { &name },
            if open { "" } else { "  [closed]" }
        );
    }
    Ok(())
}

/// `vox room post` — append a message.
///
/// `text` of `-`, or omitted entirely, reads the message from stdin. That is the
/// form an agent uses: an agent-comms envelope is JSON, and JSON on a command
/// line is where quoting goes wrong.
pub async fn post(paths: &Paths, room: &str, text: Option<&str>) -> Result<(), AppError> {
    let body = match text {
        Some("-") | None => {
            let mut buf = String::new();
            std::io::stdin()
                .read_to_string(&mut buf)
                .map_err(|e| AppError::Usage(format!("reading stdin: {e}")))?;
            buf
        }
        Some(t) => t.to_owned(),
    };
    if body.trim().is_empty() {
        return Err(AppError::Usage("refusing to post an empty message".into()));
    }
    let mut client = attach(paths).await?;
    let channel_id = room_of(&mut client, room).await?;
    match client
        .request(&Request::Post {
            channel_id,
            text: body,
        })
        .await
    {
        Ok(Frame::Ok) => Ok(()),
        Ok(Frame::Error { reason }) => Err(AppError::Usage(reason)),
        Ok(other) => Err(AppError::Usage(format!("unexpected reply: {other:?}"))),
        Err(e) => Err(AppError::Usage(e.to_string())),
    }
}

/// `vox room read` — the room's messages, optionally only what follows a cursor.
///
/// Each line is `<entry-hash> <author-prefix> <text>`. The entry hash leads
/// because it **is** the cursor: an agent reads, keeps the last hash, and passes
/// it back as `--since` next time. Nothing else needs to be remembered.
pub async fn read(
    paths: &Paths,
    room: &str,
    since: Option<&str>,
    limit: u64,
) -> Result<(), AppError> {
    let mut client = attach(paths).await?;
    let channel_id = room_of(&mut client, room).await?;
    let since = match since {
        None => None,
        Some(s) => Some(parse_cursor(s)?),
    };
    match client
        .request(&Request::Read {
            channel_id,
            since,
            limit,
        })
        .await
    {
        Ok(Frame::Rows { rows }) => {
            let mut out = std::io::stdout().lock();
            for r in rows {
                let _ = writeln!(out, "{} {} {}", id(&r.entry_hash), short(&r.author), r.text);
            }
            Ok(())
        }
        Ok(Frame::Error { reason }) => Err(AppError::Usage(reason)),
        Ok(other) => Err(AppError::Usage(format!("unexpected reply: {other:?}"))),
        Err(e) => Err(AppError::Usage(e.to_string())),
    }
}

/// `vox room roster` — who is in the room.
pub async fn roster(paths: &Paths, room: &str) -> Result<(), AppError> {
    let mut client = attach(paths).await?;
    let channel_id = room_of(&mut client, room).await?;
    match client.request(&Request::Roster { channel_id }).await {
        Ok(Frame::Members { members }) => {
            for m in members {
                println!("{}", id(&m));
            }
            Ok(())
        }
        Ok(Frame::Error { reason }) => Err(AppError::Usage(reason)),
        Ok(other) => Err(AppError::Usage(format!("unexpected reply: {other:?}"))),
        Err(e) => Err(AppError::Usage(e.to_string())),
    }
}

/// `vox room tail` — print new messages as they arrive, until interrupted.
///
/// Prints in the same shape as `read`, so a cursor taken from either works with
/// the other. A **lag report is printed, not swallowed**: it means this client
/// fell behind and the durable log is the truth, so the right response is to
/// `read --since` the last hash rather than to assume the stream was complete.
pub async fn tail(paths: &Paths, room: &str) -> Result<(), AppError> {
    // Resolve the room on one connection, then take a second for the stream:
    // subscribing is terminal, so a subscribed connection can answer nothing.
    let mut lookup = attach(paths).await?;
    let channel_id = room_of(&mut lookup, room).await?;
    drop(lookup);

    let mut client = attach(paths).await?;
    client
        .subscribe()
        .await
        .map_err(|e| AppError::Usage(e.to_string()))?;

    let mut out = std::io::stdout().lock();
    loop {
        match client.next().await {
            Ok(Some(Frame::Event(vox_core::node::api::NodeEvent::NewEntry {
                channel_id: c,
                row,
            }))) if c == channel_id => {
                let _ = writeln!(
                    out,
                    "{} {} {}",
                    id(&row.entry_hash),
                    short(&row.author),
                    row.text
                );
                let _ = out.flush();
            }
            Ok(Some(Frame::Lagged { missed })) => {
                let _ = writeln!(
                    out,
                    "-- fell behind by {missed}; re-read with `vox room read --since <last-hash>` --"
                );
                let _ = out.flush();
            }
            Ok(Some(_)) => {}
            Ok(None) => return Ok(()), // the node stopped
            Err(e) => return Err(AppError::Usage(e.to_string())),
        }
    }
}

/// Parse a full entry hash, in the same base32 the first column prints.
///
/// Deliberately **not** prefix-matched, unlike a room id. A cursor is copied from
/// a previous line of output rather than retyped by a person, and a prefix that
/// matched the wrong entry would silently skip or repeat messages — the failure
/// an agent could not detect.
fn parse_cursor(s: &str) -> Result<Digest32, AppError> {
    let t = s.trim();
    if t.len() != B32_DIGEST_LEN {
        return Err(AppError::Usage(format!(
            "--since takes a full {B32_DIGEST_LEN}-character entry hash, as \
             `vox room read` prints it in the first column"
        )));
    }
    b32_decode(t, "entry hash").map_err(|_| {
        AppError::Usage(format!(
            "--since is not an entry hash; it should be the {B32_DIGEST_LEN} \
             characters in the first column of `vox room read`"
        ))
    })
}
