//! `vox room ping <name>`, and the daemon's answer to it (V030-16).
//!
//! A ping asks the room which sessions answer to a name. It is **answered by the daemon** of
//! each node that holds such a session, never by a model: the daemon reads its own session
//! records, probes each one's wake endpoint, and posts a `pong` naming them. So a ping checks
//! the plumbing from the other side, the way `vox agent doctor` checks it from this one, and
//! costs no model a token. No drain shows a ping or a pong, and neither wakes anyone
//! ([`vox_agentcomms::envelope::is_plumbing`]).
//!
//! A daemon answers only a member its keyring trusts, and only when it holds a session under
//! a name the ping addresses. So a missing answer cannot say why: the node may be offline or
//! run no `vox daemon`, it may not trust the sender (or the sender may not be able to read its
//! answer), or it may hold no session by that name. The pinger is told exactly that, rather
//! than a guess. The decider accepts that a pong shows trusted room members which sessions a
//! node has.

use std::time::Duration;

use vox_agentcomms::envelope::{Envelope, PING, PONG};
use vox_core::hash::Digest32;
use vox_core::node::actor::NodeHandle;
use vox_core::node::api::{MessageRow, NodeCommand, NodeView, Outcome};
use vox_core::node::ipc::Frame;
use vox_core::node::link::b32_encode;
use vox_core::node::paths::Paths;

use crate::app::AppError;

/// How long `vox room ping` waits for an answer unless told otherwise.
pub const DEFAULT_WAIT: Duration = Duration::from_secs(30);

/// After the first answer, how much longer a ping listens for other nodes' answers.
const MORE_ANSWERS: Duration = Duration::from_secs(3);

/// Between reads while waiting.
const POLL: Duration = Duration::from_millis(250);

/// Whether `text` is a ping, which the daemon answers.
#[must_use]
pub fn is_ping(text: &str) -> bool {
    Envelope::parse(text).is_ok_and(|e| e.kind == PING)
}

/// Answer `row` if it is a ping this node should answer: from a member this node trusts (or
/// from this node), addressed to a name one of its sessions in that room answers to. The
/// answer is posted from a task of its own, so probing endpoints never holds the daemon's loop.
pub fn answer(
    node: &NodeHandle,
    paths: &Paths,
    view: &NodeView,
    channel_id: Digest32,
    row: &MessageRow,
) {
    let Ok(ping) = Envelope::parse(&row.text) else {
        return;
    };
    if ping.kind != PING || ping.to.is_empty() {
        return;
    }
    let me = view.identity.as_ref().map(|i| i.fingerprint);
    if Some(row.author) != me && !view.trusted.iter().any(|(fp, _)| *fp == row.author) {
        eprintln!(
            "vox daemon: not answering a ping from {}: it is not in this node's keyring",
            crate::ident::author_id(&row.author)
        );
        return;
    }
    let room = b32_encode(&channel_id);
    let sessions: Vec<crate::wake::Session> = crate::wake::registered(paths)
        .into_iter()
        .filter(|s| s.room == room && !s.name.is_empty() && ping.to.contains(&s.name))
        .collect();
    if sessions.is_empty() {
        return;
    }
    let (node, entry) = (node.clone(), b32_encode(&row.entry_hash));
    tokio::spawn(async move {
        let mut listed = Vec::new();
        for s in &sessions {
            let reach = crate::wake::reach(s).await;
            listed.push(serde_json::json!({
                "name": s.name,
                "session": s.session,
                "harness": s.harness,
                "reach": reach.token(),
                "last_read_ms": s.last_drained_ms,
                "state": s.state,
            }));
        }
        let mut pong = Envelope::new(
            PONG,
            &format!(
                "{} session{} here answer{} to {}",
                sessions.len(),
                if sessions.len() == 1 { "" } else { "s" },
                if sessions.len() == 1 { "s" } else { "" },
                ping.to.join(", ")
            ),
        );
        pong.re = Some(entry.clone());
        pong.data = serde_json::json!({
            "ping": entry,
            "sessions": listed,
            "vox": crate::coord::VERSION,
        });
        let text = pong.to_text();
        match node.apply(NodeCommand::SendText { channel_id, text }).await {
            Outcome::Done => {}
            other => eprintln!(
                "vox daemon: could not answer ping {}: {other}",
                &entry[..12]
            ),
        }
    });
}

/// One node's answer.
struct Answer {
    node: Digest32,
    sessions: Vec<serde_json::Value>,
}

/// `vox room ping <name>`: post a ping and report each node's answer, or what a missing one
/// cannot tell apart.
///
/// # Errors
/// No node, no such room, a post that fails, or no answer within `wait` (exit 1).
pub async fn ping(
    paths: &Paths,
    room: Option<&str>,
    name: &str,
    wait: Duration,
    json: bool,
) -> Result<(), AppError> {
    let name = name.trim();
    if name.is_empty() || name.len() > vox_agentcomms::envelope::MAX_NAME {
        return Err(AppError::Usage(format!(
            "a name to ping is 1 to {} characters",
            vox_agentcomms::envelope::MAX_NAME
        )));
    }
    let mut client = crate::room_cli::attach(paths).await?;
    let channel_id = room_or_only(&mut client, room).await?;
    let room_key = b32_encode(&channel_id);
    let snap = crate::coord::snapshot(&mut client, channel_id).await?;
    let draft = crate::coord::Draft {
        kind: PING.into(),
        to: vec![name.to_owned()],
        body: format!("which sessions answer to {name}?"),
        ..crate::coord::Draft::default()
    };
    let session = crate::coord::session(None).unwrap_or_default();
    let op = crate::coord::new_op()?;
    let posted = crate::coord::post_once(&mut client, channel_id, &draft, &session, &op, &snap)
        .await?
        .entry_hash;
    let ping_key = b32_encode(&posted);

    let start = tokio::time::Instant::now();
    let mut until = start + wait;
    let mut answers: Vec<Answer> = Vec::new();
    loop {
        if let Ok(Frame::Rows { rows }) = client.read_rows(channel_id, Some(posted)).await {
            for r in rows {
                let Ok(env) = Envelope::parse(&r.text) else {
                    continue;
                };
                if env.kind != PONG || env.re.as_deref() != Some(ping_key.as_str()) {
                    continue;
                }
                if answers.iter().any(|a| a.node == r.author) {
                    continue;
                }
                if answers.is_empty() {
                    until = until.min(tokio::time::Instant::now() + MORE_ANSWERS);
                }
                answers.push(Answer {
                    node: r.author,
                    sessions: env.data["sessions"].as_array().cloned().unwrap_or_default(),
                });
            }
        }
        if tokio::time::Instant::now() >= until {
            break;
        }
        tokio::time::sleep(POLL).await;
    }
    let waited = start.elapsed();

    if json {
        let out = serde_json::json!({
            "schema": "vox.room.ping/1",
            "room": room_key,
            "name": name,
            "ping": ping_key,
            "waited_ms": u64::try_from(waited.as_millis()).unwrap_or(u64::MAX),
            "answers": answers.iter().map(|a| serde_json::json!({
                "node": b32_encode(&a.node),
                "sessions": a.sessions,
            })).collect::<Vec<_>>(),
        });
        println!("{out}");
    } else {
        for a in &answers {
            println!("node {} answered:", crate::ident::author_id(&a.node));
            for s in &a.sessions {
                println!("  {}", describe(s));
            }
        }
    }
    if answers.is_empty() {
        return Err(AppError::Refused {
            code: 1,
            message: no_answer(name, waited),
        });
    }
    Ok(())
}

/// What a missing answer says, and what it cannot.
fn no_answer(name: &str, waited: Duration) -> String {
    format!(
        "no answer for {name:?} within {}s. That cannot tell apart: the node holding {name:?} \
         is offline or runs no `vox daemon`; it does not trust you (so it cannot read your \
         ping), or you do not trust it (so you cannot read its answer); or no session there \
         answers to {name:?}",
        waited.as_secs()
    )
}

/// One session in a pong, as a person reads it.
fn describe(s: &serde_json::Value) -> String {
    let get = |k: &str| s[k].as_str().unwrap_or("").to_owned();
    let reach = match s["reach"].as_str() {
        Some("interrupt") => "an urgent message interrupts it".to_owned(),
        Some("turn") => "it cannot be interrupted; it reads at its next turn".to_owned(),
        Some("gone") => {
            "its wake endpoint is gone; it reads at its next turn, if it has one".to_owned()
        }
        other => format!("reach {other:?}"),
    };
    let read = match s["last_read_ms"].as_u64() {
        Some(ms) if ms > 0 => format!("last read {}", ago_ms(ms)),
        _ => "has not read yet".to_owned(),
    };
    let state = match get("state").as_str() {
        "" => String::new(),
        st => format!("; {st}"),
    };
    format!(
        "{} as session {} ({}): {reach}; {read}{state}",
        get("name"),
        get("session"),
        get("harness")
    )
}

/// How long ago `ms` (since the epoch) was, as a person reads it.
pub(crate) fn ago_ms(ms: u64) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
    let s = now.saturating_sub(ms) / 1000;
    match s {
        0..=59 => format!("{s}s ago"),
        60..=3599 => format!("{}m ago", s / 60),
        3600..=86_399 => format!("{}h ago", s / 3600),
        _ => format!("{}d ago", s / 86_400),
    }
}

/// The room `room` names, or from `VOX_ROOM`, or the node's only room.
///
/// # Errors
/// None given and the node holds no room or several, or a name that resolves to none.
pub(crate) async fn room_or_only(
    client: &mut vox_core::node::ipc::IpcClient,
    room: Option<&str>,
) -> Result<Digest32, AppError> {
    let named = room
        .map(str::to_owned)
        .or_else(|| std::env::var("VOX_ROOM").ok())
        .filter(|r| !r.trim().is_empty());
    if let Some(r) = named {
        return crate::room_cli::room_of(client, r.trim()).await;
    }
    let rooms = match client.rooms().await {
        Ok(Frame::Rooms { rooms }) => rooms,
        Ok(Frame::Error { reason }) => return Err(AppError::Usage(reason)),
        Ok(other) => return Err(AppError::Usage(format!("unexpected reply: {other:?}"))),
        Err(e) => return Err(AppError::Usage(e.to_string())),
    };
    match rooms.as_slice() {
        [(id, _, _)] => crate::room_cli::room_of(client, &b32_encode(id)).await,
        [] => Err(AppError::Usage(
            "this node holds no rooms yet: join or create one first".into(),
        )),
        _ => Err(AppError::Usage(
            "this node holds several rooms: name one with --room, or set VOX_ROOM".into(),
        )),
    }
}
