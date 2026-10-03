//! `vox room ping <room> <member>`, and the daemon's answer to it (V030-16).
//!
//! A ping asks one member's node which agent sessions it holds and whether each can be reached.
//! It is **answered by that node's daemon**, never by a model: the daemon reads its own session
//! records, probes each one's wake endpoint, and posts a `pong` listing them. So a ping checks the
//! plumbing from the other side, the way `vox agent doctor` checks it from this one, and costs no
//! model a token. No drain shows a ping or a pong, and neither wakes anyone
//! ([`vox_agentcomms::envelope::is_plumbing`]).
//!
//! A daemon answers only a member its keyring trusts, and answers even when it holds no session,
//! so "no session there" is an answer. A missing answer cannot say why: the node may be offline or
//! run no `vox daemon`, or trust is missing in one direction (it cannot read the ping, or this node
//! cannot read its answer). The pinger is told exactly that, rather than a guess. The decider
//! accepts that a pong shows trusted room members which sessions a node has.

use std::time::Duration;

use vox_agentcomms::envelope::{Envelope, PING, PONG};
use vox_core::hash::Digest32;
use vox_core::node::actor::NodeHandle;
use vox_core::node::api::{MessageRow, NodeCommand, NodeView, Outcome};
use vox_core::node::ipc::Frame;
use vox_core::node::link::b32_encode;
use vox_core::node::paths::Paths;

use crate::app::AppError;

/// Between reads while waiting for an answer.
const POLL: Duration = Duration::from_millis(250);

/// A ping older than this is not answered: its pinger has stopped waiting, and a daemon that
/// starts sweeps every room from the start.
const STALE_MS: u64 = 5 * 60 * 1000;

/// Whether `text` is a ping, which the daemon answers.
#[must_use]
pub fn is_ping(text: &str) -> bool {
    Envelope::parse(text).is_ok_and(|e| e.kind == PING)
}

/// Answer `row` if it is a ping this node should answer: addressed to this node, from a member
/// this node trusts (or from this node). The answer is posted from a task of its own, so probing
/// wake endpoints never holds the daemon's loop.
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
    let Some(me) = view.identity.as_ref().map(|i| i.fingerprint) else {
        return;
    };
    if ping.kind != PING || !ping.is_addressed_to(&b32_encode(&me)) {
        return;
    }
    let now = crate::wake::now_millis();
    if now.saturating_sub(row.created_millis) > STALE_MS {
        return;
    }
    if row.author != me && !view.trusted.iter().any(|(fp, _)| *fp == row.author) {
        eprintln!(
            "vox daemon: not answering a ping from {}: it is not in this node's keyring",
            crate::ident::author_id(&row.author)
        );
        return;
    }
    let sessions = crate::wake::registered(paths);
    let busy_idle = crate::wake::Settings::load(paths).0.busy_idle;
    let (node, entry, to) = (
        node.clone(),
        b32_encode(&row.entry_hash),
        b32_encode(&row.author),
    );
    tokio::spawn(async move {
        let mut listed = Vec::new();
        for s in &sessions {
            let reach = crate::wake::reach(s).await;
            listed.push(serde_json::json!({
                "session": s.session,
                "harness": s.harness,
                "reach": reach.token(),
                "last_read_ms": s.last_drained_ms,
                "idle": s.idle(now, busy_idle),
            }));
        }
        let mut pong = Envelope::new(
            PONG,
            &format!(
                "{} agent session{} on this node",
                sessions.len(),
                if sessions.len() == 1 { "" } else { "s" },
            ),
        );
        pong.re = Some(entry.clone());
        pong.to = vec![to];
        pong.data = serde_json::json!({
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

/// `vox room ping <room> <member>`: post a ping addressed to the member's node and report its
/// daemon's answer, or what a missing one cannot tell apart.
///
/// # Errors
/// No node, no such room or member, a post that fails, or no answer within `wait` (exit 1).
pub async fn ping(
    paths: &Paths,
    room: &str,
    member: &str,
    wait: Duration,
    json: bool,
) -> Result<(), AppError> {
    let mut client = crate::room_cli::attach(paths).await?;
    let channel_id = crate::room_cli::room_of(&mut client, room).await?;
    let to = crate::room_cli::addressees(&mut client, channel_id, &[member.to_owned()]).await?;
    let Some(target) = to.first().and_then(|t| crate::ident::recipient(t)) else {
        return Err(AppError::Usage(format!(
            "refusing to ping {member:?}: no such member"
        )));
    };
    let name = crate::ident::name_of(&target);
    let snap = crate::coord::snapshot(&mut client, channel_id).await?;
    let draft = crate::coord::Draft {
        kind: PING.into(),
        to: to.clone(),
        body: "which agent sessions does this node hold, and can each be reached?".into(),
        ..crate::coord::Draft::default()
    };
    let session = crate::coord::session(None).unwrap_or_default();
    let op = crate::coord::new_op()?;
    let posted = crate::coord::post_once(&mut client, channel_id, &draft, &session, &op, &snap)
        .await?
        .entry_hash;
    let ping_key = b32_encode(&posted);

    let start = tokio::time::Instant::now();
    let answer = loop {
        if let Ok(Frame::Rows { rows }) = client.read_rows(channel_id, Some(posted)).await {
            let pong = rows.iter().find_map(|r| {
                let env = Envelope::parse(&r.text).ok()?;
                (r.author == target && env.kind == PONG && env.re.as_deref() == Some(&ping_key))
                    .then_some(env)
            });
            if let Some(p) = pong {
                break Some(p);
            }
        }
        if start.elapsed() >= wait {
            break None;
        }
        tokio::time::sleep(POLL).await;
    };
    let waited = start.elapsed();
    let Some(pong) = answer else {
        return Err(AppError::Refused {
            code: 1,
            message: no_answer(&name, waited),
        });
    };
    let sessions = pong.data["sessions"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    if json {
        let out = serde_json::json!({
            "schema": "vox.room.ping/1",
            "room": b32_encode(&channel_id),
            "node": b32_encode(&target),
            "ping": ping_key,
            "waited_ms": u64::try_from(waited.as_millis()).unwrap_or(u64::MAX),
            "vox": pong.data["vox"],
            "sessions": sessions,
        });
        println!("{out}");
    } else if sessions.is_empty() {
        println!("{name}'s node answered: it holds no agent session");
    } else {
        println!("{name}'s node answered:");
        for s in &sessions {
            println!("  {}", describe(s));
        }
    }
    Ok(())
}

/// What a missing answer says, and what it cannot.
fn no_answer(name: &str, waited: Duration) -> String {
    format!(
        "no answer from {name}'s node within {}s. That cannot tell apart: it is offline or runs \
         no `vox daemon`; it does not trust you, so it cannot read your ping; or you do not trust \
         it, so you cannot read its answer",
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
        _ => "not read yet".to_owned(),
    };
    let idle = match s["idle"].as_bool() {
        Some(true) => "; idle",
        Some(false) => "; busy",
        None => "",
    };
    format!(
        "session {} ({}): {reach}; {read}{idle}",
        get("session"),
        get("harness")
    )
}

/// How long ago `ms` (since the epoch) was, as a person reads it.
pub(crate) fn ago_ms(ms: u64) -> String {
    let s = crate::wake::now_millis().saturating_sub(ms) / 1000;
    match s {
        0..=59 => format!("{s}s ago"),
        60..=3599 => format!("{}m ago", s / 60),
        3600..=86_399 => format!("{}h ago", s / 3600),
        _ => format!("{}d ago", s / 86_400),
    }
}
