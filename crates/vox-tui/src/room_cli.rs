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
use std::path::Path;

use vox_core::hash::Digest32;
use vox_core::node::ipc::{Frame, IpcClient, Request};
use vox_core::node::link::{b32_decode, b32_encode, B32_DIGEST_LEN};
use vox_core::node::paths::Paths;

use crate::app::AppError;
use crate::tunnel_cli::resolve_prefix;

/// Connect to the running node's control socket for this profile.
///
/// The failure an operator will actually hit is "no node is running", so it says
/// that rather than surfacing a connect error — **and names the thing that would
/// actually fix it.** It used to say "Start one with `vox node`", which is the first
/// error a new person meets and it sent them in a circle: `vox node` is an anchor, it
/// holds no room and serves no control socket, so following the advice produced this
/// same message again, verbatim. `vox daemon` is what holds a profile's rooms and
/// serves this socket.
async fn attach(paths: &Paths) -> Result<IpcClient, AppError> {
    let sock = paths.socket_file();
    if !sock.exists() {
        return Err(AppError::Usage(format!(
            "no node is running for this profile, so there is nothing to ask.\n\
             \x20      Start one:  vox daemon        (holds this profile's rooms, no \
             terminal needed)\n\
             \x20             or:  vox tui           (the interactive client)\n\
             \x20      `vox node` will NOT do: it is an anchor, it holds no room and \
             serves no socket.\n\
             \x20      Socket: {}",
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

/// A held-since time, as a person reads it.
///
/// It was printed as raw epoch seconds — `held by … since 1790105354` — which nobody
/// reads, and which is the one number in the message that is supposed to tell you
/// whether to wait or go and find the holder. Both forms are given: the elapsed time
/// answers that question, and the absolute time survives being pasted into a report.
fn held_since(since_secs: u64) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let ago = now.saturating_sub(since_secs);
    let elapsed = if ago < 60 {
        format!("{ago}s ago")
    } else if ago < 3600 {
        format!("{}m ago", ago / 60)
    } else if ago < 86_400 {
        format!("{}h{:02}m ago", ago / 3600, (ago % 3600) / 60)
    } else {
        format!("{}d ago", ago / 86_400)
    };
    // A fixed-offset UTC stamp without pulling in a date library: the fields are
    // arithmetic on the epoch, and the only calendar subtlety is leap years.
    let (days, secs) = (since_secs / 86_400, since_secs % 86_400);
    let (mut y, mut d) = (1970_u64, days);
    loop {
        let len = if (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 {
            366
        } else {
            365
        };
        if d < len {
            break;
        }
        d -= len;
        y += 1;
    }
    let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    let months = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let mut m = 0;
    while m < 12 && d >= months[m] {
        d -= months[m];
        m += 1;
    }
    format!(
        "{y:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z ({elapsed})",
        m + 1,
        d + 1,
        secs / 3600,
        (secs % 3600) / 60,
        secs % 60
    )
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

// ---------------------------------------------------------------------------
// The work board (ADR-020 §5, M19.9)
// ---------------------------------------------------------------------------
//
// The decider's requirement is that agents "communicate **and split work loads**".
// `vox-agentcomms` has carried the whole model since M19.3 — the claim vocabulary,
// the operations and a resolver that folds a room's claims into one owner per
// resource — and until now nothing in the shipped binary called any of it. An agent
// could speak but could not take a piece of work, give it up, hand it over, or ask
// what was already taken. These four verbs are that model made reachable.
//
// Claims are **messages, not locks**. Nothing here reserves anything in the node:
// ownership is whatever `resolve` computes from the room's log, so two agents that
// both post a claim converge on the same answer without either asking a coordinator
// — and an agent that dies holding a resource releases it by its claim's `--ttl`
// lapsing, with nobody acting.

use vox_agentcomms::claim::{self, Posted};
use vox_agentcomms::envelope::Envelope;

/// Read a room's claims and fold them into one owner per resource.
///
/// A pure function of the log, so every member computes the same board with nobody
/// being authoritative — which is the property that lets agents split work without
/// a coordinator.
async fn read_board(
    client: &mut IpcClient,
    channel_id: Digest32,
) -> Result<std::collections::BTreeMap<String, claim::Ownership>, AppError> {
    let rows = match client
        .request(&Request::Read {
            channel_id,
            since: None,
            limit: 0,
        })
        .await
    {
        Ok(Frame::Rows { rows }) => rows,
        Ok(Frame::Error { reason }) => return Err(AppError::Usage(reason)),
        Ok(other) => return Err(AppError::Usage(format!("unexpected reply: {other:?}"))),
        Err(e) => return Err(AppError::Usage(e.to_string())),
    };
    let posted: Vec<Posted> = rows
        .iter()
        .filter_map(|r| {
            Envelope::parse(&r.text).ok().map(|envelope| Posted {
                entry_hash: r.entry_hash,
                author: r.author,
                created_millis: r.created_millis,
                envelope,
            })
        })
        .collect();
    Ok(claim::resolve(&posted, now_secs()))
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Post a claim operation as an envelope.
async fn post_claim_op(
    paths: &Paths,
    room: &str,
    kind: &str,
    data: serde_json::Value,
    body: &str,
) -> Result<(), AppError> {
    let mut env = Envelope::new(kind, body);
    env.data = data;
    post(paths, room, Some(&env.to_text())).await
}

/// `vox room claim` — take a resource.
///
/// # Errors
/// If the node cannot be reached, the room is unknown, or the post is refused.
pub async fn claim_resource(
    paths: &Paths,
    room: &str,
    resource: &str,
    ttl_secs: Option<u64>,
) -> Result<(), AppError> {
    if resource.trim().is_empty() {
        return Err(AppError::Usage("a claim needs a resource".into()));
    }
    let mut data = serde_json::json!({ "resource": resource });
    if let Some(ttl) = ttl_secs {
        data["ttl_secs"] = serde_json::json!(ttl);
    }
    post_claim_op(
        paths,
        room,
        claim::CLAIM,
        data,
        &format!("claiming {resource}"),
    )
    .await?;

    // **Then say whether it was won.** A claim is a message, not a lock, so posting
    // one is not taking the resource — the log decides, and an earlier claim beats
    // this one. An agent that cannot tell the difference would start work somebody
    // else is already doing, which is the exact failure claims exist to prevent.
    // The exit status is the machine-readable half: 0 means it is yours.
    let mut client = attach(paths).await?;
    let channel_id = room_of(&mut client, room).await?;
    let board = read_board(&mut client, channel_id).await?;
    let me = client.me();
    match board.get(resource) {
        Some(own) if Some(own.owner) == me => {
            println!("you hold {resource}");
            Ok(())
        }
        Some(own) => Err(AppError::Usage(format!(
            "{resource} is held by {} since {} — you did not get it",
            short(&own.owner),
            held_since(own.since_secs)
        ))),
        // Resolvable only if the post has not converged yet; treat it as not held
        // rather than claiming success we cannot see.
        None => Err(AppError::Usage(format!(
            "{resource} is not held by anyone, including you — the claim has not \
             converged yet; run `vox room board {room}` to check"
        ))),
    }
}

/// `vox room release` — give a resource up.
///
/// # Errors
/// If the node cannot be reached, the room is unknown, or the post is refused.
pub async fn release_resource(paths: &Paths, room: &str, resource: &str) -> Result<(), AppError> {
    if resource.trim().is_empty() {
        return Err(AppError::Usage("a release needs a resource".into()));
    }
    post_claim_op(
        paths,
        room,
        claim::RELEASE,
        serde_json::json!({ "resource": resource }),
        &format!("releasing {resource}"),
    )
    .await
}

/// `vox service remove`, asked of the node already running this profile.
///
/// The one-shot form opens the profile itself, which redb refuses while a daemon holds it
/// — and a running host is exactly when removing a service matters, because that is when
/// it is carrying sessions the removal must cut (PRD-001 R22). The request is the one
/// `vox room send` already makes when its offer ends; it only ever narrows what is exposed.
///
/// # Errors
/// If the node cannot be reached, the room is unknown, or the service was not offered.
pub async fn service_remove(paths: &Paths, room: &str, tag: &str) -> Result<(), AppError> {
    let mut client = attach(paths).await?;
    let channel_id = room_of(&mut client, room).await?;
    match client
        .request(&Request::RemoveService {
            channel_id,
            service_tag: tag.to_owned(),
        })
        .await
    {
        Ok(Frame::Ok) => {
            println!("vox: no longer offering {tag:?}; its live sessions were cut");
            Ok(())
        }
        Ok(Frame::Error { .. }) => Err(AppError::Usage(format!("{tag:?} was not offered here"))),
        Ok(other) => Err(AppError::Usage(format!("unexpected reply: {other:?}"))),
        Err(e) => Err(AppError::Usage(e.to_string())),
    }
}

/// `vox room handoff` — pass a resource to someone by petname.
///
/// # Errors
/// If the node cannot be reached, the room is unknown, or the post is refused.
pub async fn handoff_resource(
    paths: &Paths,
    room: &str,
    resource: &str,
    to: &str,
) -> Result<(), AppError> {
    if resource.trim().is_empty() {
        return Err(AppError::Usage("a handoff needs a resource".into()));
    }
    if to.trim().is_empty() {
        return Err(AppError::Usage("a handoff needs a recipient".into()));
    }
    post_claim_op(
        paths,
        room,
        claim::HANDOFF,
        serde_json::json!({ "resource": resource, "to": to }),
        &format!("handing {resource} to {to}"),
    )
    .await
}

/// `vox room board` — what is taken, by whom, and until when.
///
/// Reads the whole room and folds its claims. The result is a pure function of the
/// log, so every member computes the same board without anyone being authoritative.
///
/// **Handoffs are shown by the name the sender used, not resolved to a
/// fingerprint.** A petname is local to whoever typed it, and resolving one needs
/// the trust keyring, which has no control-socket request yet — that arrives with
/// `vox trust`. Until then a handoff is displayed as the intent it is, marked so,
/// rather than guessed at.
///
/// # Errors
/// If the node cannot be reached or the room is unknown.
pub async fn board(paths: &Paths, room: &str) -> Result<(), AppError> {
    let mut client = attach(paths).await?;
    let channel_id = room_of(&mut client, room).await?;
    let owned = read_board(&mut client, channel_id).await?;
    let me = client.me();
    let now = now_secs();

    let mut out = std::io::stdout().lock();
    if owned.is_empty() {
        writeln!(out, "nothing is claimed").map_err(AppError::Io)?;
        return Ok(());
    }
    for (resource, own) in &owned {
        let expiry = match own.expires_secs {
            // Seconds remaining, not an absolute time: "in 240s" is actionable and
            // a Unix timestamp is not.
            Some(e) if e > now => format!(" expires in {}s", e - now),
            Some(_) => " expired".to_owned(),
            None => String::new(),
        };
        let named = match &own.named {
            Some(n) => format!(" (handed to {n}, unresolved)"),
            None => String::new(),
        };
        let mine = if Some(own.owner) == me { " (you)" } else { "" };
        writeln!(
            out,
            "{resource}\t{}{mine}{expiry}{named}",
            short(&own.owner)
        )
        .map_err(AppError::Io)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// File exchange (ADR-020 §11, M19.8)
// ---------------------------------------------------------------------------
//
// **The bytes never enter the log.** They ride a room-bound service — the same
// ADR-013/017 machinery `vox serve` uses — and what goes on the log is a signed
// announcement naming the file, its size and its **SHA-256**. That is the decider's
// own idiom, `nc -l` one side and `cat file | nc` the other, with the address
// become a `.vox` name: no routable address, no firewall hole, no VPN, and the
// bytes end-to-end encrypted because the overlay already is.
//
// Two properties follow, and both are deliberate:
//
//   - the **announcement is durable** — it is a log entry, so an agent asleep when
//     the file was offered still sees it on waking;
//   - the **bytes are live** — the sender must still be serving, so a late
//     collector may find the offer gone. It is then told so, which is better than a
//     reference that silently resolves to nothing.
//
// **Nobody is granted anything.** Reach is gated on the offering node's trust
// keyring plus room authorship, and reading the announcement requires exactly the
// same ring entry — so the audience of the announcement *is* the audience of the
// transfer, by construction rather than by coincidence.
//
// The hash earns its place for a reason unrelated to secrecy: `cat | nc` **truncates
// silently**. The connection drops, the receiver gets a partial file, and `nc` exits
// 0. Verifying against a hash the sender signed turns that into a loud failure.

/// The envelope type an offer is announced with.
const FILE: &str = "file";

/// Read a file and return its SHA-256 and length.
fn digest_file(path: &std::path::Path) -> Result<(String, u64), AppError> {
    use sha2::{Digest as _, Sha256};
    let mut f = std::fs::File::open(path)
        .map_err(|e| AppError::Usage(format!("opening {}: {e}", path.display())))?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    let mut total: u64 = 0;
    loop {
        let n = std::io::Read::read(&mut f, &mut buf)
            .map_err(|e| AppError::Usage(format!("reading {}: {e}", path.display())))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        total += n as u64;
    }
    Ok((hex(&hasher.finalize()), total))
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// `vox room send` — offer a file to a room and announce it.
///
/// Runs until interrupted: the bytes are served live, so stopping this stops the
/// offer. Every member that collects it gets the same file.
///
/// # Errors
/// If the node cannot be reached, the room is unknown, the file cannot be read, or
/// the node refuses to offer the service.
pub async fn send_file(paths: &Paths, room: &str, path: &std::path::Path) -> Result<(), AppError> {
    let (sha256, size) = digest_file(path)?;
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "file".to_owned());
    // The tag is derived from the content, so two offers of the same bytes collide
    // harmlessly and two different files never do.
    let tag = format!("file-{}", &sha256[..16]);

    let mut client = attach(paths).await?;
    let channel_id = room_of(&mut client, room).await?;

    // A listener that hands the file to whoever connects, for as long as we run.
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .map_err(|e| AppError::Usage(format!("cannot listen locally: {e}")))?;
    let local = listener
        .local_addr()
        .map_err(|e| AppError::Usage(format!("cannot read the local address: {e}")))?;

    match client
        .request(&Request::AddService {
            channel_id,
            service_tag: tag.clone(),
            local: local.to_string(),
        })
        .await
    {
        Ok(Frame::Ok) => {}
        Ok(Frame::Error { reason }) => {
            // Not "needs bind:<tag>, which the room's admin grants": that capability was
            // deleted in ADR-017's third revision — offering a port of your own machine
            // is not the room's business — and `add_service` stopped checking it at M17.7.
            // The message named a permission nobody can hold and an admin nobody has.
            return Err(AppError::Usage(format!("cannot offer {tag:?}: {reason}")));
        }
        Ok(other) => return Err(AppError::Usage(format!("unexpected reply: {other:?}"))),
        Err(e) => return Err(AppError::Usage(e.to_string())),
    }

    // A `dial:` grant per member used to be issued here, "so it works under either
    // model". There is one model: reach is the host's trust keyring (M17.7), and the
    // capability has not been consulted since. The loop wrote a governance fact per
    // member per offer onto the room's log, which nothing read — and it kept the
    // withdrawn model alive in the one verb a person uses most.

    let env = {
        let mut e = Envelope::new(FILE, &format!("offering {name} ({size} bytes)"));
        e.data = serde_json::json!({
            "name": name,
            "size": size,
            "sha256": sha256,
            "tag": tag,
        });
        e
    };
    post(paths, room, Some(&env.to_text())).await?;

    println!("vox: offering {name} ({size} bytes) as {tag}");
    println!("     sha256 {sha256}");
    println!(
        "     collect it with: vox room get {} {name}",
        &room_of_label(channel_id)
    );
    println!("     Ctrl-C stops the offer; the announcement stays on the log");

    let path = path.to_owned();
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let Ok((mut sock, _)) = accepted else { continue };
                let p = path.clone();
                // `std::fs` because this workspace's tokio has no `fs` feature, and
                // widening a dependency for one CLI verb is the wrong trade. The
                // reads are chunked, so a large file is not held in memory.
                tokio::spawn(async move {
                    use tokio::io::AsyncWriteExt as _;
                    let Ok(mut f) = std::fs::File::open(&p) else { return };
                    let mut buf = vec![0u8; 64 * 1024];
                    loop {
                        match std::io::Read::read(&mut f, &mut buf) {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                if sock.write_all(&buf[..n]).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                    let _ = sock.flush().await;
                });
            }
            _ = tokio::signal::ctrl_c() => break,
        }
    }
    println!("vox: no longer offering {tag}");
    let _ = client
        .request(&Request::RemoveService {
            channel_id,
            service_tag: tag,
        })
        .await;
    Ok(())
}

fn room_of_label(channel_id: Digest32) -> String {
    b32_encode(&channel_id).chars().take(12).collect()
}

/// An offer read off the room's log.
struct Offer {
    author: Digest32,
    name: String,
    size: u64,
    sha256: String,
    tag: String,
}

/// `vox room get` — collect an offered file and verify it.
///
/// # Errors
/// If the node cannot be reached, the room is unknown, no matching offer exists,
/// the transfer cannot be established, or **the bytes do not match the announced
/// hash**, in which case the partial file is removed.
pub async fn get_file(
    paths: &Paths,
    room: &str,
    selector: &str,
    out: Option<&std::path::Path>,
) -> Result<(), AppError> {
    let mut client = attach(paths).await?;
    let channel_id = room_of(&mut client, room).await?;
    let rows = match client
        .request(&Request::Read {
            channel_id,
            since: None,
            limit: 0,
        })
        .await
    {
        Ok(Frame::Rows { rows }) => rows,
        Ok(Frame::Error { reason }) => return Err(AppError::Usage(reason)),
        Ok(other) => return Err(AppError::Usage(format!("unexpected reply: {other:?}"))),
        Err(e) => return Err(AppError::Usage(e.to_string())),
    };

    // The most recent matching offer wins: re-offering a file supersedes.
    let offer = rows
        .iter()
        .rev()
        .filter_map(|r| {
            let env = Envelope::parse(&r.text).ok()?;
            if env.kind != FILE {
                return None;
            }
            let d = &env.data;
            let name = d.get("name")?.as_str()?.to_owned();
            let sha256 = d.get("sha256")?.as_str()?.to_owned();
            let tag = d.get("tag")?.as_str()?.to_owned();
            let size = d.get("size")?.as_u64()?;
            (name == selector || sha256.starts_with(selector) || tag == selector).then_some(Offer {
                author: r.author,
                name,
                size,
                sha256,
                tag,
            })
        })
        .next()
        .ok_or_else(|| {
            AppError::Usage(format!(
                "no offer in this room matches {selector:?} — `vox room read` shows what was \
                 announced"
            ))
        })?;

    let dest = out.map_or_else(|| std::path::PathBuf::from(&offer.name), Path::to_owned);

    let bound = match client
        .request(&Request::Forward {
            channel_id,
            host: offer.author,
            service_tag: offer.tag.clone(),
            local: "127.0.0.1:0".into(),
        })
        .await
    {
        Ok(Frame::Bound { local }) => local,
        Ok(Frame::Error { reason }) => {
            return Err(AppError::Usage(format!(
                "cannot reach the offer: {reason} — the sender may have stopped serving it, or \
                 may not have trusted this identity"
            )))
        }
        Ok(other) => return Err(AppError::Usage(format!("unexpected reply: {other:?}"))),
        Err(e) => return Err(AppError::Usage(e.to_string())),
    };

    let result = collect(&bound, &dest, &offer).await;
    let _ = client
        .request(&Request::StopForward {
            local: bound.clone(),
        })
        .await;
    result
}

/// Stream the offered bytes to `dest`, verifying as we go.
async fn collect(bound: &str, dest: &std::path::Path, offer: &Offer) -> Result<(), AppError> {
    use sha2::{Digest as _, Sha256};
    use tokio::io::AsyncReadExt as _;

    let mut sock = tokio::net::TcpStream::connect(bound)
        .await
        .map_err(|e| AppError::Usage(format!("connecting to the forward: {e}")))?;
    let mut file = std::fs::File::create(dest)
        .map_err(|e| AppError::Usage(format!("creating {}: {e}", dest.display())))?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    let mut total: u64 = 0;
    loop {
        let n = sock
            .read(&mut buf)
            .await
            .map_err(|e| AppError::Usage(format!("reading the transfer: {e}")))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        std::io::Write::write_all(&mut file, &buf[..n])
            .map_err(|e| AppError::Usage(format!("writing {}: {e}", dest.display())))?;
        total += n as u64;
    }
    std::io::Write::flush(&mut file)
        .map_err(|e| AppError::Usage(format!("flushing {}: {e}", dest.display())))?;
    drop(file);

    let got = hex(&hasher.finalize());
    if got != offer.sha256 {
        // **The partial file is removed.** `cat | nc` truncating silently is the
        // classic way this idiom bites; leaving a file that looks complete and is
        // not would reproduce exactly that failure with extra steps.
        let _ = std::fs::remove_file(dest);
        return Err(AppError::Usage(format!(
            "the transfer does not match what was announced — expected sha256 {} over {} bytes, \
             got {got} over {total}. The partial file was removed.",
            offer.sha256, offer.size
        )));
    }
    println!("vox: {} ({total} bytes) verified", dest.display());
    Ok(())
}

/// Read a passphrase from stdin, stripping exactly one trailing newline.
///
/// Stdin rather than an argument: argv is visible to anything that can run `ps`.
fn passphrase_from_stdin(what: &str) -> Result<String, AppError> {
    let mut buf = String::new();
    std::io::stdin()
        .read_to_string(&mut buf)
        .map_err(|e| AppError::Usage(format!("reading {what} on stdin: {e}")))?;
    let p = buf
        .strip_suffix('\n')
        .unwrap_or(&buf)
        .strip_suffix('\r')
        .unwrap_or_else(|| buf.strip_suffix('\n').unwrap_or(&buf));
    if p.is_empty() {
        // The caller's phrase is a noun phrase ("the room's passphrase", "a passphrase
        // for the new room"), so it reads as "expected <phrase> on stdin" and never as
        // "no a passphrase", which is what "no {what}" produced.
        return Err(AppError::Usage(format!(
            "expected {what} on stdin — pipe it in, e.g. `echo … | vox room join …`"
        )));
    }
    Ok(p.to_owned())
}

/// `vox room join` — join a room over a running node (ADR-020 §12).
///
/// This is what makes agent comms reachable on a host with no terminal. `vox
/// daemon` lets a node *hold* rooms unattended; until this existed, the only way
/// to get a room onto that node was the TUI, so an agent on a remote machine could
/// run a daemon and never have anything to put in it.
///
/// # Errors
/// If the node cannot be reached, or the join is refused — and the refusal is
/// reported as the node gave it, because `Unreachable` and a wrong passphrase need
/// completely different responses from whoever holds the link.
pub async fn join(paths: &Paths, link: &str, local_name: &str) -> Result<(), AppError> {
    let passphrase = passphrase_from_stdin("the room's passphrase")?;
    let mut client = attach(paths).await?;
    match client
        .request(&Request::Join {
            link: link.to_owned(),
            local_name: local_name.to_owned(),
            passphrase,
        })
        .await
    {
        Ok(Frame::Ok) => {
            println!("vox: joined {local_name}");
            println!("     you can read this room; whether anyone can read YOU is their decision");
            Ok(())
        }
        // The daemon sends the outcome's name; turn it into the same guidance `vox connect`
        // gives, so a wrong passphrase is not reported as `Failed(Refused)`.
        Ok(Frame::Error { reason }) => Err(AppError::Usage(
            match crate::tunnel_cli::fault_named(&reason) {
                Some(fault) => format!(
                    "cannot join: {}",
                    crate::tunnel_cli::join_advice(Some(fault))
                ),
                None => format!("cannot join: {reason}"),
            },
        )),
        Ok(other) => Err(AppError::Usage(format!("unexpected reply: {other:?}"))),
        Err(e) => Err(AppError::Usage(e.to_string())),
    }
}

/// `vox room create` — create a room over a running node.
///
/// # Errors
/// If the node cannot be reached or the create is refused.
pub async fn create(paths: &Paths, local_name: &str) -> Result<(), AppError> {
    let passphrase = passphrase_from_stdin("a passphrase for the new room")?;
    let mut client = attach(paths).await?;
    match client
        .request(&Request::Create {
            local_name: local_name.to_owned(),
            passphrase,
        })
        .await
    {
        Ok(Frame::Ok) => {
            println!("vox: created {local_name}");
            println!("     `vox room list` shows its id; that id is what agents pass as --room");
            Ok(())
        }
        Ok(Frame::Error { reason }) => Err(AppError::Usage(format!("cannot create: {reason}"))),
        Ok(other) => Err(AppError::Usage(format!("unexpected reply: {other:?}"))),
        Err(e) => Err(AppError::Usage(e.to_string())),
    }
}

/// `vox room invite` — print a room's address for someone else to join with.
///
/// The address is rendezvous information, not a credential: it names the room and
/// where to look, it carries no passphrase, and since M17.6 joining with it grants
/// nothing. Send the passphrase by a different channel, and decide separately who
/// may read you.
///
/// # Errors
/// If the node cannot be reached, the room is unknown, or no link is minted.
pub async fn invite(paths: &Paths, room: &str) -> Result<(), AppError> {
    let mut client = attach(paths).await?;
    let channel_id = room_of(&mut client, room).await?;
    match client.request(&Request::Invite { channel_id }).await {
        Ok(Frame::Link { url }) => {
            println!("{url}");
            eprintln!("vox: send the passphrase by a different channel than this address");
            eprintln!("     joining grants nothing — use `vox trust add` to decide who reads you");
            Ok(())
        }
        Ok(Frame::Error { reason }) => Err(AppError::Usage(reason)),
        Ok(other) => Err(AppError::Usage(format!("unexpected reply: {other:?}"))),
        Err(e) => Err(AppError::Usage(e.to_string())),
    }
}

// ---------------------------------------------------------------- the trust keyring

/// Whether a node is already serving this profile's control socket.
///
/// Used to decide whether a verb should ask the running node or start its own. It is a
/// probe, not a guarantee: the node may stop between this answering and the request being
/// made, and the caller handles that the same way it handles any other socket failure.
pub async fn node_is_running(paths: &Paths) -> bool {
    let sock = paths.socket_file();
    sock.exists() && IpcClient::open(&sock).await.is_ok()
}

/// `vox trust add`, asked of the running node instead of a second one.
///
/// The keyring is the one thing an agent session must not be able to change (ADR-020 §7),
/// so the request carries the identity passphrase and the node checks it before doing
/// anything. That is what makes this safe to put on a socket an agent can reach.
pub async fn trust_add(
    paths: &Paths,
    target: Digest32,
    petname: &str,
    identity_passphrase: &str,
) -> Result<(), AppError> {
    let mut client = attach(paths).await?;
    match client
        .request(&Request::Trust {
            target,
            petname: petname.to_owned(),
            identity_passphrase: identity_passphrase.to_owned(),
        })
        .await
    {
        Ok(Frame::Ok) => {
            println!("vox: trusting {} as {petname:?}", short(&target));
            println!("     it may now read what you write in every room you share — now and later");
            println!("     and reach every service you bind to a room you are both in");
            println!("     `vox trust remove` undoes it and changes the lock everywhere");
            Ok(())
        }
        Ok(Frame::Error { reason }) => Err(AppError::Usage(reason)),
        Ok(other) => Err(AppError::Usage(format!("unexpected reply: {other:?}"))),
        Err(e) => Err(AppError::Usage(e.to_string())),
    }
}

/// `vox trust remove`, asked of the running node.
pub async fn trust_remove(
    paths: &Paths,
    target: Digest32,
    identity_passphrase: &str,
) -> Result<(), AppError> {
    let mut client = attach(paths).await?;
    match client
        .request(&Request::Untrust {
            target,
            identity_passphrase: identity_passphrase.to_owned(),
        })
        .await
    {
        Ok(Frame::Ok) => {
            println!("vox: no longer trusting {}", short(&target));
            println!("     your sender key is rotated and everyone still trusted is re-keyed");
            Ok(())
        }
        Ok(Frame::Error { reason }) => Err(AppError::Usage(reason)),
        Ok(other) => Err(AppError::Usage(format!("unexpected reply: {other:?}"))),
        Err(e) => Err(AppError::Usage(e.to_string())),
    }
}

/// `vox trust list`, asked of the running node.
pub async fn trust_list(paths: &Paths, identity_passphrase: &str) -> Result<(), AppError> {
    let mut client = attach(paths).await?;
    match client
        .request(&Request::TrustList {
            identity_passphrase: identity_passphrase.to_owned(),
        })
        .await
    {
        Ok(Frame::Trusted { entries }) => {
            if entries.is_empty() {
                println!("no trusted identities");
                println!("     nobody can read what you write until you `vox trust add` them");
                return Ok(());
            }
            for (id, petname) in entries {
                println!("{}  {petname}", vox_core::node::link::b32_encode(&id));
            }
            Ok(())
        }
        Ok(Frame::Error { reason }) => Err(AppError::Usage(reason)),
        Ok(other) => Err(AppError::Usage(format!("unexpected reply: {other:?}"))),
        Err(e) => Err(AppError::Usage(e.to_string())),
    }
}

/// `vox id`, asked of the running node.
///
/// Printing your own fingerprint is the most ordinary thing a person does — it is what
/// they send to somebody who will type it into `vox trust add` — and it needs no secret
/// and changes nothing. It nevertheless failed outright whenever a daemon held the
/// profile, because it went through a node of its own.
///
/// The socket's hello already carries it (protocol 2's `me`), so this costs no new
/// request and no passphrase: a fingerprint is public.
pub async fn print_identity(paths: &Paths) -> Result<(), AppError> {
    let client = attach(paths).await?;
    let Some(me) = client.me() else {
        return Err(AppError::Usage(
            "the running node has no identity yet. Make one:  vox id  (with the daemon \
             stopped)"
                .into(),
        ));
    };
    // The whole fingerprint, alone on the line, so it pipes and pastes without editing.
    println!("{}", vox_core::node::link::b32_encode(&me));
    Ok(())
}
