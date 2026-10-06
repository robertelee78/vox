//! `vox share` (ADR-028 F-1, F-2; PRD-001 R18, ADR-020 §11) — hand a file or a folder to a room,
//! addressed like a message, pulled by whoever it is for with any tool.
//!
//! **A share is one message.** Its announcement carries the note (`-m`), the addressees (`--to`,
//! each resolved here once to a whole fingerprint) and the urgent flag, besides the name, the size
//! and the **SHA-256**; the note never travels as a message of its own.
//!
//! **The daemon serves it.** This command hands the daemon the path and the addressed
//! announcement, and returns once the daemon serves the file: the daemon hashes it, serves it over
//! a **room-bound HTTP service**, and posts the announcement. It serves until the message expires
//! under the room's retention, `vox share stop`, this node leaves the room, or the room ends;
//! `--count` and `--for` remain as the sharer's own earlier stop. The receiver uses `vox room get`,
//! or `curl` (or `rsync`, or a browser) through `vox up`:
//!
//! ```text
//! curl --socks5-hostname 127.0.0.1:1080 http://<tag>.<sharer>.<room>.vox/<name> -o <name>
//! ```
//!
//! A folder is served as one deterministic tar (sorted, zero timestamps), so it has one hash like
//! a file does.
//!
//! Reach is the keyring's, as for any room-bound service: a member this node has not trusted can
//! neither read the announcement nor open the service.

use std::path::Path;
use std::time::Duration;

use vox_agentcomms::envelope::Envelope;
use vox_core::node::ipc::{Frame, Request};
use vox_core::node::paths::Paths;
use vox_core::node::shares::ShareRow;

use crate::app::AppError;
use crate::room_cli::{addressees, attach, room_of, FILE};

/// Parse `90s`, `10m`, `2h` or a bare number of seconds.
///
/// # Errors
/// A duration that is none of those.
pub fn parse_for(text: &str) -> Result<Duration, String> {
    let t = text.trim();
    let (num, unit) = t.split_at(t.find(|c: char| !c.is_ascii_digit()).unwrap_or(t.len()));
    let n: u64 = num
        .parse()
        .map_err(|_| format!("{text:?} is not a duration (90s, 10m, 2h)"))?;
    let secs = match unit {
        "" | "s" => n,
        "m" => n * 60,
        "h" => n * 3600,
        _ => return Err(format!("{text:?} is not a duration (90s, 10m, 2h)")),
    };
    Ok(Duration::from_secs(secs))
}

/// How `vox share` was asked to address and end a share.
#[derive(Debug, Clone, Default)]
pub struct ShareOpts {
    /// Addressees: the sharer's names for members, or their fingerprints. Empty addresses the
    /// room.
    pub to: Vec<String>,
    /// May interrupt the addressed members' agents mid-turn.
    pub urgent: bool,
    /// The entry hash this share answers.
    pub re: Option<String>,
    /// The note, carried in the share itself.
    pub note: Option<String>,
    /// Stop after this many completed fetches.
    pub count: Option<u64>,
    /// Stop after this long.
    pub for_: Option<Duration>,
}

fn shares_of(frame: Result<Frame, vox_core::error::Error>) -> Result<Vec<ShareRow>, AppError> {
    match frame {
        Ok(Frame::Shares { shares }) => Ok(shares),
        Ok(Frame::Error { reason }) => Err(AppError::Usage(reason)),
        Ok(other) => Err(crate::client::unexpected(&other)),
        Err(e) => Err(AppError::Usage(e.to_string())),
    }
}

/// `vox share <room> <file|dir>`.
///
/// # Errors
/// If the node cannot be reached, the room is unknown, an addressee is no member, or the daemon
/// cannot read, serve or announce the file.
pub async fn share(
    paths: &Paths,
    room: &str,
    path: &Path,
    opts: &ShareOpts,
) -> Result<(), AppError> {
    // The daemon reads the path, from wherever it was started: it is made absolute here.
    let path = std::fs::canonicalize(path)
        .map_err(|e| AppError::Usage(format!("{}: {e}", path.display())))?;
    let mut client = attach(paths).await?;
    let channel_id = room_of(&mut client, room).await?;
    let to = addressees(&mut client, channel_id, &opts.to).await?;
    let note = opts.note.as_deref().map(str::trim).unwrap_or_default();
    let session = crate::coord::session_if_named();
    let me = client
        .me()
        .ok_or_else(|| AppError::Usage("the node did not say who it is".into()))?;
    // **A share is a post, and follows a post's hop rule** (ADR-020 §9, V210-121): it answers
    // what woke the session, and spends a hop of that budget. An urgent share with a fresh one
    // would let two agents wake each other for ever by sharing.
    let (re, hops) = crate::room_cli::answers(
        &mut client,
        channel_id,
        paths,
        session.as_deref(),
        &me,
        opts.re.as_deref(),
        opts.urgent,
    )
    .await?;
    let env = {
        // The note is the message's body; with none, the daemon says what is shared.
        let mut e = Envelope::new(FILE, note);
        e.to = to;
        e.urgent = opts.urgent;
        e.re = re;
        if let Some(h) = hops {
            e.hops = h;
        }
        if !note.is_empty() {
            e.data = serde_json::json!({ "note": note });
        }
        if let Some(session) = session {
            e.from = session;
        }
        e
    };
    let shared = shares_of(
        client
            .request(&Request::Share {
                channel_id,
                path: path.to_string_lossy().into_owned(),
                envelope: serde_json::to_string(&env)
                    .map_err(|e| AppError::Usage(format!("the announcement: {e}")))?,
                count: opts.count.unwrap_or(0),
                for_secs: opts.for_.map_or(0, |d| d.as_secs().max(1)),
            })
            .await,
    )?;
    let Some(s) = shared.first() else {
        return Err(AppError::Usage(
            "the daemon did not say what it shares".into(),
        ));
    };
    if opts.urgent {
        let me = client
            .me()
            .map(|d| vox_core::node::link::b32_encode(&d))
            .unwrap_or_default();
        if let Some(line) = crate::wake::uninterruptible(paths, &me, &env.to) {
            eprintln!("vox: {line}");
        }
    }
    println!("vox: sharing {} ({} bytes) as {}", s.name, s.size, s.tag);
    println!("     sha256 {}", s.sha256);
    if !env.to.is_empty() {
        let names: Vec<String> = env
            .to
            .iter()
            .filter_map(|fp| crate::ident::recipient(fp))
            .map(|fp| crate::ident::name_of(&fp))
            .collect();
        println!("     for {}", names.join(", "));
    }
    println!("     collect it with: vox room get {room} {}", s.name);
    println!(
        "     or through `vox up`: curl --socks5-hostname <proxy> \
         http://{}.<your-name-for-this-node>.<room>.vox/{} -o {}",
        s.tag, s.name, s.name
    );
    match (opts.count, opts.for_) {
        (Some(n), _) => println!("     the daemon serves it for {n} fetch(es) at most"),
        (None, Some(d)) => println!("     the daemon serves it for {}s at most", d.as_secs()),
        (None, None) => {}
    }
    println!(
        "     served until its message expires, `vox share stop {room} {}`, you leave the room, \
         or it ends",
        s.name
    );
    Ok(())
}

/// `vox share stop <room> <name|tag>`.
///
/// # Errors
/// If the node cannot be reached, the room is unknown, or no share there matches.
pub async fn stop(paths: &Paths, room: &str, selector: &str) -> Result<(), AppError> {
    let mut client = attach(paths).await?;
    let channel_id = room_of(&mut client, room).await?;
    let stopped = shares_of(
        client
            .request(&Request::ShareStop {
                channel_id,
                selector: selector.to_owned(),
            })
            .await,
    )?;
    if stopped.is_empty() {
        return Err(AppError::Usage(format!(
            "no share of this node's in the room matches {selector:?} — `vox share list {room}` \
             shows them"
        )));
    }
    for s in stopped {
        println!(
            "vox: no longer sharing {} ({}; fetched {} time(s))",
            s.name, s.tag, s.fetched
        );
    }
    Ok(())
}

/// `vox share list <room>`.
///
/// # Errors
/// If the node cannot be reached or the room is unknown.
pub async fn list(paths: &Paths, room: &str) -> Result<(), AppError> {
    let mut client = attach(paths).await?;
    let channel_id = room_of(&mut client, room).await?;
    let shares = shares_of(client.request(&Request::ShareList { channel_id }).await)?;
    if shares.is_empty() {
        println!("(this node shares nothing in the room)");
    }
    for s in shares {
        println!(
            "{}  {} ({} bytes)  fetched {} time(s)",
            s.tag, s.name, s.size, s.fetched
        );
    }
    Ok(())
}
