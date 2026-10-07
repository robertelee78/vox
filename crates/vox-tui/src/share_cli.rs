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
//! A folder is listed, not packed (ADR-028 F-8): its announcement carries every file's path, size
//! and SHA-256, and its own SHA-256 is that of the list. Each file is served at its own path, from
//! the folder, and one that changed since it was listed is refused. A receiver fetches only what it
//! does not already hold, so pulling it again after one file changed fetches that file alone.
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

pub(crate) fn shares_of(
    frame: Result<Frame, vox_core::error::Error>,
) -> Result<Vec<ShareRow>, AppError> {
    match frame {
        Ok(Frame::Shares { shares }) => Ok(shares),
        Ok(Frame::Error { reason }) => Err(AppError::Usage(reason)),
        Ok(other) => Err(crate::client::unexpected(&other)),
        Err(e) => Err(AppError::Usage(e.to_string())),
    }
}

/// What a share offered: what the daemon serves, whom its announcement is to, and anything the
/// sharer is to be told besides (an addressee that cannot be interrupted).
pub(crate) struct Offered {
    pub(crate) row: ShareRow,
    pub(crate) to: Vec<String>,
    pub(crate) notes: Vec<String>,
}

/// **The one way a file or folder is shared** (ADR-028 F-1): `vox share`, and the TUI's attach.
/// The path is made absolute, the addressees checked, the hop rule applied, and one announcement
/// carrying the note, the addressees and urgent is posted by the daemon, which serves it.
/// `before` is told what is to be shared, in which room, and who is to fetch it, before it is.
///
/// # Errors
/// As `vox share` refuses.
pub(crate) async fn offer(
    paths: &Paths,
    room: &str,
    path: &Path,
    opts: &ShareOpts,
    before: impl FnOnce(&str, &str, &[String]),
) -> Result<Offered, AppError> {
    // The daemon reads the path, from wherever it was started: it is made absolute here.
    let path = std::fs::canonicalize(path)
        .map_err(|e| AppError::Usage(format!("{}: {e}", path.display())))?;
    let mut client = attach(paths).await?;
    let channel_id = room_of(&mut client, room).await?;
    let to = addressees(&mut client, channel_id, &opts.to).await?;
    // Who it is to reach, said before it is offered (ADR-028 E-5).
    let which = crate::room_cli::room_named(&mut client, channel_id).await;
    let reach = crate::room_cli::trusted_in(&mut client, channel_id).await;
    let base = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let what = if path.is_dir() {
        // A folder is shared as its files, each pulled and checked on its own (#499).
        format!("{base}/ (a folder)")
    } else {
        base
    };
    before(&what, &which, &reach);
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
    let Some(row) = shared.into_iter().next() else {
        return Err(AppError::Usage(
            "the daemon did not say what it shares".into(),
        ));
    };
    let mut notes = Vec::new();
    if opts.urgent {
        let me = client
            .me()
            .map(|d| vox_core::node::link::b32_encode(&d))
            .unwrap_or_default();
        if let Some(line) = crate::wake::uninterruptible(paths, &me, &env.to) {
            notes.push(line);
        }
    }
    Ok(Offered {
        row,
        to: env.to,
        notes,
    })
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
    let Offered { row, to, notes } = offer(paths, room, path, opts, |what, which, reach| {
        println!("vox: about to share {what} in {which}");
        println!(
            "     the members of it in your keyring are to fetch it: {}",
            crate::room_cli::listed(reach, "none yet")
        );
    })
    .await?;
    for line in &notes {
        eprintln!("vox: {line}");
    }
    let s = &row;
    let env = Envelope {
        to,
        ..Envelope::new(FILE, "")
    };
    if s.files > 0 {
        println!(
            "vox: sharing {}/ ({} files, {} bytes) as {}",
            s.name, s.files, s.size, s.tag
        );
        println!("     sha256 {} (of its file list)", s.sha256);
    } else {
        println!("vox: sharing {} ({} bytes) as {}", s.name, s.size, s.tag);
        println!("     sha256 {}", s.sha256);
    }
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
    if s.files > 0 {
        println!(
            "     or one file through `vox up`: curl --socks5-hostname <proxy> \
             http://{}.<your-name-for-this-node>.<room>.vox/<path in {}/>",
            s.tag, s.name
        );
    } else {
        println!(
            "     or through `vox up`: curl --socks5-hostname <proxy> \
             http://{}.<your-name-for-this-node>.<room>.vox/{} -o {}",
            s.tag, s.name, s.name
        );
    }
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
    // What it is to end, said before it is ended (ADR-028 E-5).
    let which = crate::room_cli::room_named(&mut client, channel_id).await;
    println!("vox: about to stop sharing {selector:?} in {which}");
    println!("     no member is to fetch it from this node after this");
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
