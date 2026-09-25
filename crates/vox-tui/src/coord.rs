//! ADR-021 — the plumbing every coordinating verb shares: who is speaking, where,
//! with which operation id, under which version, and whether it may.
//!
//! The verbs in [`crate::room_cli`] decide *what* to post. This module decides
//! everything a post must carry to be a valid work-coordination message, and it is
//! one code path so that no verb can forget a part of it:
//!
//! - **the session** (`from`) — ownership is `(author fingerprint, session)`, so a
//!   claim with no session is refused rather than attributed to the whole harness;
//! - **the context** (`at`) — the repository, worktree, branch and directory the
//!   session is working in, read from Git rather than trusted to a caller;
//! - **the operation id** (`data.op`) — supplied by the caller for a real retry, or
//!   minted as a convenience;
//! - **the version stamp** (`data.vox`) — always this binary's own, never the
//!   caller's;
//! - **the version gate** — a worker refuses to coordinate while any participant in
//!   the room runs another version (ADR-021 §5).
//!
//! It holds no work state. `data.work` is carried and never interpreted: this is a
//! transport for a tracker's observations, not a tracker (ADR-021 §1).

use vox_agentcomms::claim::{self, Fold, Posted};
use vox_agentcomms::envelope::{Context, Envelope, HELLO, WORK_KEY};
use vox_agentcomms::ops::{self, OpIndex, Verdict};
use vox_agentcomms::version::{self, Stamp, VersionTable, VOX_KEY};
use vox_core::hash::Digest32;
use vox_core::node::api::MessageRow;
use vox_core::node::ipc::{Frame, IpcClient, Request};
use vox_core::node::link::b32_encode;

use crate::app::AppError;

/// This binary's version: the stamp it writes and the only one its fold applies.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Exit status of a verb refused because a participant runs another version.
pub const EXIT_VERSION: u8 = 3;
/// Exit status of a post whose operation id already names different content.
pub const EXIT_CONFLICT: u8 = 4;

/// The session this process speaks for, or `None` when nothing names one.
///
/// In order: `--session`; `VOX_SESSION`; then what the harness puts in every tool
/// process's environment — Claude Code's `CLAUDE_CODE_SESSION_ID` and Codex's
/// `CODEX_THREAD_ID`. OpenCode has no such variable, and its Vox plugin exports
/// `VOX_SESSION` to every shell it runs instead (`shell.env`).
///
/// These are the *same* values the drain hook receives as the session id, which is
/// what lets it recognise this session's own messages (ADR-021 §7).
///
/// **Not `VOX_AGENT_NAME`.** That is the name a session is *addressed* by, and it is
/// set in harness settings shared by every session of the harness — using it as the
/// owner would make two sessions one owner again, the defect ADR-021 F3 names.
#[must_use]
pub fn session(flag: Option<&str>) -> Option<String> {
    let from_env = |k: &str| std::env::var(k).ok();
    flag.map(str::to_owned)
        .or_else(|| from_env("VOX_SESSION"))
        .or_else(|| from_env("CLAUDE_CODE_SESSION_ID"))
        .or_else(|| from_env("CODEX_THREAD_ID"))
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty() && s.len() <= 128)
}

/// The session, or a refusal that says how to name one.
///
/// # Errors
/// When nothing names a session.
pub fn require_session(flag: Option<&str>) -> Result<String, AppError> {
    session(flag).ok_or_else(|| {
        AppError::Usage(
            "no session: work coordination is owned per session (ADR-021 §4), and nothing \
             names this one. Run inside Claude Code or Codex, set VOX_SESSION, or pass \
             --session."
                .into(),
        )
    })
}

/// Where this process is working, read from Git.
///
/// Best effort: outside a repository only `cwd` is filled, and a missing `git` is
/// not an error — the context is information for readers, not a precondition.
#[must_use]
pub fn context() -> Context {
    let git = |args: &[&str]| -> Option<String> {
        let out = std::process::Command::new("git")
            .args(args)
            .stderr(std::process::Stdio::null())
            .output()
            .ok()?;
        if !out.status.success() {
            return None;
        }
        let s = String::from_utf8_lossy(&out.stdout).trim().to_owned();
        (!s.is_empty()).then_some(s)
    };
    let worktree = git(&["rev-parse", "--show-toplevel"]);
    // The repository is where the shared `.git` lives, which is not the worktree when
    // several are checked out — the distinction ADR-020 §4 keeps both fields for.
    let repo = git(&["rev-parse", "--path-format=absolute", "--git-common-dir"]).map(|d| {
        let p = std::path::PathBuf::from(&d);
        if p.file_name().is_some_and(|n| n == ".git") {
            p.parent().map_or(d.clone(), |q| q.display().to_string())
        } else {
            d
        }
    });
    let branch = git(&["rev-parse", "--abbrev-ref", "HEAD"]).filter(|b| b != "HEAD");
    Context {
        repo,
        worktree,
        branch,
        cwd: std::env::current_dir()
            .ok()
            .map(|d| d.display().to_string()),
    }
}

/// A fresh operation id: `op-` and 26 base32 characters of OS randomness.
///
/// A convenience for callers that do not need to recover a lost response. A caller
/// that does must choose its id **before** the first attempt and pass it on every
/// retry, which this cannot do for it.
///
/// # Errors
/// If the OS random source fails.
pub fn new_op() -> Result<String, AppError> {
    let mut b = [0u8; 32];
    getrandom::fill(&mut b[..16])
        .map_err(|e| AppError::Usage(format!("no randomness for an operation id: {e}")))?;
    Ok(format!("op-{}", &b32_encode(&b)[..26]))
}

/// Milliseconds since the Unix epoch, by this machine's clock — the clock the fold
/// measures lapses against.
#[must_use]
pub fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// Everything a coordinating verb needs to know about a room at one moment.
pub struct Snapshot {
    /// This node's identity.
    pub me: Digest32,
    /// Every row, in the node's local order.
    pub rows: Vec<MessageRow>,
    /// Every row that parsed as an envelope.
    pub posted: Vec<Posted>,
    /// Folded claim state under this version.
    pub fold: Fold,
    /// The version table.
    pub table: VersionTable,
    /// When it was taken.
    pub now_millis: u64,
}

impl Snapshot {
    /// The operation index over every row.
    #[must_use]
    pub fn ops(&self) -> OpIndex {
        let mut idx = OpIndex::new();
        for p in &self.posted {
            idx.insert(p.entry_hash, p.author, p.created_millis, &p.envelope);
        }
        idx
    }

    /// Whether `session` of this node has announced itself with this version.
    #[must_use]
    pub fn announced(&self, session: &str) -> bool {
        self.posted.iter().any(|p| {
            p.author == self.me
                && p.envelope.kind == HELLO
                && p.envelope.from == session
                && version::stamp_of(&p.envelope, VERSION) == Stamp::Match
        })
    }
}

async fn ask(client: &mut IpcClient, req: &Request) -> Result<Frame, AppError> {
    match client.request(req).await {
        Ok(Frame::Error { reason }) => Err(AppError::Usage(reason)),
        Ok(f) => Ok(f),
        Err(e) => Err(AppError::Usage(e.to_string())),
    }
}

/// Every row of a room, in the node's local order.
///
/// # Errors
/// If the node cannot answer.
pub async fn read_all(
    client: &mut IpcClient,
    channel_id: Digest32,
    since: Option<Digest32>,
) -> Result<Vec<MessageRow>, AppError> {
    match ask(
        client,
        &Request::Read {
            channel_id,
            since,
            limit: 0,
        },
    )
    .await?
    {
        Frame::Rows { rows } => Ok(rows),
        other => Err(AppError::Usage(format!("unexpected reply: {other:?}"))),
    }
}

/// Parse rows into envelopes, keeping only those that are envelopes.
#[must_use]
pub fn posted_of(rows: &[MessageRow]) -> Vec<Posted> {
    rows.iter()
        .filter_map(|r| {
            Envelope::parse(&r.text).ok().map(|envelope| Posted {
                entry_hash: r.entry_hash,
                author: r.author,
                created_millis: r.created_millis,
                envelope,
            })
        })
        .collect()
}

/// Take a [`Snapshot`] of a room.
///
/// # Errors
/// If the node cannot answer, or does not say who it is.
pub async fn snapshot(client: &mut IpcClient, channel_id: Digest32) -> Result<Snapshot, AppError> {
    let me = client.me().ok_or_else(|| {
        AppError::Usage("the node did not say who it is; is its identity unlocked?".into())
    })?;
    let rows = read_all(client, channel_id, None).await?;
    let roster = match ask(client, &Request::Roster { channel_id }).await? {
        Frame::Members { members } => members,
        other => return Err(AppError::Usage(format!("unexpected reply: {other:?}"))),
    };
    let posted = posted_of(&rows);
    let now = now_millis();
    let fold = claim::fold(&posted, VERSION, now);
    let table = version::version_table(&posted, me, &roster, VERSION, now, &fold);
    Ok(Snapshot {
        me,
        rows,
        posted,
        fold,
        table,
        now_millis: now,
    })
}

/// The refusal, naming every incompatible worker, its version and the required one.
#[must_use]
pub fn refusal(room: &str, table: &VersionTable) -> AppError {
    let mut msg = format!(
        "work coordination refused in room {}",
        &room[..12.min(room.len())]
    );
    for p in table.mismatched() {
        msg.push_str(&format!(
            "\n  worker {} session {} runs vox {}; required {}",
            &b32_encode(&p.author)[..12],
            if p.session.is_empty() {
                "(none)"
            } else {
                &p.session
            },
            p.stamp.describe(&table.mine),
            table.mine
        ));
    }
    msg.push_str(
        "\n  every worker in a coordinating room must run the same vox version — upgrade \
         it, or remove it from the room",
    );
    AppError::Refused {
        code: EXIT_VERSION,
        message: msg,
    }
}

/// One message to post, before the fields every coordinating post carries are added.
#[derive(Debug, Clone, Default)]
pub struct Draft {
    /// The envelope type.
    pub kind: String,
    /// Addressees, by petname.
    pub to: Vec<String>,
    /// Whether it may interrupt an addressed session.
    pub urgent: bool,
    /// Reply-to entry.
    pub re: Option<String>,
    /// Thread root.
    pub thread: Option<String>,
    /// Human prose.
    pub body: String,
    /// Payload, without `op` or `vox`.
    pub data: serde_json::Map<String, serde_json::Value>,
}

/// How long a post waits to see its own entry in the node's view. The view skips a room while a
/// sync session holds it; a session that stalls is cut off by the 20s per-frame timeout
/// (`SYNC_FRAME_TIMEOUT`), so the bound sits above one such stall rather than at a guess about load.
const READBACK_PATIENCE: std::time::Duration = std::time::Duration::from_secs(30);
/// Between reads while waiting for it.
const READBACK_POLL: std::time::Duration = std::time::Duration::from_millis(50);

/// What a post turned out to be once the log was read back.
pub struct Posting {
    /// The entry that **is** the operation — the canonical first of its group.
    pub entry_hash: Digest32,
    /// The operation id.
    pub op: String,
    /// `posted`, or `already-posted` when an identical entry was found before posting.
    pub status: &'static str,
    /// The room as read back after posting.
    pub after: Snapshot,
}

/// Build the envelope a draft becomes.
fn envelope(draft: &Draft, session: &str, op: &str) -> Envelope {
    let mut env = Envelope::new(&draft.kind, &draft.body);
    env.from = session.to_owned();
    env.at = context();
    env.to.clone_from(&draft.to);
    env.urgent = draft.urgent;
    env.re.clone_from(&draft.re);
    env.thread.clone_from(&draft.thread);
    let mut data = draft.data.clone();
    data.insert(ops::OP_KEY.into(), op.into());
    data.insert(VOX_KEY.into(), VERSION.into());
    env.data = serde_json::Value::Object(data);
    env
}

/// Post a draft as operation `op`, **exactly once in effect**, and read it back.
///
/// 1. If this identity already posted `op`: the same content returns that entry
///    without posting again; different content is refused as a conflict.
/// 2. Otherwise post.
/// 3. Read the group back. If it is now a conflict — two concurrent attempts with
///    different content — that is reported, never success.
///
/// Step 1 only avoids a duplicate entry. What makes a retry *safe* is step 3 and the
/// rule that a conflicted operation has no effect anywhere (ADR-021 §6).
///
/// # Errors
/// A conflict ([`EXIT_CONFLICT`]), or a node that cannot be reached.
pub async fn post_once(
    client: &mut IpcClient,
    channel_id: Digest32,
    draft: &Draft,
    session: &str,
    op: &str,
    before: &Snapshot,
) -> Result<Posting, AppError> {
    let env = envelope(draft, session, op);
    let mine = ops::semantic(&env);
    let prior: Vec<&Posted> = before
        .posted
        .iter()
        .filter(|p| p.author == before.me && ops::op_of(&p.envelope) == Some(op))
        .collect();
    if let Some(p) = prior.first() {
        if prior.iter().all(|q| ops::semantic(&q.envelope) == mine) {
            let idx = before.ops();
            let first = match idx.verdict(p.author, &p.envelope, p.entry_hash) {
                Some(Verdict::Duplicate { of }) => of,
                _ => p.entry_hash,
            };
            let after = snapshot(client, channel_id).await?;
            return Ok(Posting {
                entry_hash: first,
                op: op.to_owned(),
                status: "already-posted",
                after,
            });
        }
        return Err(conflict(
            op,
            &prior.iter().map(|p| p.entry_hash).collect::<Vec<_>>(),
        ));
    }

    match ask(
        client,
        &Request::Post {
            channel_id,
            text: env.to_text(),
        },
    )
    .await?
    {
        Frame::Ok => {}
        other => return Err(AppError::Usage(format!("unexpected reply: {other:?}"))),
    }

    // **This post's own entry, by content — and waited for.** The node answers `Ok` once the
    // entry is appended, but the view a read is served from skips a room a sync session holds at
    // that moment (`view_of`), so the first read can be one publish behind. Two defects followed
    // from reading it once and matching by op alone: on a busy node a post that succeeded was
    // reported as a failure, and a racing post under the same op found the *other* post's entry,
    // judged that entry alone, and reported success for content it never saw — both racers
    // "succeeded". Matching the content this call sent means the verdict is only ever computed on
    // a log that holds this entry, and so every entry before it.
    let deadline = tokio::time::Instant::now() + READBACK_PATIENCE;
    let is_mine = |me, p: &Posted| {
        p.author == me && ops::op_of(&p.envelope) == Some(op) && ops::semantic(&p.envelope) == mine
    };
    let (after, entry) = loop {
        let after = snapshot(client, channel_id).await?;
        if let Some(entry) = after.posted.iter().find(|p| is_mine(after.me, p)).cloned() {
            break (after, entry);
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(AppError::Usage(format!(
                "posted, but the entry was not in the room's log after {}s — read it back with \
                 `vox room read --json` before retrying with the same --op",
                READBACK_PATIENCE.as_secs()
            )));
        }
        tokio::time::sleep(READBACK_POLL).await;
    };
    let idx = after.ops();
    match idx.verdict(entry.author, &entry.envelope, entry.entry_hash) {
        Some(Verdict::Conflict { group }) => Err(conflict(op, &group)),
        Some(Verdict::Duplicate { of }) => Ok(Posting {
            entry_hash: of,
            op: op.to_owned(),
            status: "posted",
            after,
        }),
        _ => Ok(Posting {
            entry_hash: entry.entry_hash,
            op: op.to_owned(),
            status: "posted",
            after,
        }),
    }
}

fn conflict(op: &str, group: &[Digest32]) -> AppError {
    let list: Vec<String> = group.iter().map(b32_encode).collect();
    AppError::Refused {
        code: EXIT_CONFLICT,
        message: format!(
            "operation {op} conflicts: this identity has already posted it with different \
             content, so it has NO effect anywhere (ADR-021 §6). Entries: {}. Use a new \
             --op for a different operation.",
            list.join(", ")
        ),
    }
}

/// Take part in work coordination: announce this session if it has not, then refuse
/// if any participant runs another version.
///
/// The announcement comes **first**. A worker that checked before announcing would,
/// after an upgrade of every worker, see only the others' old-version messages and
/// refuse — and so would every other worker, and nobody would ever announce. Posting
/// the stamped `hello` first means the second worker to act sees the first one's new
/// version.
///
/// # Errors
/// [`EXIT_VERSION`] naming every incompatible worker, or a node error.
pub async fn participate(
    client: &mut IpcClient,
    channel_id: Digest32,
    room: &str,
    session: &str,
) -> Result<Snapshot, AppError> {
    let mut snap = snapshot(client, channel_id).await?;
    if !snap.announced(session) {
        let hello = Draft {
            kind: HELLO.into(),
            body: format!("session {session} runs vox {VERSION}"),
            ..Draft::default()
        };
        let op = new_op()?;
        snap = post_once(client, channel_id, &hello, session, &op, &snap)
            .await?
            .after;
    }
    if snap.table.refused() {
        return Err(refusal(room, &snap.table));
    }
    Ok(snap)
}

/// Whether a draft or raw text is a claim-protocol operation, which only the
/// dedicated verbs may post.
#[must_use]
pub fn is_claim_type(kind: &str, data: &serde_json::Value) -> bool {
    let mut env = Envelope::new(kind, "");
    env.data = data.clone();
    claim::is_claim_protocol(&env)
}

/// The work reference a row carries, if any.
#[must_use]
pub fn work_of(env: &Envelope) -> Option<&str> {
    env.data.get(WORK_KEY).and_then(serde_json::Value::as_str)
}
