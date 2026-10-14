//! Ephemeral, bounded daemon projection of the room's canonical work protocol (ADR-033 WD).
//! No derived board is persisted. Each requested page reads the existing structured/notice
//! indexes and invokes the same claim fold used by coordination. A changed room refuses the
//! whole answer. Client continuations carry an existing display token, never a saved snapshot.

use super::{
    actor::NodeHandle,
    channel::history::{Filter, Query as HistoryQuery, Reply, Selection},
};
use crate::hash::Digest32;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use vox_agentcomms::{
    claim::{self, Owner, Posted, State},
    envelope::{self, Envelope},
    version,
};

/// Existing agreement/coordination capacity; over capacity is an explicit refusal, not a board.
const POSTS: usize = super::agreestream::MAX_LISTED;
const BYTES: usize = 64 * 1024 * 1024;
/// One displayed page, including JSON string escaping and metadata.
const PAGE_BYTES: usize = 96 * 1024;
const PAGE_ROWS: usize = 64;
const VERSION: &str = env!("CARGO_PKG_VERSION");
// Two transient folds across the daemon. Admission refuses rather than accumulating waiters.
static READERS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(2);
const CHANGED: &str = "the room's work board changed while reading; refresh and retry";
const TYPES: &[&str] = &[
    claim::CLAIM,
    claim::RELEASE,
    claim::HANDOFF,
    claim::RENEW,
    envelope::work::DECLINE,
    envelope::HELLO,
    envelope::BYE,
    envelope::work::FAILED,
    envelope::work::ASK,
    envelope::work::ASSIGN,
    envelope::work::BLOCKED,
    envelope::work::WORKING,
    envelope::work::RESULT,
];
const COORDINATION: &[&str] = &[
    claim::CLAIM,
    claim::RELEASE,
    claim::HANDOFF,
    claim::RENEW,
    envelope::work::DECLINE,
    envelope::HELLO,
    envelope::BYE,
    envelope::work::FAILED,
];

/// Which part of the one daemon fold to project.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Section {
    /// Canonical resource ownership and pending handoffs.
    Claims,
    /// The existing coordination version table.
    Participants,
    /// Canonical operation outcomes, with large conflict lists streamed in fragments.
    Violations,
    /// Current claims and outstanding addressed work, grouped by the responsible member/session.
    Work,
}
/// A page selection. `member` filters Work only; omitted means every responsible member.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Query {
    /// Selected projection.
    pub section: Section,
    /// Responsible signed identity, not a display name.
    pub member: Option<Digest32>,
    /// Continuation from this exact section/selection, or none for a fresh board.
    pub after: Option<Cursor>,
}
/// Stateless continuation. A changed room or elapsed lapse refuses it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cursor {
    /// Actor/room/display/roster identity of the fold.
    pub revision: Digest32,
    /// Clock at which the canonical fold was evaluated.
    pub now_millis: u64,
    /// First deadline at which this board must be recomputed.
    pub valid_until: u64,
    /// Selected projection, bound into continuation.
    pub section: Section,
    /// Selected responsible member, bound into continuation.
    pub member: Option<Digest32>,
    /// Next logical row (or violation fragment).
    pub offset: usize,
}
/// One outstanding relationship. These are signed room statements, not tracker status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Work {
    /// Identity responsible for this row (holder, handoff recipient, or addressed recipient).
    pub member: Digest32,
    /// Exact Session, or empty for a node-wide address.
    pub session: String,
    /// `claim`, `handoff`, `ask`, `assign`, or `blocked`.
    pub kind: String,
    /// Source message hash.
    pub entry: Digest32,
    /// Authenticated source author.
    pub author: Digest32,
    /// Source author's claimed Session.
    pub from: String,
    /// Resource named by the source, if any.
    pub resource: String,
    /// Source task/project tags, opaque to Vox.
    pub tags: Vec<String>,
    /// Source `data.work`, opaque plain text, never a tracker link.
    pub work: String,
    /// Source body, or the blocked reason when present.
    pub body: String,
}
/// Typed records from one shared fold. Violation fragments keep worst-case conflict output bounded.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Row {
    /// Existing board ownership semantics, unchanged.
    Claim {
        /// Resource key.
        resource: String,
        /// Canonical state.
        state: State,
    },
    /// Existing version participation semantics, unchanged.
    Participant(version::Participant),
    /// Consecutive UTF-8 JSON fragments of one existing `board/1` violation object.
    Violation {
        /// First fragment of this object.
        first: bool,
        /// Last fragment of this object.
        last: bool,
        /// Literal JSON bytes as text.
        text: String,
    },
    /// Outstanding work for one responsible identity/Session.
    Work(Work),
}
/// One bounded projection page. An absent continuation means this section is complete.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Page {
    /// Token to use for the next section too: set its section and offset to zero.
    pub cursor: Cursor,
    /// Reading node's authenticated identity.
    pub me: Digest32,
    /// Required coordination version.
    pub version: String,
    /// Whether the canonical version table refuses coordination.
    pub refused: bool,
    /// Whole-room readable entry count at this fold's position.
    pub entries: u64,
    /// Whole-room newest arrival, not greatest send timestamp.
    pub last: Option<Digest32>,
    /// Bounded selected records.
    pub rows: Vec<Row>,
    /// Continue here; do not call a partial page a complete board.
    pub next: Option<Cursor>,
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}
fn roster(handle: &NodeHandle, room: Digest32) -> Result<(Digest32, Vec<Digest32>), String> {
    handle.inspect_view(|view, _| {
        let me = view
            .identity
            .as_ref()
            .ok_or("the node is locked")?
            .fingerprint;
        let members = view
            .open_channels
            .iter()
            .find(|r| r.channel_id == room)
            .ok_or("room not open")?
            .members
            .clone();
        Ok((me, members))
    })
}
async fn token(handle: &NodeHandle, room: Digest32) -> Result<Digest32, String> {
    let revision = handle.room_display_revision(&room).await?;
    let (me, members) = roster(handle, room)?;
    let mut bytes = Vec::with_capacity(64 + members.len() * 32);
    bytes.extend_from_slice(&revision);
    bytes.extend_from_slice(&me);
    for member in members {
        bytes.extend_from_slice(&member);
    }
    Ok(crate::hash::sha256(&bytes))
}
/// Read one fresh daemon-folded page. Indexed input is capped before allocation; CPU folding
/// runs outside the node actor and has at most two simultaneous readers across the daemon.
///
/// # Errors
/// Current-authority/read refusal, changed selection, busy reader, or explicit finite capacity.
pub async fn page(handle: &NodeHandle, room: Digest32, query: Query) -> Result<Page, String> {
    let permit = READERS
        .try_acquire()
        .map_err(|_| "work board readers are busy; retry")?;
    let revision = token(handle, room).await?;
    let clock = now();
    if let Some(c) = &query.after {
        if c.revision != revision
            || c.section != query.section
            || c.member != query.member
            || clock >= c.valid_until
            || c.now_millis > clock
            || c.valid_until > c.now_millis.saturating_add(30_000)
            || c.offset > POSTS * 1024
        {
            return Err(CHANGED.into());
        }
    }
    let at = query.after.as_ref().map_or(clock, |c| c.now_millis);
    let (me, members) = roster(handle, room)?;
    let mut posted = Vec::new();
    let mut bytes = 0usize;
    let mut examined = 0usize;
    let mut after = None;
    let mut instance = None;
    loop {
        let filters = TYPES
            .iter()
            .map(|s| Filter::Type((*s).into()))
            .chain(std::iter::once(Filter::NoticeCandidates))
            .collect();
        let Reply::CursorPage(page) = handle
            .room_history(
                room,
                HistoryQuery::CursorPage {
                    after,
                    selection: Some(Selection::Any(filters)),
                    limit: 64,
                },
            )
            .await?
        else {
            return Err("unexpected work board input".into());
        };
        if instance.is_some_and(|i| i != page.instance) {
            return Err(CHANGED.into());
        }
        instance = Some(page.instance);
        for row in page.rows {
            let charge = row.text.len().saturating_add(std::mem::size_of::<Posted>());
            if examined == POSTS || bytes.saturating_add(charge) > BYTES {
                return Err(format!("coordination history exceeds this reader's capacity ({POSTS} posts / 64 MiB); no partial board or ownership verdict was produced. Saved messages remain available through paged room reads"));
            }
            // Invalid indexed bodies still consume examined work and the input budget.
            examined += 1;
            bytes += charge;
            if row.owed {
                continue;
            }
            if let Ok(envelope) = Envelope::parse(&row.text) {
                posted.push(Posted {
                    entry_hash: row.entry_hash,
                    author: row.author,
                    created_millis: row.created_millis,
                    envelope,
                });
            }
        }
        match page.next {
            Some(next) if after != Some(next) => after = Some(next),
            Some(_) => return Err("work board input did not advance".into()),
            None => break,
        }
    }
    let Reply::Count { n: entries, last } = handle
        .room_history(room, HistoryQuery::Count { since: None })
        .await?
    else {
        return Err("unexpected work board position".into());
    };
    if token(handle, room).await? != revision {
        return Err(CHANGED.into());
    }
    // The permit travels into blocking work: cancellation cannot admit an unbounded queue of folds.
    let result = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        project(posted, members, me, (entries, last), revision, at, query)
    })
    .await
    .map_err(|_| "work board reader stopped")??;
    if token(handle, room).await? != revision || now() >= result.cursor.valid_until {
        return Err(CHANGED.into());
    }
    Ok(result)
}

struct Output {
    skip: usize,
    seen: usize,
    bytes: usize,
    rows: Vec<Row>,
    more: bool,
}
impl Output {
    fn push(&mut self, row: Row) -> Result<(), String> {
        if self.more {
            return Ok(());
        }
        if self.seen < self.skip {
            self.seen += 1;
            return Ok(());
        }
        let bytes = serde_json::to_vec(&row).map_err(|e| e.to_string())?.len();
        if bytes > PAGE_BYTES {
            return Err("one work-board row exceeds the bounded page capacity".into());
        }
        if self.rows.len() == PAGE_ROWS || self.bytes + bytes > PAGE_BYTES {
            self.more = true;
        } else {
            self.seen += 1;
            self.bytes += bytes;
            self.rows.push(row);
        }
        Ok(())
    }
}
fn work(post: &Posted, member: Digest32, session: String, kind: &str) -> Work {
    let e = &post.envelope;
    Work {
        member,
        session,
        kind: kind.into(),
        entry: post.entry_hash,
        author: post.author,
        from: e.from.clone(),
        resource: e
            .data
            .get("resource")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .into(),
        tags: e.tags.clone(),
        work: e
            .data
            .get(envelope::WORK_KEY)
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .into(),
        body: if kind == envelope::work::BLOCKED {
            e.data
                .get("reason")
                .and_then(|v| v.as_str())
                .unwrap_or(&e.body)
                .into()
        } else {
            e.body.clone()
        },
    }
}
fn matched(q: &Query, row: &Work) -> bool {
    q.member.is_none_or(|m| m == row.member)
}
fn project(
    mut posts: Vec<Posted>,
    members: Vec<Digest32>,
    me: Digest32,
    position: (u64, Option<Digest32>),
    revision: Digest32,
    at: u64,
    query: Query,
) -> Result<Page, String> {
    let (entries, last) = position;
    posts.sort_by_key(|p| (p.created_millis, p.entry_hash));
    // Keep the established board's version participation input exactly as before. Work replies
    // are additional read evidence, not a new coordination/version authority model.
    let coordination: Vec<_> = posts
        .iter()
        .filter(|p| COORDINATION.contains(&p.envelope.kind.as_str()))
        .cloned()
        .collect();
    let fold = claim::fold(&coordination, VERSION, at);
    let table = version::version_table(&coordination, me, &members, VERSION, at, &fold);
    let by_hash: BTreeMap<_, _> = posts.iter().map(|p| (p.entry_hash, p)).collect();
    let until = fold
        .resources
        .values()
        .filter_map(State::lapses_at)
        .chain(std::iter::once(at.saturating_add(30_000)))
        .min()
        .unwrap_or(at.saturating_add(30_000));
    let mut out = Output {
        skip: query.after.as_ref().map_or(0, |c| c.offset),
        seen: 0,
        bytes: 0,
        rows: Vec::new(),
        more: false,
    };
    match query.section {
        Section::Claims => {
            for (resource, state) in &fold.resources {
                out.push(Row::Claim {
                    resource: resource.clone(),
                    state: state.clone(),
                })?;
                if out.more {
                    break;
                }
            }
        }
        Section::Participants => {
            for p in &table.participants {
                out.push(Row::Participant(p.clone()))?;
                if out.more {
                    break;
                }
            }
        }
        Section::Violations => {
            for (hash, outcome) in &fold.outcomes {
                if matches!(outcome, claim::Outcome::Applied | claim::Outcome::Lost) {
                    continue;
                }
                let p = by_hash.get(hash);
                // Only one violation is encoded at a time; even a maximal conflict is bounded by
                // POSTS, and fragments avoid a giant IPC frame or quadratic retained JSON array.
                let object = serde_json::json!({ "entry_hash": claim::b32(hash),
                "author": p.map(|p| claim::b32(&p.author)), "session": p.map(|p| &p.envelope.from),
                "type": p.map(|p| &p.envelope.kind), "outcome": outcome_json(outcome) })
                .to_string();
                let mut start = 0;
                while start < object.len() {
                    let mut end = (start + 16 * 1024).min(object.len());
                    while !object.is_char_boundary(end) {
                        end -= 1;
                    }
                    out.push(Row::Violation {
                        first: start == 0,
                        last: end == object.len(),
                        text: object[start..end].into(),
                    })?;
                    start = end;
                    if out.more {
                        break;
                    }
                }
                if out.more {
                    break;
                }
            }
        }
        Section::Work => {
            // Reply closure uses the signed responder and exact addressed Session, not a name
            // or a reply from an unrelated room participant. Partial multi-target asks stay open.
            let mut replies: BTreeMap<Digest32, BTreeSet<Owner>> = BTreeMap::new();
            let mut blocked: BTreeMap<(Owner, String), &Posted> = BTreeMap::new();
            for p in &posts {
                let e = &p.envelope;
                if let Some(parent) =
                    e.re.as_ref()
                        .and_then(|s| super::link::b32_decode(s, "reply").ok())
                {
                    // Exact re identity binds the answer even when the recipient's clock
                    // sorts its reply before the ask. Sender timestamps are not causality.
                    if by_hash.contains_key(&parent) {
                        replies.entry(parent).or_default().insert(Owner {
                            author: p.author,
                            session: e.from.clone(),
                        });
                    }
                }
                let owner = Owner {
                    author: p.author,
                    session: e.from.clone(),
                };
                let key = e
                    .data
                    .get("resource")
                    .or_else(|| e.data.get(envelope::WORK_KEY))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_owned();
                if e.kind == envelope::work::BLOCKED {
                    blocked.insert((owner, key), p);
                } else if [
                    envelope::work::WORKING,
                    envelope::work::RESULT,
                    envelope::work::FAILED,
                    claim::RELEASE,
                ]
                .contains(&e.kind.as_str())
                {
                    blocked.remove(&(owner, key));
                }
            }
            for state in fold.resources.values() {
                let (entry, member, session, kind) = match state {
                    State::Held {
                        owner, acquisition, ..
                    } => (acquisition, owner.author, owner.session.clone(), "claim"),
                    State::Pending {
                        to_fp,
                        to_session,
                        handoff,
                        ..
                    } => (
                        handoff,
                        *to_fp,
                        to_session.clone().unwrap_or_default(),
                        "handoff",
                    ),
                };
                if let Some(p) = by_hash.get(entry) {
                    let row = work(p, member, session, kind);
                    if matched(&query, &row) {
                        out.push(Row::Work(row))?;
                    }
                }
            }
            for p in &posts {
                if ![envelope::work::ASK, envelope::work::ASSIGN]
                    .contains(&p.envelope.kind.as_str())
                {
                    continue;
                }
                let mut targets = BTreeSet::new();
                for target in &p.envelope.to {
                    let (fp, session) = envelope::addressee(target);
                    let Ok(member) = super::link::b32_decode(fp, "addressee") else {
                        continue;
                    };
                    if !targets.insert((member, session)) {
                        continue;
                    }
                    if replies.get(&p.entry_hash).is_some_and(|rs| {
                        rs.iter()
                            .any(|r| r.author == member && session.is_none_or(|s| r.session == s))
                    }) {
                        continue;
                    }
                    let row = work(p, member, session.unwrap_or("").into(), &p.envelope.kind);
                    if matched(&query, &row) {
                        out.push(Row::Work(row))?;
                    }
                }
            }
            for ((owner, _), p) in blocked {
                let row = work(p, owner.author, owner.session, "blocked");
                if matched(&query, &row) {
                    out.push(Row::Work(row))?;
                }
            }
        }
    }
    let cursor = Cursor {
        revision,
        now_millis: at,
        valid_until: until,
        section: query.section,
        member: query.member,
        offset: 0,
    };
    let next = out.more.then(|| Cursor {
        offset: out.seen,
        ..cursor.clone()
    });
    Ok(Page {
        cursor,
        me,
        version: VERSION.into(),
        refused: table.refused(),
        entries,
        last,
        rows: out.rows,
        next,
    })
}
fn outcome_json(outcome: &claim::Outcome) -> serde_json::Value {
    use claim::Outcome;
    match outcome {
        Outcome::Applied => "applied".into(),
        Outcome::Lost => "lost".into(),
        Outcome::NoEffect(s) => serde_json::json!({"no_effect":s}),
        Outcome::Invalid(s) => serde_json::json!({"invalid":s}),
        Outcome::OtherVersion(s) => serde_json::json!({"other_version":s.token()}),
        Outcome::Duplicate { of } => serde_json::json!({"duplicate_of":claim::b32(of)}),
        Outcome::Conflict { group } => {
            serde_json::json!({"conflict":group.iter().map(claim::b32).collect::<Vec<_>>()})
        }
    }
}
