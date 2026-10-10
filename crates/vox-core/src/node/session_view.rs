//! **One Session, read the way a member with drive reads it** (ADR-029 SC-1, CL-1; #540, #545,
//! #554), for `vox room session`, the TUI and the app alike.
//!
//! The words are the TUI's and the app's (tui2's steps and words for #553), so a person reading a
//! Session in a terminal, the TUI or the app reads the same lines. One line per activity: a tool
//! call with what it returned, the reply, the end of each turn, the prompt typed at the terminal
//! or in Vox, approvals and questions with who answered them, files either way. Each line keeps
//! its entry's full input and output for Details, a split entry joined whole.

use std::collections::BTreeMap;

use serde_json::Value;
use vox_agentcomms::activity::one_line;

use crate::hash::Digest32;
use crate::node::drive::SessionRow;
use crate::node::sessions::SessionRow as Session;

/// One activity as the reader sees it: its line, and what Details shows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Line {
    /// The entry that gave it its place: the first part's, for a split entry.
    pub id: Digest32,
    /// That entry's send time, milliseconds since the Unix epoch.
    pub at_millis: u64,
    /// The session node's numbering of it.
    pub seq: u64,
    /// The kind it was drawn from.
    pub kind: String,
    /// The one line.
    pub text: String,
    /// The full input and output, labelled, in order.
    pub details: Vec<(String, String)>,
    /// The harness's id for the call or request it is about (`ref`): what `--approve`,
    /// `--reject` and `--answer` name. Empty for an entry about none.
    pub reference: String,
    /// What it waits for from a member with drive: an approval or a question still open and
    /// answerable from Vox, or `None`.
    pub waiting: Option<Waiting>,
    /// A file to or from the session.
    pub file: Option<FileLine>,
    /// An approval or a question the session asked.
    pub request: Option<RequestLine>,
}

impl Line {
    /// The request's `ref` when this line is an approval or a question still waiting for an
    /// answer from a member with drive (not resolved, not expired, answerable from Vox); `None`
    /// otherwise. What the TUI offers approve, reject and answer on, and what counts a Session
    /// under "needs you" (ADR-029 CL-2).
    #[must_use]
    pub fn open(&self) -> Option<&str> {
        self.waiting
            .is_some()
            .then_some(self.reference.as_str())
            .filter(|r| !r.is_empty())
    }
}

/// The refs of the requests in one Session's `rows` (its entries, in order) still waiting for an
/// answer: the same rule [`lines`] words them by.
#[must_use]
pub fn waiting(rows: &[SessionRow]) -> Vec<String> {
    lines(rows, "", &Nameless)
        .iter()
        .filter_map(|l| l.open().map(str::to_owned))
        .collect()
}

/// Names for a reading that shows none.
struct Nameless;

impl Names for Nameless {
    fn alias(&self, _: &Digest32) -> String {
        String::new()
    }
    fn is_me(&self, _: &str) -> bool {
        false
    }
    fn alias_b32(&self, _: &str) -> String {
        String::new()
    }
}

/// What an open request waits for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Waiting {
    /// Approve or reject.
    Approval,
    /// An answer.
    Question,
}

/// A file to or from a session, as its entry says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileLine {
    /// Its name.
    pub name: String,
    /// Its size in bytes.
    pub size: u64,
    /// Its SHA-256, hex, when the entry gives it.
    pub sha256: String,
    /// Whether the session sent it, rather than received it.
    pub from_session: bool,
}

/// An approval or a question a session asked, and where it stands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestLine {
    /// What a driver's approve, reject or answer names.
    pub reference: String,
    /// A question, rather than an approval.
    pub is_question: bool,
    /// A question's parts, each its text and its options' labels; none for an approval.
    pub questions: Vec<(String, Vec<String>)>,
    /// `None` while it is open and may be answered from Vox; otherwise what became of it, in the
    /// line's own words ("approved here", "not answerable from Vox: …").
    pub state: Option<String>,
}

/// How the reader names a node: by its alias, or as itself.
pub trait Names {
    /// The node's alias as this reader knows it.
    fn alias(&self, fp: &Digest32) -> String;
    /// Whether `by` (a whole fingerprint in base32) is the reader.
    fn is_me(&self, by: &str) -> bool;
    /// The alias of the node `by` names (a whole fingerprint in base32), or `by` cut short.
    fn alias_b32(&self, by: &str) -> String;
}

/// An entry's author, carrying where its first part is: compared by the author alone, so the
/// parts of a split entry join as one.
#[derive(Clone, Copy, Debug)]
struct At {
    author: Digest32,
    id: Digest32,
    millis: u64,
}

impl PartialEq for At {
    fn eq(&self, other: &Self) -> bool {
        self.author == other.author
    }
}
impl Eq for At {}
impl PartialOrd for At {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for At {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.author.cmp(&other.author)
    }
}

type Body = vox_agentcomms::activity::Entry<At>;

/// `rows`, one Session's entries in this node's order, joined: the parts of a split entry become
/// one entry, whole.
fn joined(rows: &[SessionRow]) -> Vec<Body> {
    vox_agentcomms::activity::join(rows.iter().map(|r| {
        (
            At {
                author: r.author,
                id: r.entry_hash,
                millis: r.created_millis,
            },
            r.body.as_str(),
        )
    }))
}

/// A size as a person reads it.
#[allow(clippy::cast_precision_loss)]
fn size(bytes: u64) -> String {
    match bytes {
        b if b < 1024 => format!("{b} bytes"),
        b if b < 1024 * 1024 => format!("{} KB", b / 1024),
        b => format!("{:.1} MB", b as f64 / (1024.0 * 1024.0)),
    }
}

/// A question's options, numbered: "1. red  2. blue".
fn options(q: &Value) -> String {
    q.get("options")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .enumerate()
        .map(|(i, o)| {
            format!(
                "{}. {}",
                i + 1,
                o.get("label").and_then(Value::as_str).unwrap_or_default()
            )
        })
        .collect::<Vec<_>>()
        .join("  ")
}

/// Answers as one line: "colour: blue; size: large", or the one answer alone.
fn answers_line(a: &Value) -> String {
    let Some(m) = a.as_object() else {
        return String::new();
    };
    if m.len() == 1 {
        return m.values().next().map(value_text).unwrap_or_default();
    }
    m.iter()
        .map(|(q, v)| format!("{q}: {}", value_text(v)))
        .collect::<Vec<_>>()
        .join("; ")
}

fn value_text(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Array(a) => a.iter().map(value_text).collect::<Vec<_>>().join(", "),
        other => other.to_string(),
    }
}

/// What a request's outcome reads, from the reader's side (DR-4): "approved here", "answered in
/// the terminal: rejected", "answered in Vox by ann: blue", "expired: …".
fn outcome_words(resolved: &Body, names: &dyn Names) -> String {
    let outcome = resolved.str("outcome");
    let what = match outcome {
        "allowed" => "approved".to_owned(),
        "denied" => "rejected".to_owned(),
        "answered" => resolved
            .fields
            .get("answers")
            .map(answers_line)
            .unwrap_or_default(),
        "cancelled" => "cancelled".to_owned(),
        _ => return "expired: the session moved on before an answer".to_owned(),
    };
    let by = resolved.str("by");
    if by == "terminal" || by.is_empty() {
        format!("answered in the terminal: {what}")
    } else if names.is_me(by) {
        match outcome {
            "allowed" | "denied" => format!("{what} here"),
            _ => format!("answered here: {what}"),
        }
    } else {
        format!("answered in Vox by {}: {what}", names.alias_b32(by))
    }
}

/// Where a request stands: `None` while it is open and may be answered from Vox.
fn request_state(
    b: &Body,
    resolved: &BTreeMap<String, usize>,
    bodies: &[Body],
    names: &dyn Names,
) -> Option<String> {
    if b.fields.get("answerable").and_then(Value::as_bool) == Some(false) {
        return Some(format!("not answerable from Vox: {}", b.str("why")));
    }
    resolved
        .get(b.reference())
        .map(|&i| outcome_words(&bodies[i], names))
}

/// One Session's lines, in order. `label` names the Session, as `vox_agentcomms::session_label`
/// gives it.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn lines(rows: &[SessionRow], label: &str, names: &dyn Names) -> Vec<Line> {
    let bodies = joined(rows);
    // What settles an earlier line: a tool call's result, a request's resolution.
    let mut done: BTreeMap<String, usize> = BTreeMap::new();
    let mut resolved: BTreeMap<String, usize> = BTreeMap::new();
    // A drive's results, by the drive's tag (`of` on the result, `id` on the drive), in order.
    let mut results: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    let mut driven: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    // Calls that asked first: their request's line names them, so an unanswered or refused call
    // is not shown twice.
    let mut asked: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for (i, b) in bodies.iter().enumerate() {
        if matches!(b.kind(), "approval" | "question") {
            asked.insert(b.reference().to_owned());
        }
        match b.kind() {
            "tool-done" => {
                done.insert(b.reference().to_owned(), i);
            }
            "resolved" => {
                resolved.insert(b.reference().to_owned(), i);
            }
            "drive" if !b.str("id").is_empty() => {
                driven.insert(b.str("id").to_owned());
            }
            "drive-result" if !b.str("of").is_empty() => {
                results.entry(b.str("of").to_owned()).or_default().push(i);
            }
            _ => {}
        }
    }
    let mut out = Vec::new();
    for b in &bodies {
        let seq = b.fields.get("seq").and_then(Value::as_u64).unwrap_or(0);
        let prefix = match b.str("agent") {
            "" => String::new(),
            t => format!("[{t}] "),
        };
        let mut details: Vec<(String, String)> = Vec::new();
        let mut file = None;
        let mut request = None;
        let mut waiting = None;
        let text = match b.kind() {
            "user" => {
                details.push(("typed".into(), b.str("text").to_owned()));
                format!("typed at the terminal: {}", one_line(b.str("text")))
            }
            "tool" if asked.contains(b.reference()) && !done.contains_key(b.reference()) => {
                continue
            }
            "tool" => {
                details.push(("input".into(), b.str("input").to_owned()));
                let head = format!("{}: {}", b.str("tool"), b.str("summary"));
                match done.get(b.reference()).map(|&i| &bodies[i]) {
                    None => format!("{head} …"),
                    Some(d) => {
                        details.push(("output".into(), d.str("output").to_owned()));
                        let ok = d.fields.get("ok").and_then(Value::as_bool) != Some(false);
                        let interrupted =
                            d.fields.get("interrupted").and_then(Value::as_bool) == Some(true);
                        if interrupted {
                            format!("{head} ✗ interrupted")
                        } else if ok {
                            format!("{head} → {}", d.str("summary"))
                        } else {
                            format!("{head} ✗ {}", d.str("summary"))
                        }
                    }
                }
            }
            // Drawn on its call's line.
            "tool-done" | "resolved" => continue,
            "reply" => {
                details.push(("reply".into(), b.str("text").to_owned()));
                format!("reply: {}", one_line(b.str("text")))
            }
            "turn-end" => "— turn ended —".to_owned(),
            "approval" => {
                details.push(("input".into(), b.str("input").to_owned()));
                let head = format!("{}: {}", b.str("tool"), b.str("summary"));
                let state = request_state(b, &resolved, &bodies, names);
                request = Some(RequestLine {
                    reference: b.reference().to_owned(),
                    is_question: false,
                    questions: Vec::new(),
                    state: state.clone(),
                });
                match state {
                    None => {
                        waiting = Some(Waiting::Approval);
                        format!("{head} — approve or reject?")
                    }
                    Some(s) => format!("{head} — {s}"),
                }
            }
            "question" => {
                let qs: Vec<Value> = b
                    .fields
                    .get("questions")
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default();
                let mut parts = Vec::new();
                for q in &qs {
                    let text = q
                        .get("text")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_owned();
                    let mut d = text.clone();
                    let mut labels = Vec::new();
                    for o in q
                        .get("options")
                        .and_then(Value::as_array)
                        .into_iter()
                        .flatten()
                    {
                        let label = o.get("label").and_then(Value::as_str).unwrap_or_default();
                        labels.push(label.to_owned());
                        d.push_str(&format!(
                            "\n- {label}{}",
                            o.get("description")
                                .and_then(Value::as_str)
                                .map(|s| format!(": {s}"))
                                .unwrap_or_default()
                        ));
                    }
                    details.push(("question".into(), d));
                    parts.push((text, labels));
                }
                let head = qs
                    .iter()
                    .map(|q| {
                        format!(
                            "{} — {}",
                            one_line(q.get("text").and_then(Value::as_str).unwrap_or_default()),
                            options(q)
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(" | ");
                let head = format!("question: {head}");
                let state = request_state(b, &resolved, &bodies, names);
                request = Some(RequestLine {
                    reference: b.reference().to_owned(),
                    is_question: true,
                    questions: parts,
                    state: state.clone(),
                });
                match state {
                    None => {
                        waiting = Some(Waiting::Question);
                        head
                    }
                    Some(s) => format!("{head} — {s}"),
                }
            }
            "file" => {
                let bytes = b.fields.get("size").and_then(Value::as_u64).unwrap_or(0);
                let what = format!("{} ({})", b.str("name"), size(bytes));
                let to_session = b.str("dir") == "in";
                file = Some(FileLine {
                    name: b.str("name").to_owned(),
                    size: bytes,
                    sha256: b.str("sha256").to_owned(),
                    from_session: !to_session,
                });
                if to_session {
                    // Written by the session's node once the file has landed (#546).
                    let from = match b.str("by") {
                        "" => String::new(),
                        by => format!(" from {}", names.alias_b32(by)),
                    };
                    match b.str("path") {
                        "" => format!("file to {label}: {what}{from}"),
                        path => format!("file to {label}: {what}{from}, at {path}"),
                    }
                } else {
                    match b.str("note").trim() {
                        "" => format!("file from {label}: {what}"),
                        note => format!("file from {label}: {what} — {}", one_line(note)),
                    }
                }
            }
            "drive" => {
                // The session's node writes what a driver did, naming the driver it admitted on
                // the drive stream: the driver cannot seal under the session's key.
                let by = match b.str("by") {
                    "" => names.alias(&b.author.author),
                    by => names.alias_b32(by),
                };
                match b.str("action") {
                    "text" => {
                        details.push(("typed".into(), b.str("text").to_owned()));
                        format!("typed in Vox by {by}: {}", one_line(b.str("text")))
                    }
                    "interrupt" => format!("interrupt sent by {by}"),
                    "stop" => format!("stop sent by {by}"),
                    // As typed, with its arguments (`/rename frogs`): the command alone hid what
                    // was sent. A record written before "text" was kept says its command.
                    "slash" => {
                        let typed = match b.str("text").trim() {
                            "" => format!("/{}", b.str("cmd").trim_start_matches('/')),
                            t => one_line(t),
                        };
                        details.push(("typed".into(), b.str("text").to_owned()));
                        format!("{typed} sent by {by}")
                    }
                    "file" => {
                        if !b.str("note").trim().is_empty() {
                            details.push(("note".into(), b.str("note").to_owned()));
                        }
                        let mut line = format!(
                            "file sent in by {by}: {} ({})",
                            b.str("name"),
                            size(b.fields.get("size").and_then(Value::as_u64).unwrap_or(0))
                        );
                        // What came of it, in order: each result names this drive's tag as `of`.
                        for r in results.get(b.str("id")).into_iter().flatten() {
                            let r = &bodies[*r];
                            if r.fields.get("ok").and_then(Value::as_bool) == Some(true) {
                                line.push_str(&format!(" — {}", r.str("said")));
                            } else {
                                line.push_str(&format!(" ✗ {}", r.str("why")));
                            }
                        }
                        line
                    }
                    // An answer shows on its request's line.
                    _ => continue,
                }
            }
            // A line Vox itself says in the Session.
            "notice" => format!("Vox: {}", one_line(b.str("text"))),
            "drive-result" => {
                // A result paired with its drive's tag is drawn on that drive's line.
                if !b.str("of").is_empty() && driven.contains(b.str("of")) {
                    continue;
                }
                if b.fields.get("ok").and_then(Value::as_bool) == Some(true) {
                    continue;
                }
                format!("not delivered to {label}: {}", b.str("why"))
            }
            _ => "(unknown activity)".to_owned(),
        };
        out.push(Line {
            id: b.author.id,
            at_millis: b.author.millis,
            seq,
            kind: b.kind().to_owned(),
            text: format!("{prefix}{text}"),
            details,
            reference: b.reference().to_owned(),
            waiting,
            file,
            request,
        });
    }
    out
}

/// A line's Details as the terminal prints them under it: each labelled part, indented. Empty when
/// the line is all there is.
#[must_use]
pub fn details_text(line: &Line) -> String {
    let mut s = String::new();
    for (label, body) in &line.details {
        s.push_str(&format!("    {label}:\n"));
        for l in body.lines() {
            s.push_str("      ");
            s.push_str(l);
            s.push('\n');
        }
    }
    s
}

/// `lines` as the terminal prints them; with `details`, each entry's full input and output
/// indented under its line.
///
/// `answer_with` is the command that drives this Session (`vox room session ROOM SESSION`): each
/// request still waiting for an answer is followed by the command that gives it, with its ref.
#[must_use]
pub fn render(lines: &[Line], details: bool, answer_with: &str) -> String {
    let mut s = String::new();
    for l in lines {
        s.push_str(&l.text);
        s.push('\n');
        // **A request waiting for an answer names how to give it** (DR-1.4, DR-1.5): the ref
        // `--approve`, `--reject` and `--answer` take, whole, so a person can copy it.
        match (l.waiting, l.reference.as_str()) {
            (_, "") | (None, _) => {}
            (Some(Waiting::Approval), r) => s.push_str(&format!(
                "    waiting: {answer_with} --approve {r}, or --reject {r}\n"
            )),
            (Some(Waiting::Question), r) => s.push_str(&format!(
                "    waiting: {answer_with} --answer {r} \"<question>=<answer>\"\n"
            )),
        }
        if details {
            s.push_str(&details_text(l));
        }
    }
    s
}

/// The entries of the Session `id` of `node` among a room's Session entries, in the order they were
/// written: the session node's own, and the drive entries that name the session; each author's
/// send time, and within one moment the session node's own numbering (a split entry's parts share
/// a millisecond).
#[must_use]
pub fn of_session(rows: Vec<SessionRow>, id: &str, node: &Digest32) -> Vec<SessionRow> {
    let field = |r: &SessionRow, k: &str| {
        serde_json::from_str::<Value>(&r.body)
            .ok()
            .and_then(|v| v.get(k).cloned())
    };
    let mut mine: Vec<SessionRow> = rows
        .into_iter()
        .filter(|r| {
            r.session_id == id
                && (r.author == *node
                    || field(r, "kind").as_ref().and_then(Value::as_str) == Some("drive"))
        })
        .collect();
    mine.sort_by_key(|r| {
        (
            r.created_millis,
            field(r, "seq")
                .as_ref()
                .and_then(Value::as_u64)
                .unwrap_or(0),
        )
    });
    mine
}

/// One Session as this node reads it: which it is, where it stands, and its lines.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Read {
    /// The harness's session id.
    pub id: String,
    /// The session's node.
    pub node: Digest32,
    /// Its label (ADR-029 SE-3).
    pub label: String,
    /// "open", "ended", or "opening not received yet".
    pub state: &'static str,
    /// Its lines, oldest first; none when this node may not see inside it.
    pub lines: Vec<Line>,
    /// When this node may not see inside it: whose trust it lacks, as a sentence (SC-3).
    pub hidden: Option<String>,
}

/// What a Session's state reads when its opening, a room message, has not reached this node,
/// though entries it can open have (the two travel apart, SC-2).
pub const OPENING_NOT_RECEIVED: &str = "opening not received yet";

/// The Session `typed` names in a room (ADR-029 SC-1, SE-5), read from the room's Sessions and the
/// Session entries this node holds; only `node`'s when it is given. An ended Session stays
/// readable. A Session whose opening has not arrived is read from its entries alone, named by its
/// node and whole id, or 8 characters of it or more, never guessed.
///
/// `label_of` labels a Session as the reader does; `names` names nodes as the reader does.
///
/// # Errors
/// The refusal [`crate::node::sessions::resolve`] gives, when no one Session answers.
pub fn read(
    sessions: &[Session],
    rows: Vec<SessionRow>,
    typed: &str,
    node: Option<&Digest32>,
    label_of: &dyn Fn(&Session) -> String,
    names: &dyn Names,
) -> Result<Read, String> {
    let kind = |r: &SessionRow| {
        serde_json::from_str::<Value>(&r.body)
            .ok()
            .and_then(|v| v.get("kind").and_then(Value::as_str).map(str::to_owned))
            .unwrap_or_default()
    };
    let candidates: Vec<Session> = sessions
        .iter()
        .filter(|s| node.is_none_or(|n| s.node == *n))
        .cloned()
        .collect();
    let (id, node, label, state, can_drive) =
        match crate::node::sessions::resolve(&candidates, typed, true, |s| label_of(s)) {
            Ok(row) => (
                row.id.clone(),
                row.node,
                label_of(row),
                if row.open { "open" } else { "ended" },
                row.can_drive,
            ),
            Err(refused) => {
                let typed = typed.trim();
                let mut found: Vec<(&str, Digest32)> = rows
                    .iter()
                    .filter(|r| kind(r) != "drive")
                    .filter(|r| node.is_none_or(|n| r.author == *n))
                    .filter(|r| {
                        r.session_id == typed
                            || (typed.chars().count() >= 8 && r.session_id.starts_with(typed))
                    })
                    .map(|r| (r.session_id.as_str(), r.author))
                    .collect();
                found.sort_unstable();
                found.dedup();
                let [(id, node)] = found.as_slice() else {
                    return Err(refused);
                };
                let label = vox_agentcomms::envelope::session_label(&names.alias(node), None, id);
                ((*id).to_owned(), *node, label, OPENING_NOT_RECEIVED, true)
            }
        };
    let mine = of_session(rows, &id, &node);
    // A member without drive holds the entries but cannot open them (SC-2, SC-3): it is told whose
    // trust it lacks, never shown an empty Session.
    if !can_drive && mine.iter().all(|r| r.author != node) {
        return Ok(Read {
            hidden: Some(format!(
                "Only members {} trusts with drive see inside this Session.",
                names.alias(&node)
            )),
            id,
            node,
            label,
            state,
            lines: Vec::new(),
        });
    }
    let lines = lines(&mine, &label, names);
    Ok(Read {
        id,
        node,
        label,
        state,
        lines,
        hidden: None,
    })
}

/// How many of a Session's requests are open and may be answered from Vox: what waits on a member
/// with drive (ADR-029 CL-2).
#[must_use]
pub fn pending(read: &Read) -> u32 {
    let open = read
        .lines
        .iter()
        .filter(|l| l.request.as_ref().is_some_and(|r| r.state.is_none()))
        .count();
    u32::try_from(open).unwrap_or(u32::MAX)
}
