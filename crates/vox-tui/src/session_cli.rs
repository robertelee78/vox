//! `vox room session ROOM <session>` — **one Session, read the way a member with drive reads it**
//! (ADR-029 SC-1, CL-1; #540, #545).
//!
//! The words are the TUI's and the app's (tui2's steps and words for #553), so a person reading a
//! Session in a terminal, the TUI or the app reads the same lines. One line per activity: a tool
//! call with what it returned, the reply, the end of each turn, the prompt typed at the terminal
//! or in Vox, approvals and questions with who answered them, files either way. `--details` adds
//! each entry's full input and output under its line, a split entry joined whole.

use std::collections::BTreeMap;

use serde_json::Value;
use vox_core::hash::Digest32;
use vox_core::node::drive::SessionRow;

/// One activity as the reader sees it: its line, and what Details shows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Line {
    /// The entry that gave it its place.
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
}

/// What an open request waits for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Waiting {
    /// Approve or reject.
    Approval,
    /// An answer.
    Question,
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

type Body = vox_agentcomms::activity::Entry<Digest32>;

/// `rows`, one Session's entries in this node's order, joined: the parts of a split entry become
/// one entry, whole.
fn joined(rows: &[SessionRow]) -> Vec<Body> {
    vox_agentcomms::activity::join(rows.iter().map(|r| (r.author, r.body.as_str())))
}

fn one_line(s: &str) -> String {
    crate::session_mirror::one_line(s)
}

/// A size as a person reads it.
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

/// One Session's lines, in order. `label` names the Session, as `vox_agentcomms::session_label`
/// gives it.
#[must_use]
pub fn lines(rows: &[SessionRow], label: &str, names: &dyn Names) -> Vec<Line> {
    let bodies = joined(rows);
    // What settles an earlier line: a tool call's result, a request's resolution.
    let mut done: BTreeMap<String, usize> = BTreeMap::new();
    let mut resolved: BTreeMap<String, usize> = BTreeMap::new();
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
                if b.fields.get("answerable").and_then(Value::as_bool) == Some(false) {
                    format!("{head} — not answerable from Vox: {}", b.str("why"))
                } else {
                    match resolved.get(b.reference()).map(|&i| &bodies[i]) {
                        None => {
                            waiting = Some(Waiting::Approval);
                            format!("{head} — approve or reject?")
                        }
                        Some(r) => format!("{head} — {}", outcome_words(r, names)),
                    }
                }
            }
            "question" => {
                let qs: Vec<Value> = b
                    .fields
                    .get("questions")
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default();
                for q in &qs {
                    let mut d = q
                        .get("text")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_owned();
                    for o in q
                        .get("options")
                        .and_then(Value::as_array)
                        .into_iter()
                        .flatten()
                    {
                        d.push_str(&format!(
                            "\n- {}{}",
                            o.get("label").and_then(Value::as_str).unwrap_or_default(),
                            o.get("description")
                                .and_then(Value::as_str)
                                .map(|s| format!(": {s}"))
                                .unwrap_or_default()
                        ));
                    }
                    details.push(("question".into(), d));
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
                if b.fields.get("answerable").and_then(Value::as_bool) == Some(false) {
                    format!("{head} — not answerable from Vox: {}", b.str("why"))
                } else {
                    match resolved.get(b.reference()).map(|&i| &bodies[i]) {
                        None => {
                            waiting = Some(Waiting::Question);
                            head
                        }
                        Some(r) => format!("{head} — {}", outcome_words(r, names)),
                    }
                }
            }
            "file" => {
                let what = format!(
                    "{} ({})",
                    b.str("name"),
                    size(b.fields.get("size").and_then(Value::as_u64).unwrap_or(0))
                );
                if b.str("dir") == "in" {
                    format!("file to {label}: {what}")
                } else {
                    format!("file from {label}: {what}")
                }
            }
            "drive" => {
                // The session's node writes what a driver did, naming the driver it admitted on
                // the drive stream: the driver cannot seal under the session's key.
                let by = match b.str("by") {
                    "" => names.alias(&b.author),
                    by => names.alias_b32(by),
                };
                match b.str("action") {
                    "text" => {
                        details.push(("typed".into(), b.str("text").to_owned()));
                        format!("typed in Vox by {by}: {}", one_line(b.str("text")))
                    }
                    "interrupt" => format!("interrupt sent by {by}"),
                    "stop" => format!("stop sent by {by}"),
                    "slash" => format!("/{} sent by {by}", b.str("cmd").trim_start_matches('/')),
                    // An answer shows on its request's line.
                    _ => continue,
                }
            }
            // A line Vox itself says in the Session.
            "notice" => format!("Vox: {}", one_line(b.str("text"))),
            "drive-result" => {
                if b.fields.get("ok").and_then(Value::as_bool) == Some(true) {
                    continue;
                }
                format!("not delivered to {label}: {}", b.str("why"))
            }
            _ => "(unknown activity)".to_owned(),
        };
        out.push(Line {
            seq,
            kind: b.kind().to_owned(),
            text: format!("{prefix}{text}"),
            details,
            reference: b.reference().to_owned(),
            waiting,
        });
    }
    out
}

/// `lines` as the terminal prints them; with `details`, each entry's full input and output
/// indented under its line.
#[must_use]
///
/// `answer_with` is the command that drives this Session (`vox room session ROOM SESSION`): each
/// request still waiting for an answer is followed by the command that gives it, with its ref.
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
            for (label, body) in &l.details {
                s.push_str(&format!("    {label}:\n"));
                for line in body.lines() {
                    s.push_str("      ");
                    s.push_str(line);
                    s.push('\n');
                }
            }
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

/// One Session's lines, each with its Details as plain lines, named as this node names its members:
/// what `vox room session --details` prints, for the TUI to draw the same words (CL-1). `rows` are
/// the Session's entries, in order; `label` its label.
#[must_use]
pub fn drawn(rows: &[SessionRow], label: &str) -> Vec<(String, Vec<String>)> {
    lines(rows, label, &ByIdent)
        .into_iter()
        .map(|l| {
            let details = crate::session_drive_ui::details(&l.details);
            (l.text, details)
        })
        .collect()
}

/// How this command names nodes: the names this node gave them ([`crate::ident`]).
struct ByIdent;

impl Names for ByIdent {
    fn alias(&self, fp: &Digest32) -> String {
        crate::ident::name_of(fp)
    }
    fn is_me(&self, by: &str) -> bool {
        vox_core::node::link::b32_decode(by, "fingerprint")
            .is_ok_and(|fp| crate::ident::name_of(&fp) == crate::ident::YOU)
    }
    fn alias_b32(&self, by: &str) -> String {
        match vox_core::node::link::b32_decode(by, "fingerprint") {
            Ok(fp) => crate::ident::name_of(&fp),
            Err(_) => by.chars().take(12).collect(),
        }
    }
}

/// `vox room session ROOM SESSION [--details] [--json]`.
///
/// # Errors
/// If the node cannot be reached, the room is unknown or closed, or no one Session answers to
/// `session`.
pub async fn show(
    paths: &vox_core::node::paths::Paths,
    room: &str,
    session: &str,
    details: bool,
    json: bool,
) -> Result<(), crate::app::AppError> {
    use crate::app::AppError;
    use vox_core::node::ipc::{Frame, Request};
    let mut client = crate::room_cli::attach(paths).await?;
    let channel_id = crate::room_cli::room_of(&mut client, room).await?;
    let sessions = match client.request(&Request::Sessions { channel_id }).await {
        Ok(Frame::Sessions { sessions }) => sessions,
        Ok(Frame::Error { reason }) => return Err(AppError::Usage(reason)),
        Ok(other) => return Err(crate::client::unexpected(&other)),
        Err(e) => return Err(AppError::Usage(e.to_string())),
    };
    let label_of = |s: &vox_core::node::sessions::SessionRow| {
        vox_agentcomms::envelope::session_label(
            &crate::ident::name_of(&s.node),
            s.name.as_deref(),
            &s.id,
        )
    };
    let rows = match client
        .request(&Request::SessionEntries { channel_id })
        .await
    {
        Ok(Frame::SessionEntries { rows }) => rows,
        Ok(Frame::Error { reason }) => return Err(AppError::Usage(reason)),
        Ok(other) => return Err(crate::client::unexpected(&other)),
        Err(e) => return Err(AppError::Usage(e.to_string())),
    };
    let kind = |r: &SessionRow| {
        serde_json::from_str::<Value>(&r.body)
            .ok()
            .and_then(|v| v.get("kind").and_then(Value::as_str).map(str::to_owned))
            .unwrap_or_default()
    };
    // An ended Session stays readable (ADR-029 SE-5).
    let (id, node, label, state, can_drive) =
        match vox_core::node::sessions::resolve(&sessions, session, true, label_of) {
            Ok(row) => (
                row.id.clone(),
                row.node,
                label_of(row),
                if row.open { "open" } else { "ended" },
                row.can_drive,
            ),
            // Entries this node can open, of a Session whose opening it does not hold yet: the
            // opening is a room message, and the entries are sealed apart (SC-2), so either can
            // arrive first. They are shown, named by their node and id, never guessed: one
            // session id, matched whole or by 8 characters or more.
            Err(refused) => {
                let typed = session.trim();
                let mut found: Vec<(&str, Digest32)> = rows
                    .iter()
                    .filter(|r| kind(r) != "drive")
                    .filter(|r| {
                        r.session_id == typed
                            || (typed.chars().count() >= 8 && r.session_id.starts_with(typed))
                    })
                    .map(|r| (r.session_id.as_str(), r.author))
                    .collect();
                found.sort_unstable();
                found.dedup();
                let [(id, node)] = found.as_slice() else {
                    return Err(AppError::Usage(refused));
                };
                let label =
                    vox_agentcomms::envelope::session_label(&crate::ident::name_of(node), None, id);
                (
                    (*id).to_owned(),
                    *node,
                    label,
                    "opening not received yet",
                    true,
                )
            }
        };
    let mine = of_session(rows, &id, &node);
    use std::io::Write as _;
    // A member without drive holds the entries but cannot open them (SC-2, SC-3): it is told whose
    // trust it lacks, never shown an empty Session.
    if !can_drive && mine.iter().all(|r| r.author != node) {
        let mut out = std::io::stdout().lock();
        let _ = writeln!(out, "{label} · {state}");
        let _ = writeln!(
            out,
            "Only members {} trusts with drive see inside this Session.",
            crate::ident::name_of(&node)
        );
        return Ok(());
    }
    let drawn = lines(&mine, &label, &ByIdent);
    let mut out = std::io::stdout().lock();
    if json {
        for l in &drawn {
            let d: serde_json::Map<String, Value> = l
                .details
                .iter()
                .map(|(k, v)| (k.clone(), Value::String(v.clone())))
                .collect();
            let _ = writeln!(
                out,
                "{}",
                serde_json::json!({
                    "seq": l.seq, "kind": l.kind, "line": l.text, "ref": l.reference,
                    "waiting": l.waiting.is_some(),
                    "details": if details { Value::Object(d) } else { Value::Null },
                })
            );
        }
    } else {
        let _ = writeln!(out, "{label} · {state}");
        let answer_with = format!("vox room session {} {id}", room.trim());
        let _ = write!(out, "{}", render(&drawn, details, &answer_with));
    }
    Ok(())
}
