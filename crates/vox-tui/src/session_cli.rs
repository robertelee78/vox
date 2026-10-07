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

/// A body read back, with what assembling it needs.
struct Body {
    author: Digest32,
    v: serde_json::Map<String, Value>,
}

impl Body {
    fn str(&self, k: &str) -> &str {
        self.v.get(k).and_then(Value::as_str).unwrap_or_default()
    }
    fn kind(&self) -> &str {
        self.str("kind")
    }
    fn reference(&self) -> &str {
        self.str("ref")
    }
    fn part(&self) -> Option<(u64, u64)> {
        let p = self.v.get("part")?.as_array()?;
        Some((p.first()?.as_u64()?, p.get(1)?.as_u64()?))
    }
}

/// The field a kind's split cuts (session_mirror's `split`).
fn big_field(kind: &str) -> &'static str {
    match kind {
        "tool" | "approval" => "input",
        "tool-done" => "output",
        _ => "text",
    }
}

/// `rows`, one Session's entries in this node's order, joined: the parts of a split entry become
/// one entry, whole.
fn joined(rows: &[SessionRow]) -> Vec<Body> {
    let mut out: Vec<Body> = Vec::new();
    // A split entry waiting for its later parts: (author, kind, ref) → its index in `out`.
    let mut open: BTreeMap<(Digest32, String, String), usize> = BTreeMap::new();
    for r in rows {
        let Ok(Value::Object(v)) = serde_json::from_str::<Value>(&r.body) else {
            continue;
        };
        let b = Body {
            author: r.author,
            v,
        };
        let Some((i, n)) = b.part() else {
            out.push(b);
            continue;
        };
        let key = (b.author, b.kind().to_owned(), b.reference().to_owned());
        let field = big_field(b.kind());
        match open.get(&key) {
            Some(&at) if i > 1 => {
                let more = b.str(field).to_owned();
                if let Some(Value::String(s)) = out[at].v.get_mut(field) {
                    s.push_str(&more);
                }
                if i >= n {
                    open.remove(&key);
                }
            }
            _ => {
                if n > 1 {
                    open.insert(key, out.len());
                }
                out.push(b);
            }
        }
    }
    out
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
            .v
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
    for (i, b) in bodies.iter().enumerate() {
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
        let seq = b.v.get("seq").and_then(Value::as_u64).unwrap_or(0);
        let prefix = match b.str("agent") {
            "" => String::new(),
            t => format!("[{t}] "),
        };
        let mut details: Vec<(String, String)> = Vec::new();
        let text = match b.kind() {
            "user" => {
                details.push(("typed".into(), b.str("text").to_owned()));
                format!("typed at the terminal: {}", one_line(b.str("text")))
            }
            "tool" => {
                details.push(("input".into(), b.str("input").to_owned()));
                let head = format!("{}: {}", b.str("tool"), b.str("summary"));
                match done.get(b.reference()).map(|&i| &bodies[i]) {
                    None => format!("{head} …"),
                    Some(d) => {
                        details.push(("output".into(), d.str("output").to_owned()));
                        let ok = d.v.get("ok").and_then(Value::as_bool) != Some(false);
                        let interrupted =
                            d.v.get("interrupted").and_then(Value::as_bool) == Some(true);
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
                if b.v.get("answerable").and_then(Value::as_bool) == Some(false) {
                    format!("{head} — not answerable from Vox: {}", b.str("why"))
                } else {
                    match resolved.get(b.reference()).map(|&i| &bodies[i]) {
                        None => format!("{head} — approve or reject?"),
                        Some(r) => format!("{head} — {}", outcome_words(r, names)),
                    }
                }
            }
            "question" => {
                let qs: Vec<Value> =
                    b.v.get("questions")
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
                if b.v.get("answerable").and_then(Value::as_bool) == Some(false) {
                    format!("{head} — not answerable from Vox: {}", b.str("why"))
                } else {
                    match resolved.get(b.reference()).map(|&i| &bodies[i]) {
                        None => head,
                        Some(r) => format!("{head} — {}", outcome_words(r, names)),
                    }
                }
            }
            "file" => {
                let what = format!(
                    "{} ({})",
                    b.str("name"),
                    size(b.v.get("size").and_then(Value::as_u64).unwrap_or(0))
                );
                if b.str("dir") == "in" {
                    format!("file to {label}: {what}")
                } else {
                    format!("file from {label}: {what}")
                }
            }
            "drive" => {
                let by = names.alias(&b.author);
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
            "drive-result" => {
                if b.v.get("ok").and_then(Value::as_bool) == Some(true) {
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
        });
    }
    out
}

/// `lines` as the terminal prints them; with `details`, each entry's full input and output
/// indented under its line.
#[must_use]
pub fn render(lines: &[Line], details: bool) -> String {
    let mut s = String::new();
    for l in lines {
        s.push_str(&l.text);
        s.push('\n');
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
    let rows = match client
        .request(&Request::SessionEntries { channel_id })
        .await
    {
        Ok(Frame::SessionEntries { rows }) => rows,
        Ok(Frame::Error { reason }) => return Err(AppError::Usage(reason)),
        Ok(other) => return Err(crate::client::unexpected(&other)),
        Err(e) => return Err(AppError::Usage(e.to_string())),
    };
    // WIP(#540): the Session is to be resolved against the room's Sessions (files2's
    // `Request::Sessions`, with its label and whether this node may drive it); until that lands,
    // it is resolved against the Sessions this node can read.
    let typed = session.trim();
    let mut ids: Vec<&str> = rows.iter().map(|r| r.session_id.as_str()).collect();
    ids.sort_unstable();
    ids.dedup();
    let matching: Vec<&str> = ids
        .iter()
        .copied()
        .filter(|id| *id == typed || (typed.chars().count() >= 8 && id.starts_with(typed)))
        .collect();
    let id = match matching.as_slice() {
        [one] => (*one).to_owned(),
        [] => {
            return Err(AppError::Usage(format!(
                "no Session in this room is named {typed}"
            )))
        }
        many => {
            return Err(AppError::Usage(format!(
                "more than one Session is named {typed}: {}",
                many.join(", ")
            )))
        }
    };
    let mut mine: Vec<SessionRow> = rows.into_iter().filter(|r| r.session_id == id).collect();
    // In the order the entries were written: each author's send time, and within one moment the
    // session node's own numbering (a split entry's parts share a millisecond).
    let seq = |r: &SessionRow| {
        serde_json::from_str::<Value>(&r.body)
            .ok()
            .and_then(|v| v.get("seq").and_then(Value::as_u64))
            .unwrap_or(0)
    };
    mine.sort_by_key(|r| (r.created_millis, seq(r)));
    let owner = mine
        .iter()
        .find(|r| {
            serde_json::from_str::<Value>(&r.body)
                .ok()
                .and_then(|v| v.get("kind").and_then(Value::as_str).map(str::to_owned))
                .is_some_and(|k| k != "drive")
        })
        .map(|r| r.author);
    let label = vox_agentcomms::session_label(
        &owner.map_or_else(String::new, |fp| crate::ident::name_of(&fp)),
        None,
        &id,
    );
    let drawn = lines(&mine, &label, &ByIdent);
    let mut out = std::io::stdout().lock();
    use std::io::Write as _;
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
                    "seq": l.seq, "kind": l.kind, "line": l.text,
                    "details": if details { Value::Object(d) } else { Value::Null },
                })
            );
        }
    } else {
        let _ = writeln!(out, "{label}");
        let _ = write!(out, "{}", render(&drawn, details));
    }
    Ok(())
}
