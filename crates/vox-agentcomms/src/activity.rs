//! ADR-029 §2 — **a Session's activity entries**: the one format every harness's mirror writes
//! (from its hooks, its app-server or Vox's plugin) and every client reads (the CLI, the TUI, the
//! app).
//!
//! An entry is a JSON object, sealed inside its Session (ADR-029 SC-2), whose `kind` says what it
//! is: `user`, `tool`, `tool-done`, `reply`, `turn-end`, `approval`, `question`, `resolved`,
//! `drive`, `drive-result`. Every entry carries `v` ([`VERSION`]), `session` (the harness's own
//! session id), `kind`, `ts` and, from the session's node, `seq`; a tool call and its result, and a
//! request and its resolution, share `ref`. A sub-agent's entries carry `agent_id` and `agent`.
//! An unknown kind is shown, never refused.
//!
//! ## Long content (SC-1)
//!
//! An entry is at most the log's text limit once serialized. A longer one is cut, on character
//! boundaries and by its **serialized** size (JSON escaping can double a byte), into parts that
//! share `kind` and `ref` and carry `part: [i, n]`; a reader joins them ([`join`]) into one
//! Details view.

use std::collections::BTreeMap;

use serde_json::{json, Map, Value};

/// The format's version.
pub const VERSION: u64 = 1;

/// The longest one-line summary, in characters, before it is cut with "…".
pub const SUMMARY_CHARS: usize = 160;

/// Room left in each part for `"part":[i,n]` and the separators around it.
const PART_ROOM: usize = 48;

/// `text` as one line: every run of whitespace one space, at most [`SUMMARY_CHARS`] characters,
/// a cut one ending in "…".
#[must_use]
pub fn one_line(text: &str) -> String {
    let folded = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if folded.chars().count() <= SUMMARY_CHARS {
        return folded;
    }
    let mut cut: String = folded.chars().take(SUMMARY_CHARS - 1).collect();
    cut.push('…');
    cut
}

/// How many bytes `c` takes inside a JSON string, as `serde_json` writes it.
fn escaped_len(c: char) -> usize {
    match c {
        '"' | '\\' | '\n' | '\r' | '\t' | '\u{08}' | '\u{0c}' => 2,
        c if (c as u32) < 0x20 => 6,
        c => c.len_utf8(),
    }
}

/// `m` as entries of at most `max` bytes each: one when it fits, else parts that cut the string
/// field `big` and carry `part: [i, n]`.
#[must_use]
pub fn split(m: Map<String, Value>, big: &str, max: usize) -> Vec<String> {
    let whole = Value::Object(m.clone()).to_string();
    if whole.len() <= max {
        return vec![whole];
    }
    let Some(text) = m.get(big).and_then(Value::as_str).map(str::to_owned) else {
        // Nothing to cut: the fields other than `big` are bounded (a summary is one line), so
        // this is an entry no harness event produces. Said, not dropped.
        let mut short = m;
        short.insert(
            "summary".into(),
            json!("(this entry was too large to keep)"),
        );
        return vec![Value::Object(short).to_string()];
    };
    let mut empty = m.clone();
    empty.insert(big.into(), json!(""));
    let budget = max
        .saturating_sub(Value::Object(empty).to_string().len() + PART_ROOM)
        .max(1024);
    let mut chunks: Vec<String> = Vec::new();
    let mut cur = String::new();
    let mut used = 0;
    for c in text.chars() {
        let n = escaped_len(c);
        if used + n > budget && !cur.is_empty() {
            chunks.push(std::mem::take(&mut cur));
            used = 0;
        }
        cur.push(c);
        used += n;
    }
    chunks.push(cur);
    let n = chunks.len();
    chunks
        .into_iter()
        .enumerate()
        .map(|(i, chunk)| {
            let mut p = m.clone();
            p.insert(big.into(), json!(chunk));
            p.insert("part".into(), json!([i + 1, n]));
            Value::Object(p).to_string()
        })
        .collect()
}

/// The field a kind's [`split`] cuts.
#[must_use]
pub fn big_field(kind: &str) -> &'static str {
    match kind {
        "tool" | "approval" => "input",
        "tool-done" => "output",
        _ => "text",
    }
}

/// One entry as read back, with the author its log proves.
#[derive(Debug, Clone, PartialEq)]
pub struct Entry<A> {
    /// The node that wrote it, proven by the log.
    pub author: A,
    /// Its fields.
    pub fields: Map<String, Value>,
}

impl<A> Entry<A> {
    /// A string field, or "".
    #[must_use]
    pub fn str(&self, k: &str) -> &str {
        self.fields
            .get(k)
            .and_then(Value::as_str)
            .unwrap_or_default()
    }

    /// Its `kind`.
    #[must_use]
    pub fn kind(&self) -> &str {
        self.str("kind")
    }

    /// Its `ref`.
    #[must_use]
    pub fn reference(&self) -> &str {
        self.str("ref")
    }

    /// Its `part: [i, n]`, when it is one part of a split entry.
    #[must_use]
    pub fn part(&self) -> Option<(u64, u64)> {
        let p = self.fields.get("part")?.as_array()?;
        Some((p.first()?.as_u64()?, p.get(1)?.as_u64()?))
    }
}

/// `rows` (author, body), one Session's entries in order, as entries: the parts of a split entry
/// joined into one, whole, by (author, kind, ref). A body that is not a JSON object is skipped.
#[must_use]
pub fn join<'a, A: Ord + Clone + 'a>(
    rows: impl IntoIterator<Item = (A, &'a str)>,
) -> Vec<Entry<A>> {
    let mut out: Vec<Entry<A>> = Vec::new();
    // A split entry waiting for its later parts: (author, kind, ref) → its index in `out`.
    let mut open: BTreeMap<(A, String, String), usize> = BTreeMap::new();
    for (author, body) in rows {
        let Ok(Value::Object(fields)) = serde_json::from_str::<Value>(body) else {
            continue;
        };
        let e = Entry { author, fields };
        let Some((i, n)) = e.part() else {
            out.push(e);
            continue;
        };
        let key = (
            e.author.clone(),
            e.kind().to_owned(),
            e.reference().to_owned(),
        );
        let field = big_field(e.kind());
        match open.get(&key) {
            Some(&at) if i > 1 => {
                let more = e.str(field).to_owned();
                if let Some(Value::String(s)) = out[at].fields.get_mut(field) {
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
                out.push(e);
            }
        }
    }
    out
}
