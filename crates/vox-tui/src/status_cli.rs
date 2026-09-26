//! `vox status` — the human form of the node's sync counters (ADR-025 S0b). `--json` prints the
//! node's JSON verbatim; this renders that same JSON, so the two can never disagree.

use std::fmt::Write as _;

/// Render the node's status JSON for a person: one line per `(room, peer)`.
#[must_use]
pub fn render(json: &str) -> String {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(json) else {
        return format!("{json}\n");
    };
    let rows = v
        .get("sync")
        .and_then(|s| s.as_array())
        .cloned()
        .unwrap_or_default();
    if rows.is_empty() {
        return "no sync sessions yet\n".to_owned();
    }
    let mut out = String::new();
    for r in rows {
        let s = |k: &str| r.get(k).and_then(|x| x.as_str()).unwrap_or("?").to_owned();
        let n = |k: &str| r.get(k).and_then(serde_json::Value::as_u64).unwrap_or(0);
        let short = |id: String| id.chars().take(12).collect::<String>();
        let _ = write!(
            out,
            "room {} peer {}: opened {} admitted {} completed {} partial {} failed {} busy-refused {} \
             stale {} skipped {} queued {}",
            short(s("room")),
            short(s("peer")),
            n("opened"),
            n("admitted"),
            n("completed"),
            n("partial"),
            n("failed"),
            n("busy_refused"),
            n("stale"),
            n("skipped_at_cap"),
            n("queued"),
        );
        if let Some(b) = r.get("backoff").filter(|b| !b.is_null()) {
            let _ = write!(
                out,
                ", backing off ({}, {} failure(s))",
                b.get("kind").and_then(|k| k.as_str()).unwrap_or("?"),
                b.get("failures")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or(0)
            );
        }
        if let Some(f) = r.get("last_failure").and_then(|f| f.as_str()) {
            let _ = write!(out, "; last failure: {f}");
        }
        out.push('\n');
    }
    out
}
