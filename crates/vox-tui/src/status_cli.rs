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
    let mut out = String::new();
    // Stored entries a room set aside when it opened (V210-74): said first, whatever else there is.
    for r in v
        .get("set_aside")
        .and_then(|s| s.as_array())
        .into_iter()
        .flatten()
    {
        let room: String = r
            .get("room")
            .and_then(|x| x.as_str())
            .unwrap_or("?")
            .chars()
            .take(12)
            .collect();
        for e in r
            .get("entries")
            .and_then(|x| x.as_array())
            .into_iter()
            .flatten()
        {
            let _ = writeln!(
                out,
                "room {room}, when it opened: {}",
                e.as_str().unwrap_or("?")
            );
        }
    }
    tunnels(&v, &mut out);
    if rows.is_empty() {
        out.push_str("no sync sessions yet\n");
        return out;
    }
    for r in rows {
        let s = |k: &str| r.get(k).and_then(|x| x.as_str()).unwrap_or("?").to_owned();
        let n = |k: &str| r.get(k).and_then(serde_json::Value::as_u64).unwrap_or(0);
        let short = |id: String| id.chars().take(12).collect::<String>();
        let _ = write!(
            out,
            "room {} peer {}: opened {} admitted {} completed {} partial {} failed {} busy-refused {} \
             stale {} refused {} skipped {} queued {}",
            short(s("room")),
            short(s("peer")),
            n("opened"),
            n("admitted"),
            n("completed"),
            n("partial"),
            n("failed"),
            n("busy_refused"),
            n("stale"),
            n("refused"),
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

/// One line per live tunnel (V210-81): who, which service, which way, how long it has been open
/// and how long since it last moved a byte — so a stale one, holding a member's connection, is
/// seen. Said before the sync rows.
fn tunnels(v: &serde_json::Value, out: &mut String) {
    let now = vox_core::transport::quic::unix_now();
    let ago = |t: u64| {
        let s = now.saturating_sub(t);
        if s < 120 {
            format!("{s}s")
        } else if s < 7200 {
            format!("{}m", s / 60)
        } else {
            format!("{}h", s / 3600)
        }
    };
    for t in v
        .get("tunnels")
        .and_then(|t| t.as_array())
        .into_iter()
        .flatten()
    {
        let s = |k: &str| t.get(k).and_then(|x| x.as_str()).unwrap_or("?").to_owned();
        let n = |k: &str| t.get(k).and_then(serde_json::Value::as_u64).unwrap_or(0);
        let peer: String = s("peer").chars().take(12).collect();
        let way = if s("direction") == "out" {
            format!("to {peer}")
        } else {
            format!("from {peer}")
        };
        let _ = writeln!(
            out,
            "tunnel {way} for {}: open {}, last moved {} ago",
            s("service"),
            ago(n("opened")),
            ago(n("last_moved"))
        );
    }
}
