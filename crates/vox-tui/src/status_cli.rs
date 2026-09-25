//! `vox status` (PRD-001 R35) — what the running node is doing, and what needs looking
//! at, in one command.
//!
//! It attaches to the node's control socket like `vox room`, asks for the report, and
//! prints it: for a person by default, as the node's own JSON with `--json`. The JSON is
//! the contract; the human form is a rendering of it, so the two cannot disagree.

use serde_json::Value;
use vox_core::node::paths::Paths;

use crate::app::AppError;

/// `vox status`.
pub async fn status(paths: &Paths, json: bool) -> Result<(), AppError> {
    let sock = paths.socket_file();
    let report = vox_core::node::status::request(&sock).await.map_err(|e| {
        AppError::Usage(format!(
            "no node answers at {} — start one with `vox daemon` (or `vox tui`): {e}",
            sock.display()
        ))
    })?;
    if json {
        println!("{report}");
        return Ok(());
    }
    let v: Value = serde_json::from_str(&report)
        .map_err(|e| AppError::Usage(format!("the node's report did not parse: {e}")))?;
    print!("{}", render(&v));
    Ok(())
}

fn s<'a>(v: &'a Value, k: &str) -> &'a str {
    v.get(k).and_then(Value::as_str).unwrap_or("")
}

fn short(id: &str) -> String {
    id.chars().take(12).collect()
}

fn ago(now: u64, v: &Value) -> String {
    match v.as_u64() {
        Some(t) => format!("{}s ago", now.saturating_sub(t)),
        None => "never".into(),
    }
}

/// The report for a person.
fn render(v: &Value) -> String {
    use std::fmt::Write as _;
    let now = v.get("now").and_then(Value::as_u64).unwrap_or(0);
    let mut o = String::new();
    let _ = writeln!(
        o,
        "node {}  {}",
        short(s(v, "identity")),
        if v.get("networked").and_then(Value::as_bool) == Some(true) {
            "on the network"
        } else {
            "NOT on the network"
        }
    );
    let empty = Vec::new();
    let arr = |k: &str| v.get(k).and_then(Value::as_array).unwrap_or(&empty);
    let unhealthy = arr("unhealthy");
    if unhealthy.is_empty() {
        let _ = writeln!(o, "healthy: nothing needs attention");
    } else {
        let _ = writeln!(o, "UNHEALTHY:");
        for u in unhealthy {
            let _ = writeln!(o, "  ! {}", s(u, "message"));
        }
    }
    let _ = writeln!(o, "\nrooms");
    for r in arr("rooms") {
        let _ = writeln!(
            o,
            "  {} {}  epoch {}  last sync {}  sender keys held {}",
            short(s(r, "id")),
            s(r, "name"),
            r.get("epoch").and_then(Value::as_u64).unwrap_or(0),
            ago(now, &r["last_sync"]),
            r.get("key_generations")
                .and_then(Value::as_u64)
                .map_or_else(|| "(busy)".to_owned(), |n| n.to_string())
        );
        // A fork is a member caught signing two different entries at one position: loud,
        // because everything that member posts here is refused from then on.
        for f in r.get("frozen").and_then(Value::as_array).unwrap_or(&empty) {
            let _ = writeln!(
                o,
                "    ! {} is frozen here: it signed two different entries at one position",
                short(f.as_str().unwrap_or("?"))
            );
        }
        if let Some(n) = r
            .get("refused_below_checkpoint")
            .and_then(Value::as_u64)
            .filter(|n| *n > 0)
        {
            let _ = writeln!(
                o,
                "    refused {n} entries at or below their author's checkpoint"
            );
        }
        for m in r.get("members").and_then(Value::as_array).unwrap_or(&empty) {
            let flag = |k: &str| m.get(k).and_then(Value::as_bool) == Some(true);
            let _ = writeln!(
                o,
                "    {}{}{}  {}  last seen {}  last sync {}",
                short(s(m, "id")),
                if flag("me") { " (this node)" } else { "" },
                if flag("trusted") { " trusted" } else { "" },
                if flag("me") {
                    ""
                } else if flag("connected") {
                    "connected"
                } else {
                    "not connected"
                },
                ago(now, &m["last_seen"]),
                ago(now, &m["last_sync"])
            );
        }
    }
    let _ = writeln!(o, "  always-on member: {}", s(v, "always_on_member"));
    let _ = writeln!(o, "\npeers");
    for p in arr("peers") {
        let path = match (s(p, "path"), p.get("relay").and_then(Value::as_str)) {
            ("relayed", Some(r)) => format!("relayed via {}", short(r)),
            (path, _) => path.to_owned(),
        };
        let _ = writeln!(
            o,
            "  {}  {}  rtt {} ms",
            short(s(p, "id")),
            path,
            p.get("rtt_ms").and_then(Value::as_u64).unwrap_or(0)
        );
    }
    let _ = writeln!(
        o,
        "  relaying {} circuit(s) for others",
        v.get("relaying").and_then(Value::as_u64).unwrap_or(0)
    );
    let _ = writeln!(o, "\ntunnels");
    for t in arr("tunnels_served") {
        let _ = writeln!(
            o,
            "  serving {} to {} (room {})",
            s(t, "service"),
            short(s(t, "client")),
            short(s(t, "room"))
        );
    }
    for t in arr("tunnels_dialed") {
        let _ = writeln!(
            o,
            "  forwarding {} to {}'s {} (room {})",
            s(t, "local"),
            short(s(t, "host")),
            s(t, "service"),
            short(s(t, "room"))
        );
    }
    let d = &v["datagrams"];
    let a = &v["app"];
    let n = |x: &Value, k: &str| x.get(k).and_then(Value::as_u64).unwrap_or(0);
    let _ = writeln!(
        o,
        "\ndatagrams  sent {}  delivered {}  fragmented {}  dropped: unknown flow {}, inbox full {}, malformed {}, unsendable {}",
        n(d, "sent"),
        n(d, "delivered"),
        n(d, "fragmented"),
        n(d, "unknown_flow"),
        n(d, "inbox_full"),
        n(d, "malformed"),
        n(d, "send_dropped")
    );
    let _ = writeln!(
        o,
        "app streams  in {}  accepted {}  opened {}  refused: untrusted {}, busy {}, no listener {}, unaccepted {}, locally {}  withdrawn {}",
        n(a, "inbound"),
        n(a, "accepted"),
        n(a, "opened"),
        n(a, "refused_untrusted"),
        n(a, "refused_busy"),
        n(a, "refused_no_listener"),
        n(a, "refused_unaccepted"),
        n(a, "refused_locally"),
        n(a, "withdrawn")
    );
    o
}
