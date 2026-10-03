//! `vox status` (PRD-001 R35) — what the running node is doing, and what needs looking
//! at, in one command.
//!
//! It attaches to the node's control socket like `vox room`, asks for the report, and
//! prints it: for a person by default, as the node's own JSON with `--json`. The JSON is
//! the contract; the human form is a rendering of it, so the two cannot disagree.
//!
//! The report ends with ADR-025 S0b's sync counters: one line per `(room, peer)`.

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
    // Stored entries a room set aside when it opened (V210-74): said first, whatever else there is.
    for r in arr("set_aside") {
        for e in r.get("entries").and_then(Value::as_array).unwrap_or(&empty) {
            let _ = writeln!(
                o,
                "room {}, when it opened: {}",
                short(s(r, "room")),
                e.as_str().unwrap_or("?")
            );
        }
    }
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
                .unwrap_or(0)
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
            "  {}  {}  rtt {} ms  key exchange {}",
            short(s(p, "id")),
            path,
            p.get("rtt_ms").and_then(Value::as_u64).unwrap_or(0),
            s(p, "tls_group")
        );
    }
    let _ = writeln!(
        o,
        "  relaying {} circuit(s) for others",
        v.get("relaying").and_then(Value::as_u64).unwrap_or(0)
    );
    // **One listing of tunnels** (V210-81): each live tunnel once, from the node's one list,
    // whichever way it was opened. A forward is listed apart: it is a door, not a tunnel.
    let _ = writeln!(o, "\ntunnels");
    // Every live tunnel, with how long since it last moved a byte (V210-81).
    tunnels(v, &mut o);
    for t in arr("forwards") {
        let _ = writeln!(
            o,
            "  forward {} to {}'s {} (room {})",
            s(t, "local"),
            short(s(t, "host")),
            s(t, "service"),
            short(s(t, "room"))
        );
    }
    // **Each UDP flow, with its own counts** (ADR-022 6.9, V030-34): what it put on its tunnel,
    // what it delivered from the far side, and what a full local socket or queue dropped.
    let _ = writeln!(o, "\nudp flows");
    let flows = arr("udp_flows");
    if flows.is_empty() {
        let _ = writeln!(o, "  none");
    }
    for f in flows {
        let n = |k: &str| f.get(k).and_then(Value::as_u64).unwrap_or(0);
        let _ = writeln!(
            o,
            "  {} with {}: to {} from {} dropped {}, idle {} ms",
            s(f, "service"),
            short(s(f, "peer")),
            n("to"),
            n("from"),
            n("dropped"),
            n("idle_ms")
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
    let _ = writeln!(o, "\nsync, per room and peer");
    let sync = arr("sync");
    if sync.is_empty() {
        let _ = writeln!(o, "  no sync sessions yet");
    }
    for r in sync {
        let _ = write!(
            o,
            "  room {} peer {}: opened {} admitted {} completed {} partial {} failed {} busy-refused {} \
             stale {} refused {} skipped {} queued {}",
            short(s(r, "room")),
            short(s(r, "peer")),
            n(r, "opened"),
            n(r, "admitted"),
            n(r, "completed"),
            n(r, "partial"),
            n(r, "failed"),
            n(r, "busy_refused"),
            n(r, "stale"),
            n(r, "refused"),
            n(r, "skipped_at_cap"),
            n(r, "queued"),
        );
        if let Some(b) = r.get("backoff").filter(|b| !b.is_null()) {
            let _ = write!(
                o,
                ", backing off ({}, {} failure(s))",
                s(b, "kind"),
                n(b, "failures")
            );
        }
        if let Some(f) = r.get("last_failure").and_then(Value::as_str) {
            let _ = write!(o, "; last failure: {f}");
        }
        // A session that runs on: which end opened it, the step it is at and for how long
        // (V210-110).
        let running: Vec<String> = r
            .get("running")
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
            .map(|x| {
                let t = |k: &str| x.get(k).and_then(|v| v.as_str()).unwrap_or("?").to_owned();
                let ms = |k: &str| x.get(k).and_then(serde_json::Value::as_u64).unwrap_or(0);
                format!(
                    "{} {} for {:.1}s (started {:.1}s ago)",
                    t("dir"),
                    t("step"),
                    ms("for_ms") as f64 / 1000.0,
                    ms("age_ms") as f64 / 1000.0
                )
            })
            .collect();
        if !running.is_empty() {
            let _ = write!(o, "; running: {}", running.join(", "));
        }
        o.push('\n');
    }
    o
}

/// One line per live tunnel (V210-81): who, which service, which way, how long it has been open
/// and how long since it last moved a byte — so a stale one, holding a member's connection, is
/// seen. Said before the sync rows.
fn tunnels(v: &serde_json::Value, out: &mut String) {
    use std::fmt::Write as _;
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
            "tunnel {} {way} for {}: open {}, last moved {} ago",
            n("id"),
            s("service"),
            ago(n("opened")),
            ago(n("last_moved"))
        );
    }
    // Ended for a reason a person should see (V030-11): closed here, there, or as stuck.
    for t in v
        .get("closed_tunnels")
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
            "tunnel {} {way} for {} was {} {} ago",
            n("id"),
            s("service"),
            s("why"),
            ago(n("closed"))
        );
    }
}
