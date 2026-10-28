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
    use vox_core::node::daemonipc::{DaemonClient, DaemonFrame, DaemonRequest, NodeStatus};
    let at = crate::client::one_shot(paths)?;
    let mut daemon = DaemonClient::open(&paths.account().socket())
        .await
        .map_err(|e| crate::client::said(&at, e))?;
    let nodes = match daemon.request(DaemonRequest::Nodes).await? {
        DaemonFrame::Nodes(nodes) => nodes,
        DaemonFrame::Refused(r) => return Err(AppError::Usage(r.to_string())),
        other => return Err(crate::client::unexpected_daemon(&other)),
    };
    let name = crate::client::name_of(paths)?;
    if let Some(info) = nodes
        .iter()
        .find(|n| n.name == name && n.status != Some(NodeStatus::Ready))
    {
        let anchors = vox_core::node::status::request_anchors(&at)
            .await
            .map_err(|e| crate::client::said(&at, e))?;
        let value = serde_json::json!({
            "node": name.as_str(), "status": info.status.map(|s| s.as_str()),
            "identity": info.fingerprint.map(|f| vox_core::node::link::b32_encode(&f)),
            "anchors": anchors.iter().map(|a| a.to_json()).collect::<Vec<_>>(),
        });
        if json {
            println!("{value}");
        } else {
            println!("node {name}  {}", info.status.map_or("…", |s| s.as_str()));
            if info.status == Some(NodeStatus::Locked) {
                println!(
                    "Unlock with {}",
                    vox_text::shell::command(&["vox", "node", "unlock", name.as_str()])
                );
            }
            print!("{}", render_anchors(&value));
        }
        return Ok(());
    }
    let report = vox_core::node::status::request(&at)
        .await
        .map_err(|e| crate::client::said(&at, e))?;
    if json {
        println!("{report}");
        return Ok(());
    }
    let v: Value = serde_json::from_str(&report)
        .map_err(|e| AppError::Usage(format!("the node's report did not parse: {e}")))?;
    validate_governance_status(&v)?;
    print!("{}", render(&v)?);
    Ok(())
}

/// The human renderer must not silently turn a missing or wrong-typed governance answer into
/// revision zero or an idle backfill. JSON and human status are the same shipped contract.
fn validate_governance_status(v: &Value) -> Result<(), AppError> {
    if v.get("governance_pending")
        .and_then(Value::as_bool)
        .is_none()
    {
        return Err(AppError::Usage(
            "the node's report has no boolean governance_pending".into(),
        ));
    }
    let rooms = v
        .get("rooms")
        .and_then(Value::as_array)
        .ok_or_else(|| AppError::Usage("the node's report has no rooms array".into()))?;
    for (index, room) in rooms.iter().enumerate() {
        if room
            .get("governance_revision")
            .and_then(Value::as_u64)
            .is_none()
        {
            return Err(AppError::Usage(format!(
                "the node's report room {index} has no numeric governance_revision"
            )));
        }
        for (member_index, member) in room["members"].as_array().into_iter().flatten().enumerate() {
            if member
                .get("key_delivery_pending")
                .and_then(Value::as_bool)
                .is_none()
            {
                return Err(AppError::Usage(format!(
                    "the node's report room {index} member {member_index} has no boolean \
                     key_delivery_pending"
                )));
            }
        }
        if room
            .get("render_backfill_pending")
            .and_then(Value::as_bool)
            .is_none()
        {
            return Err(AppError::Usage(format!(
                "the node's report room {index} has no boolean render_backfill_pending"
            )));
        }
    }
    Ok(())
}

fn s<'a>(v: &'a Value, k: &str) -> &'a str {
    v.get(k).and_then(Value::as_str).unwrap_or("")
}

fn short(id: &str) -> String {
    id.chars().take(12).collect()
}

fn ago(now_ms: u64, v: &Value) -> String {
    match v.as_u64() {
        Some(t_ms) => format!("{}s ago", now_ms.saturating_sub(t_ms) / 1_000),
        None => "never".into(),
    }
}

/// Shared anchor wording, including when the selected node is Locked or in transition.
fn render_anchors(v: &Value) -> String {
    use std::fmt::Write as _;
    let mut o = String::new();
    for a in v["anchors"].as_array().into_iter().flatten() {
        let sources = a["sources"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|source| {
                if source["kind"] == "added-by-hand" {
                    "added by hand".to_owned()
                } else {
                    format!(
                        "from room {}{}",
                        source["name"].as_str().unwrap_or(""),
                        if source["stale"] == true {
                            " (last known)"
                        } else {
                            ""
                        }
                    )
                }
            })
            .collect::<Vec<_>>()
            .join("; ");
        let addresses = a["addresses"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>()
            .join(", ");
        let reach = s(a, "reach_text");
        let _ = writeln!(
            o,
            "anchor {}  {addresses}  {sources}  {reach}",
            short(s(a, "fingerprint"))
        );
    }
    o
}

/// The report for a person.
fn render(v: &Value) -> Result<String, AppError> {
    use std::fmt::Write as _;
    let now = v.get("now_ms").and_then(Value::as_u64).unwrap_or(0);
    let mut o = String::new();
    let _ = writeln!(
        o,
        "node {}  Ready  {}",
        short(s(v, "identity")),
        if v.get("networked").and_then(Value::as_bool) == Some(true) {
            "on the network"
        } else {
            "NOT on the network"
        }
    );
    // The node's fingerprint whole, grouped, with its art beside it (ADR-028 K-1, L-9).
    for line in vox_text::fingerprint::card(s(v, "identity")) {
        let _ = writeln!(o, "  {line}");
    }
    if let Some(path) = v.get("log_path").and_then(Value::as_str) {
        let _ = writeln!(o, "daemon log: {path}");
    }
    let _ = writeln!(
        o,
        "governance work: {}",
        if v.get("governance_pending").and_then(Value::as_bool) == Some(true) {
            "pending"
        } else {
            "idle"
        }
    );
    let empty = Vec::new();
    let arr = |k: &str| v.get(k).and_then(Value::as_array).unwrap_or(&empty);
    o.push_str(&render_anchors(v));
    // Stored entries a room set aside when it opened (V210-74), before the room details.
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
    let _ = writeln!(
        o,
        "{}",
        crate::ui::keyring_label(v.get("keyring_open_secs").and_then(Value::as_u64))
    );
    let unhealthy = arr("unhealthy");
    if unhealthy.is_empty() {
        let _ = writeln!(o, "healthy: nothing needs attention");
    } else {
        let _ = writeln!(o, "UNHEALTHY:");
        for u in unhealthy {
            let _ = writeln!(o, "  ! {}", s(u, "message"));
        }
    }
    for r in arr("recovered") {
        let _ = writeln!(o, "{}", s(r, "message"));
    }
    // What this node refused most recently, from its decision record (ADR-028 D-3).
    let refusals = arr("refusals");
    if !refusals.is_empty() {
        let _ = writeln!(o, "\nrecent refusals");
        for e in refusals {
            let who = match e.get("alias").and_then(Value::as_str) {
                Some(alias) => format!("{alias} ({})", short(s(e, "by"))),
                None => short(s(e, "by")),
            };
            let _ = writeln!(
                o,
                "  {}  refused {who} {}: {}",
                ago(now, &e["at_ms"]),
                s(e, "asked"),
                s(e, "why")
            );
        }
    }
    let _ = writeln!(o, "\nrooms");
    for (index, r) in arr("rooms").iter().enumerate() {
        let governance_revision = r["governance_revision"].as_u64().ok_or_else(|| {
            AppError::Usage(format!(
                "the node's report room {index} has no numeric governance_revision"
            ))
        })?;
        let render_backfill_pending = r["render_backfill_pending"].as_bool().ok_or_else(|| {
            AppError::Usage(format!(
                "the node's report room {index} has no boolean render_backfill_pending"
            ))
        })?;
        let _ = writeln!(
            o,
            "  {} {}  epoch {}  last sync {}  rows {}  log entries {}  sender keys held {}, received {}; governance revision {}, render backfill {}",
            short(s(r, "id")),
            s(r, "name"),
            r.get("epoch").and_then(Value::as_u64).unwrap_or(0),
            ago(now, &r["last_sync_ms"]),
            r.get("entries").and_then(Value::as_u64).unwrap_or(0),
            r.get("log_entries").and_then(Value::as_u64).unwrap_or(0),
            r.get("key_generations")
                .and_then(Value::as_u64)
                .unwrap_or(0),
            r.get("received_key_generations")
                .and_then(Value::as_u64)
                .unwrap_or(0),
            governance_revision,
            if render_backfill_pending {
                "pending"
            } else {
                "idle"
            }
        );
        let _ = writeln!(
            o,
            "    messages: {}; Session steps: {}",
            vox_core::node::retention::describe(
                r.get("retention").and_then(Value::as_u64).unwrap_or(0)
            ),
            vox_core::node::retention::describe(
                r.get("step_retention").and_then(Value::as_u64).unwrap_or(0)
            )
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
                ago(now, &m["last_seen_ms"]),
                ago(now, &m["last_sync_ms"])
            );
            if let Some(said) = m.get("key_waits").and_then(Value::as_str) {
                let _ = writeln!(o, "      {said}");
            }
            if let Some(through) = m.get("held_through").and_then(Value::as_u64) {
                let _ = writeln!(o, "      holds this node's room feed through {through}");
            }
            if let Some(through) = m.get("holds_through").and_then(Value::as_u64) {
                let _ = writeln!(o, "      this node holds their room feed through {through}");
            }
            if flag("key_delivery_pending") {
                let _ = writeln!(
                    o,
                    "      is still owed one or more of your sender keys here"
                );
            }
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
    // The machine's gateways, as its routing table names them (ADR-012 N-53).
    let _ = writeln!(o, "\ngateway");
    for family in ["ipv4", "ipv6"] {
        let g = &v["gateway"][family];
        let hop = &g["next_hop"];
        let said = if hop.is_null() {
            "no default route".to_owned()
        } else {
            match hop.get("interface").and_then(Value::as_str) {
                Some(i) => format!("next hop {} via {i}", s(hop, "address")),
                None => format!("next hop {}", s(hop, "address")),
            }
        };
        let _ = writeln!(o, "  {family}  {said}");
        // Who was asked for a mapping, and who answered on which rung (N-54).
        let asked: Vec<&str> = g["asked"]
            .as_array()
            .map(|a| a.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();
        let answer = &g["answered"];
        let line = if asked.is_empty() {
            "no gateway asked".to_owned()
        } else if answer.is_null() {
            format!("asked {}: none answered", asked.join(", "))
        } else {
            format!(
                "asked {}: {} answered at {}",
                asked.join(", "),
                s(answer, "rung"),
                s(answer, "address")
            )
        };
        let _ = writeln!(o, "        {line}");
    }
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
        "app streams  in {}  accepted {}  opened {}  refused: not in keyring {}, busy {}, no listener {}, unaccepted {}, locally {}  withdrawn {}",
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
            "  room {} peer {}: opened {} admitted {} completed {} empty {} partial {} failed {} \
             busy-refused {} stale {} refused {} skipped {} queued {}",
            short(s(r, "room")),
            short(s(r, "peer")),
            n(r, "opened"),
            n(r, "admitted"),
            n(r, "completed"),
            n(r, "empty"),
            n(r, "partial"),
            n(r, "failed"),
            n(r, "busy_refused"),
            n(r, "stale"),
            n(r, "refused"),
            n(r, "skipped_at_cap"),
            n(r, "queued"),
        );
        // Why each completed round ran (ADR-038 FX-15, #996): a round with no need a person
        // can read here is the defect, not the load.
        if let Some(why) = r.get("reasons").filter(|w| w.is_object()) {
            let _ = write!(
                o,
                "; why: offer {} hint {} announce {} periodic {} page {} request {} served {}",
                n(why, "offer"),
                n(why, "hint"),
                n(why, "announce"),
                n(why, "periodic"),
                n(why, "page"),
                n(why, "request"),
                n(why, "served"),
            );
        }
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
    Ok(o)
}

/// One line per live tunnel (V210-81): who, which service, which way, how long it has been open
/// and how long since it last moved a byte — so a stale one, holding a member's connection, is
/// seen. Said before the sync rows.
fn tunnels(v: &serde_json::Value, out: &mut String) {
    use std::fmt::Write as _;
    let now_ms = vox_core::transport::quic::unix_now_ms();
    let ago = |t_ms: u64| {
        let s = now_ms.saturating_sub(t_ms) / 1_000;
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
            ago(n("opened_ms")),
            ago(n("last_moved_ms"))
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
            ago(n("closed_ms"))
        );
    }
}

/// `vox decisions`: the complete retained record, carried by the same paged reader as the app.
pub async fn decisions(paths: &Paths, json: bool) -> Result<(), AppError> {
    use vox_core::node::ipc::{Frame, IpcClient, Request};
    let at = crate::client::one_shot(paths)?;
    let mut client = IpcClient::open_at(&at)
        .await
        .map_err(|e| crate::client::said(&at, e))?;
    let reply = client
        .request(&Request::Decisions { limit: 0 })
        .await
        .map_err(|e| crate::client::said(&at, e))?;
    let Frame::Decisions { events } = reply else {
        return Err(AppError::Usage(format!(
            "the node did not return its decisions: {reply:?}"
        )));
    };
    if events.is_empty() && !json {
        println!("No decisions in the retained record.");
    }
    for event in events {
        if json {
            println!(
                "{}",
                serde_json::json!({"at_ms":event.at_ms,"asked":event.asked,
                "by":event.by,"alias":event.alias,"decided":event.decided,
                "why":event.why,"room":event.room})
            );
        } else {
            let who = event.alias.as_deref().unwrap_or(&event.by);
            println!(
                "{}  {}  {}: {} — {}",
                event.at_ms, event.decided, who, event.asked, event.why
            );
        }
    }
    Ok(())
}
