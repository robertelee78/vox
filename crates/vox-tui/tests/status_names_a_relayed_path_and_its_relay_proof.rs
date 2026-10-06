//! PRD-001 R35 — **`vox status` names a relayed path, and the relay carrying it**, proved with
//! the shipped binary (#227: the claim `ops_status_proof` carried in-process until `a1d01323`).
//!
//! The only path between guest and host is a circuit the anchor carries: the anchor listens
//! dual-stack, the host on IPv6 loopback only and the guest on IPv4 loopback only
//! (`support/world.rs`, `PathKind::Relayed`), and the harness checks the anchor reports carrying
//! a circuit. Once bytes have crossed a `vox forward` both ways, the guest's own report must say:
//!
//! - `vox status --json`: the host's row in `peers` has `path` `relayed` and `relay` equal to the
//!   anchor's fingerprint;
//! - `vox status`: the host's line says `relayed via <the anchor's short id>`.
//!
//! And the guest's own `vox room link`, whose address names the host's address as it names the
//! anchor's, never calls the host an anchor (V030-51). Mutation: the note names every entry of the
//! address as an anchor — red, PRODUCT.
//!
//! **A joiner restarted before its first sync reaches its host through the relay** (V030-51,
//! #517). A second joiner, Late, joins the same room over the relay; the moment its join got in,
//! its leg drops everything it sends, so the room's first sync cannot happen, and `vox connect`
//! lets its node go. The host does not trust Late, so nothing on the host's side dials it.
//! `vox forward` from Late then starts a new
//! daemon, whose room has not synced, and which holds no address for the host (it reached the
//! host only through a relay): it must reach the host itself, through the circuit, sync, bind and
//! carry a round trip. Mutation: an unsynced room left to its anchor's board like
//! a synced one (`reach_members_of` returning for any anchored room) — the forward waits out its
//! 180 s for the first sync, red PRODUCT.
//!
//! **The member that let a joiner in is never its anchor** (V030-51). A room of eleven, each member
//! let in by the one before (the host lets in A1, A1 lets in A2, … A8 lets in R), with only the one
//! answering online at each join, then the anchor stopped. A joiner J let in by R has not admitted
//! R's record when its join is done (its room lists the host and itself), so nothing but the join
//! itself and R's link (which marks each member it names, `m=`) say R and A1 are members. R stops
//! too. J's own `vox status --json` must list no member — R, which let it in, nor A1, which R's
//! link names at its address — among its anchors: a node kept as an anchor is dialled directly only
//! and passed over by the sync. Mutations, each red PRODUCT: the join no longer records R as a
//! member (`note_member`); the link's member role ignored (A1 listed).
//!
//! **A guest never calls its host an anchor** (V030-51, AGENTS.md "Anchors"). On a direct path, the
//! guest joins and forwards to the host's service; the host restarts. Nothing the guest's forward
//! says, nor its `vox status`, may call the host an anchor — "connected to this anchor", "the
//! connection to this anchor is gone" — and the forward carries a round trip again after the
//! restart. Mutation: the host dialled as one of the room's anchors with the old word for its loss
//! (as integrate before V030-51), red PRODUCT.
//!
//! **A red names its side.** The report's content is PRODUCT. A `vox` step that fails while the
//! world is set is PRODUCT (staging), as the harness labels it; the test's own sockets and
//! processes are APPARATUS.
//!
//! ## Why it is `#[ignore]`d
//! Production Argon2id on three profiles and a real ADR-005 proof of work. CI runs it in release.

#![cfg(unix)]
// Both harness supports, the two-node world and the room of workers, carry their own copy of the
// data-root layout helpers.
#![allow(clippy::duplicate_mod)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/world.rs"]
mod world;

#[path = "support/room.rs"]
mod room;

use std::time::{Duration, Instant};

use serde_json::Value;
use world::{
    args, echo_service, fingerprint, log_tail, mkdir, round_trip, vox_once, PathKind, Setup,
    VoxProc, World,
};

#[test]
#[ignore = "real binaries, production Argon2id and a PoW; CI runs it in release"]
fn status_names_a_relayed_path_and_its_relay() {
    watchdog::arm();
    let port = echo_service();
    let w = World::build(&Setup {
        specs: vec![format!("{port}={port}")],
        trusted: true,
        path: PathKind::Relayed,
        guest_leg: None,
    });
    let anchor_fp = w
        .guest_anchor
        .split('@')
        .next()
        .expect("APPARATUS: the anchor spec names its fingerprint")
        .to_owned();
    let guest = w.guest_dir.clone();
    let (_fwd, at) = w.forward_service("forward", &guest, &port.to_string());
    let back = round_trip(at, b"over the relay", Duration::from_secs(120))
        .unwrap_or_else(|e| panic!("PRODUCT (staging): nothing crossed the forward: {e}"));
    assert_eq!(
        back, b"over the relay",
        "PRODUCT (staging): the forward must echo what it was sent"
    );

    // The host's row, once the guest's report lists the connection.
    let until = Instant::now() + Duration::from_secs(30);
    let (row, json) = loop {
        let (ok, out, err) = vox_once(&guest, &args(&["status", "--json"]));
        assert!(
            ok,
            "PRODUCT: the guest's `vox status --json` failed: {out}{err}"
        );
        let v: Value = serde_json::from_str(&out)
            .unwrap_or_else(|e| panic!("PRODUCT: `vox status --json` did not parse ({e}): {out}"));
        let row = v["peers"]
            .as_array()
            .and_then(|ps| ps.iter().find(|p| p["id"] == w.host_fp.as_str()))
            .cloned();
        if row.is_some() || Instant::now() >= until {
            break (row, out);
        }
        std::thread::sleep(Duration::from_millis(250));
    };
    let (ok, text, err) = vox_once(&guest, &args(&["status"]));
    assert!(ok, "PRODUCT: the guest's `vox status` failed: {text}{err}");
    let short: String = anchor_fp.chars().take(12).collect();
    eprintln!(
        "[test] the guest's row for the host: {row:?}\nthe anchor is {anchor_fp}\nhuman form:\n{text}"
    );
    let row = row.unwrap_or_else(|| {
        panic!("PRODUCT: the guest's report must list its connection to the host: {json}")
    });
    assert_eq!(
        row["path"], "relayed",
        "PRODUCT: the only path to the host is a circuit, and the report must say so"
    );
    assert_eq!(
        row["relay"].as_str(),
        Some(anchor_fp.as_str()),
        "PRODUCT: the report must name the relay carrying the path"
    );
    assert!(
        text.contains(&format!("relayed via {short}")),
        "PRODUCT: `vox status` must say the path is relayed, and through whom"
    );

    // **A member is never called an anchor** (V030-51, AGENTS.md "Anchors"): the guest's own room
    // link names the host's address, as it names the anchor's, and what `vox room link` says of
    // the anchors it names must not call the host, a member, one of them.
    let (ok, link, said) = vox_once(&guest, &args(&["room", "link", &w.room]));
    assert!(
        ok && link.trim().starts_with("vox://"),
        "PRODUCT (staging): the guest's `vox room link` gave no link: {link}{said}"
    );
    let host_short: String = w.host_fp.chars().take(12).collect();
    eprintln!("[test] the guest's `vox room link` said:\n{said}");
    assert!(
        !said.contains(&host_short),
        "PRODUCT: the guest's `vox room link` named the host {host_short}, a member of the room, \
         among its anchors:\n{said}"
    );
}

#[test]
#[ignore = "real binaries, production Argon2id and a PoW; CI runs it in release"]
fn a_joiner_restarted_before_its_first_sync_reaches_its_host_through_the_relay() {
    watchdog::arm();
    let port = echo_service();
    type Knob = std::sync::Arc<std::sync::atomic::AtomicU64>;
    let knob: std::sync::Arc<std::sync::Mutex<Option<Knob>>> = std::sync::Arc::default();
    let knob_in = std::sync::Arc::clone(&knob);
    let w = World::build(&Setup {
        specs: vec![format!("{port}={port}")],
        trusted: true,
        path: PathKind::Relayed,
        // The joiners' leg to the anchor through a forwarding stand-in whose loss the proof
        // sets: every packet from a joiner dropped while it should not sync.
        guest_leg: Some(Box::new(move |anchor| {
            let (addr, _, k, _) = world::lossy_proxy(anchor, Duration::ZERO);
            *knob_in
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(k);
            Some(addr)
        })),
    });
    // Late: a second joiner, on IPv4 loopback like the guest, so a circuit the anchor carries is
    // the only path between it and the host. The host does not trust it until its forward is up,
    // so the host owes it no key and never dials it: what reaches the host is late's own doing.
    let late = w.tmp.path().join("late");
    mkdir(&late.join("cfg"));
    let _reap = world::Reaper(vec![late.clone()]);
    let late_fp = fingerprint(&late, "late");
    let mut connect = VoxProc::spawn(
        "late-connect",
        &late,
        &args(&[
            "connect",
            &w.address,
            "--passphrase-file",
            &w.passphrase_file(),
            "--anchor",
            &w.guest_anchor,
            "--listen",
            "127.0.0.1:0",
        ]),
    );
    let knob = knob
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
        .unwrap_or_else(|| panic!("APPARATUS: the joiners' leg was never built"));
    // The moment late's join got in, its leg drops everything late sends, so the room's first
    // sync, which follows the join, cannot happen; `vox connect` then lets its node go.
    let log = late.join(".daemon").join("log");
    let deadline = Instant::now() + Duration::from_secs(600);
    while !std::fs::read_to_string(&log)
        .unwrap_or_default()
        .contains("join got in")
    {
        assert!(
            Instant::now() < deadline,
            "PRODUCT (staging): late's join did not get in within 600 s. `vox connect` said:\n{}\n\
             its daemon said:\n{}",
            connect.transcript(),
            log_tail(&late, 40)
        );
        std::thread::sleep(Duration::from_millis(1));
    }
    knob.store(1, std::sync::atomic::Ordering::SeqCst);
    let deadline = Instant::now() + Duration::from_secs(600);
    while !std::fs::read_to_string(&log)
        .unwrap_or_default()
        .contains("detached (its last holder went)")
    {
        assert!(
            Instant::now() < deadline,
            "PRODUCT (staging): late's `vox connect` did not let its node go within 600 s. It \
             said:\n{}\nits daemon said:\n{}",
            connect.transcript(),
            log_tail(&late, 40)
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    drop(connect);
    knob.store(0, std::sync::atomic::Ordering::SeqCst);
    // Late restarted by the forward, before the room's first sync.
    let (mut fwd, at) = w.forward_service("late-forward", &late, &port.to_string());
    let said = fwd.transcript();
    assert!(
        said.contains("first sync"),
        "CANNOT MEASURE: APPARATUS: late's room had synced before its daemon stopped, so a restart \
         before the first sync was not staged. The forward said:\n{said}"
    );
    eprintln!("[test] late's restarted forward bound at {at} after the room's first sync:\n{said}");
    // Now the host lets late reach its service.
    let (ok, out, err) = vox_once(
        &w.host_dir,
        &args(&["trust", "add", &late_fp, "--name", "late"]),
    );
    assert!(
        ok,
        "PRODUCT (staging): the host's `vox trust add` of late failed: {out}{err}"
    );
    let back = round_trip(at, b"after a restart", Duration::from_secs(120)).unwrap_or_else(|e| {
        panic!("PRODUCT: nothing crossed late's forward after its restart: {e}")
    });
    assert_eq!(
        back, b"after a restart",
        "PRODUCT: late's forward must echo what it was sent"
    );
}

#[test]
#[ignore = "real binaries, production Argon2id and eleven proofs of work; CI runs it in release"]
fn the_member_that_let_a_joiner_in_is_never_its_anchor() {
    watchdog::arm_for(Duration::from_secs(1500));
    let tmp = world::tempdir();
    let tmp = tmp.path();
    let (anchor, spec) = room::spawn_anchor(tmp);
    let names = [
        "host", "a1", "a2", "a3", "a4", "a5", "a6", "a7", "a8", "r", "j",
    ];
    let mut ws: Vec<room::Worker> = names.iter().map(|n| room::worker(tmp, n)).collect();
    let err = |n: &str| tmp.join(format!("{n}.daemon.err"));
    room::start_daemon(&mut ws[0], &spec, &err("host"));
    ws[0]
        .vox_in(
            None,
            &[
                "room",
                "create",
                "--passphrase-file",
                "-",
                "--name",
                "chain",
            ],
            Some(room::ROOM_PASS),
        )
        .expect_ok("the host's `vox room create`");
    let id = ws[0]
        .vox(None, &["room", "list"])
        .stdout
        .split_whitespace()
        .next()
        .unwrap_or_else(|| panic!("PRODUCT (staging): the host's `vox room list` lists no room"))
        .to_owned();
    // Each joins through the one before, the only member online then, so each was let in by it.
    for i in 1..names.len() {
        let link = ws[i - 1]
            .vox(None, &["room", "link", &id])
            .expect_ok(&format!("{}'s `vox room link`", names[i - 1]))
            .stdout
            .trim()
            .to_owned();
        if names[i] == "j" {
            // Nothing else can tell J about R from here on: no anchor, no other member.
            drop(anchor);
            break;
        }
        room::start_daemon(&mut ws[i], &spec, &err(names[i]));
        ws[i]
            .vox_in(
                None,
                &["room", "join", "--passphrase-file", "-", &link],
                Some(room::ROOM_PASS),
            )
            .expect_ok(&format!(
                "{}'s `vox room join` through {}",
                names[i],
                names[i - 1]
            ));
        ws[i - 1].stop_daemon();
    }
    unreachable_anchor_check(&mut ws, &id, &spec, &err);
}

/// J joins through R, the only member online, R stops, and J's report must not list R among its
/// anchors.
fn unreachable_anchor_check(
    ws: &mut [room::Worker],
    id: &str,
    spec: &str,
    err: &dyn Fn(&str) -> std::path::PathBuf,
) {
    let (r, j) = (ws.len() - 2, ws.len() - 1);
    let link = ws[r]
        .vox(None, &["room", "link", id])
        .expect_ok("r's `vox room link`")
        .stdout
        .trim()
        .to_owned();
    room::start_daemon(&mut ws[j], spec, &err("j"));
    ws[j]
        .vox_in(
            None,
            &["room", "join", "--passphrase-file", "-", &link],
            Some(room::ROOM_PASS),
        )
        .expect_ok("j's `vox room join` through r");
    let r_fp = ws[r].b32();
    let r_short: String = r_fp.chars().take(12).collect();
    // Who let j in, in its daemon's own words: "join got in — …, <r>: exchange …".
    let said = std::fs::read_to_string(err("j")).unwrap_or_default();
    let joined = said
        .lines()
        .find(|l| l.contains("join got in"))
        .unwrap_or_default()
        .to_owned();
    assert!(
        joined.contains(&format!("{r_short}: exchange")),
        "APPARATUS: j's daemon does not say r ({r_short}) let it in, so who let it in was not \
         staged:\n{said}"
    );
    ws[r].stop_daemon();
    let report = ws[j].vox(None, &["status", "--json"]);
    let v: serde_json::Value =
        serde_json::from_str(report.expect_ok("j's `vox status --json`").stdout.trim())
            .unwrap_or_else(|e| {
                panic!("PRODUCT: `vox status --json` is not JSON ({e}): {report:?}")
            });
    eprintln!(
        "[test] j's anchors: {}\nj's join said:\n{joined}",
        v["anchors"]
    );
    // No member of the room — r, which let j in, nor a1, which r's link names at its address —
    // is among j's anchors.
    let names: Vec<(String, String)> = ws[..j].iter().map(|w| (w.name.clone(), w.b32())).collect();
    let listed: Vec<&str> = v["anchors"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|x| x["id"].as_str())
                .filter_map(|id| {
                    names
                        .iter()
                        .find(|(_, fp)| fp == id)
                        .map(|(n, _)| n.as_str())
                })
                .collect()
        })
        .unwrap_or_default();
    assert!(
        listed.is_empty(),
        "PRODUCT: j's `vox status --json` lists members of the room among its anchors: {listed:?} \
         (r {r_short} let it in). Its anchors: {}",
        v["anchors"]
    );
}

#[test]
#[ignore = "real binaries, production Argon2id and a PoW; CI runs it in release"]
fn a_guest_never_calls_its_host_an_anchor() {
    watchdog::arm();
    let port = echo_service();
    let mut w = World::build(&Setup {
        specs: vec![format!("{port}={port}")],
        trusted: true,
        path: PathKind::Direct,
        guest_leg: None,
    });
    let guest = w.guest_dir.clone();
    let (mut fwd, at) = w.forward_service("forward", &guest, &port.to_string());
    let back = round_trip(at, b"before", Duration::from_secs(120))
        .unwrap_or_else(|e| panic!("PRODUCT (staging): nothing crossed the forward: {e}"));
    assert_eq!(back, b"before", "PRODUCT (staging): the forward must echo");
    w.restart_host_as_daemon();
    // The forward reaches the restarted host again: the guest has seen the host go and come back.
    let back = round_trip(at, b"after", Duration::from_secs(120)).unwrap_or_else(|e| {
        panic!("PRODUCT: nothing crossed the forward after the host restarted: {e}")
    });
    assert_eq!(
        back, b"after",
        "PRODUCT: the forward must echo after the restart"
    );
    std::thread::sleep(Duration::from_secs(3));
    let host_short: String = w.host_fp.chars().take(12).collect();
    let said = fwd.transcript();
    let (ok, status, err) = vox_once(&guest, &args(&["status"]));
    assert!(
        ok,
        "PRODUCT: the guest's `vox status` failed: {status}{err}"
    );
    eprintln!("[test] the guest's forward said:\n{said}\nits `vox status`:\n{status}");
    let called: Vec<&str> = said
        .lines()
        .chain(status.lines())
        .filter(|l| l.contains(&host_short) && l.contains("anchor"))
        .collect();
    assert!(
        called.is_empty(),
        "PRODUCT: the guest called its host {host_short}, a member of the room, an anchor: \
         {called:?}"
    );
}
