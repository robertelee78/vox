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
//! **A red names its side.** The report's content is PRODUCT. A `vox` step that fails while the
//! world is set is PRODUCT (staging), as the harness labels it; the test's own sockets and
//! processes are APPARATUS.
//!
//! ## Why it is `#[ignore]`d
//! Production Argon2id on three profiles and a real ADR-005 proof of work. CI runs it in release.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/world.rs"]
mod world;

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
