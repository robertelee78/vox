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
use world::{args, echo_service, round_trip, vox_once, PathKind, Setup, World};

#[test]
#[ignore = "real binaries, production Argon2id and a PoW; CI runs it in release"]
fn status_names_a_relayed_path_and_its_relay() {
    watchdog::arm();
    let port = echo_service();
    let w = World::build(&Setup {
        specs: vec![port.to_string()],
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
        assert!(ok, "PRODUCT: the guest's `vox status --json` failed: {out}{err}");
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
