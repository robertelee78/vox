//! R35, #406 — **`vox status` reports the datagrams of a flow left on a retired connection**,
//! through the shipped binary.
//!
//! A UDP flow stays on the connection it began on when another connection to the same peer
//! displaces it; the displaced one is retired, not closed, and keeps carrying the flow until it is
//! done. `vox status` counted only the primary connection, so it said no datagram moved while the
//! flow carried them (udp_tunnel_proof's fragmentation check then could not measure, about one
//! run in three, whenever the tie-break between two connections retired the one in use).
//!
//! What this drives: a host sharing a UDP echo service, a guest that forwards to it by address
//! (`vox forward <port>.<host>.<room>.vox`), and a datagram through the forward. Both daemons run
//! with the test-only `VOX_TEST_SUPERSEDE_CARRYING` (the `test-knobs` feature, V210-105): once a
//! connection carries datagrams, each dials its peer again and files the new connection as the
//! primary, retiring the old one, **every run** rather than when the tie-break happens to. Each
//! daemon says it did (`vox: test-knob: superseded …`), which is checked: a run where it did not
//! is `CANNOT MEASURE`. Then more datagrams cross, still on the retired connection, and **each
//! end's `vox status` must list datagrams sent and delivered between them**.
//!
//! **Mutation that must turn it red every time:** the status counting the primary connection
//! only (the `retiring_to` loop in `NodeActor::status_report` dropped) — red as `PRODUCT: … lists
//! no datagram`.

#![cfg(unix)]

#[path = "support/test_knobs.rs"]
mod test_knobs;
#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;
#[path = "support/world.rs"]
mod world;

use std::net::UdpSocket;
use std::path::Path;
use std::time::{Duration, Instant};

use world::{args, log_tail, vox_once, PathKind, Setup, World};

const KNOB: &str = "VOX_TEST_SUPERSEDE_CARRYING";

/// A UDP echo service on loopback: its port.
fn udp_echo() -> u16 {
    let s = UdpSocket::bind("127.0.0.1:0").expect("APPARATUS: bind the echo service");
    let port = s.local_addr().expect("APPARATUS: its port").port();
    std::thread::spawn(move || {
        let mut buf = [0u8; 65536];
        while let Ok((n, from)) = s.recv_from(&mut buf) {
            let _ = s.send_to(&buf[..n], from);
        }
    });
    port
}

/// Send `payload` from `s` through the forward at `at` until it comes back, within `within`. One
/// socket for the whole proof: one source port is one flow (a new one would be a new tunnel, and
/// a member has at most sixteen).
fn echoed(s: &UdpSocket, at: std::net::SocketAddr, payload: &[u8], within: Duration) -> bool {
    let deadline = Instant::now() + within;
    let mut buf = [0u8; 65536];
    while Instant::now() < deadline {
        let _ = s.send_to(payload, at);
        if let Ok((n, _)) = s.recv_from(&mut buf) {
            if &buf[..n] == payload {
                return true;
            }
        }
    }
    false
}

/// Datagrams sent and delivered on every connection `dir`'s status lists toward `peer`, and those
/// entries as JSON.
fn moved_toward(dir: &Path, peer: &str) -> (u64, String) {
    let (ok, out, err) = vox_once(dir, &args(&["status", "--json"]));
    assert!(ok, "PRODUCT: `vox status --json` failed: {out}\n{err}");
    let v: serde_json::Value = serde_json::from_str(&out).unwrap_or_else(|e| {
        panic!("PRODUCT: `vox status --json` printed something that is not JSON ({e}): {out}")
    });
    let toward: Vec<serde_json::Value> = v["peers"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter(|p| p["id"] == peer)
        .collect();
    let moved = toward
        .iter()
        .map(|p| {
            p["datagrams"]["sent"].as_u64().unwrap_or(0)
                + p["datagrams"]["delivered"].as_u64().unwrap_or(0)
        })
        .sum();
    (moved, serde_json::to_string(&toward).unwrap_or_default())
}

/// Whether `dir`'s daemon said it superseded a connection (its log), or `transcript` did.
fn superseded(dir: &Path, transcript: &str) -> bool {
    let said = |t: &str| t.contains("vox: test-knob: superseded the connection");
    said(transcript)
        || std::fs::read_to_string(dir.join(".daemon").join("log")).is_ok_and(|t| said(&t))
}

#[test]
#[ignore = "real vox processes and production Argon2id; CI runs it in release"]
fn status_reports_the_datagrams_of_a_flow_on_a_retired_connection() {
    test_knobs::require(&[KNOB]);
    watchdog::arm();
    // Every daemon this test starts, and every client that starts one, inherits it: this file is
    // one test, so its own process.
    std::env::set_var(KNOB, "1");
    let echo = udp_echo();
    let mut w = World::build(&Setup {
        specs: vec![format!("{echo}={echo}/udp")],
        trusted: true,
        path: PathKind::Direct,
        guest_leg: None,
    });
    let guest = w.guest_dir.clone();
    let (mut fwd, at) = w.forward_service("forward", &guest, &format!("{echo}/udp"));
    let client = UdpSocket::bind("127.0.0.1:0").expect("APPARATUS: bind the client socket");
    client
        .set_read_timeout(Some(Duration::from_millis(500)))
        .expect("APPARATUS: socket timeout");

    // The first datagrams make each daemon supersede the connection carrying them.
    assert!(
        echoed(
            &client,
            at,
            b"first, on the connection the flow began on",
            Duration::from_secs(60)
        ),
        "PRODUCT (staging): no datagram came back through the UDP forward.\n{}",
        fwd.transcript()
    );
    let host_dir = w.host_dir.clone();
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let host_text = w.host.as_mut().map(|h| h.transcript()).unwrap_or_default();
        if superseded(&host_dir, &host_text) && superseded(&guest, "") {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "CANNOT MEASURE: the daemons did not both supersede the connection carrying the flow \
             (host: {}, guest: {}), so no flow was left on a retired connection",
            superseded(&host_dir, &host_text),
            superseded(&guest, "")
        );
        let _ = echoed(&client, at, b"again, to be carried", Duration::from_secs(1));
        std::thread::sleep(Duration::from_millis(200));
    }

    // More of the flow, still on the retired connection.
    for i in 0..20 {
        let payload = format!("after the supersede, datagram {i}");
        assert!(
            echoed(&client, at, payload.as_bytes(), Duration::from_secs(10)),
            "PRODUCT: the flow stopped once its connection was retired: datagram {i} never came \
             back.\n{}\n---- the host's daemon ----\n{}\n{}\n---- the guest's daemon ----\n{}",
            fwd.transcript(),
            w.host.as_mut().map(|h| h.transcript()).unwrap_or_default(),
            log_tail(&host_dir, 80),
            log_tail(&guest, 80)
        );
    }

    // Each end's status reports the datagrams the flow carried.
    let deadline = Instant::now() + Duration::from_secs(5);
    let (host_moved, host_json, guest_moved, guest_json) = loop {
        let (h, hj) = moved_toward(&host_dir, &w.guest_fp);
        let (g, gj) = moved_toward(&guest, &w.host_fp);
        if (h > 0 && g > 0) || Instant::now() >= deadline {
            break (h, hj, g, gj);
        }
        std::thread::sleep(Duration::from_millis(250));
    };
    eprintln!(
        "[proof] the host's status moved {host_moved} datagram(s) toward the guest: {host_json}\n\
         [proof] the guest's status moved {guest_moved} toward the host: {guest_json}"
    );
    assert!(
        host_moved > 0 && guest_moved > 0,
        "PRODUCT: a UDP flow carried datagrams both ways on a retired connection, and `vox status` \
         lists no datagram on {} — it does not report the connection that carried them (R35).\n\
         host toward guest: {host_json}\nguest toward host: {guest_json}",
        match (host_moved, guest_moved) {
            (0, 0) => "either end",
            (0, _) => "the host",
            _ => "the guest",
        }
    );
}
