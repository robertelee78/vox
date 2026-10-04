//! PRD-001 R38 — **`vox daemon --metrics` binds loopback only, and its gauges follow the node**,
//! proved with the shipped binary (#227: the claims `ops_status_proof` carried in-process until
//! `a1d01323`).
//!
//! 1. **Loopback only.** The counters name every peer and room this node holds, so a daemon asked
//!    to serve them where the network can reach them (`--metrics 0.0.0.0:0`) must refuse to start,
//!    exit non-zero and say the endpoint binds loopback only.
//! 2. **The gauges move.** alice's daemon serves metrics on loopback. Before anyone joins her room
//!    she has no connected peer and no completed sync. bob, on his own daemon, joins the room and
//!    posts; then alice's endpoint must count a connected peer (`vox_peers_connected` ≥ 1) and a
//!    completed sync in the room (`vox_room_last_sync_seconds{room=…}` > 0).
//!
//! **A red names its side.** What the endpoint or the daemon says is PRODUCT; a `vox` step that
//! fails while the scene is set is PRODUCT (staging), as the shared harness labels it; not reaching
//! the address the daemon named is CANNOT MEASURE; the test's own processes are APPARATUS.
//!
//! **Mutations.** The loopback check removed from `bind_metrics`: the daemon starts, and (1) goes
//! red. `vox_peers_connected` fixed at 0: (2) goes red.

#![cfg(unix)]

#[path = "support/sync_pair.rs"]
mod sync_pair;

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::io::{Read as _, Write as _};
use std::time::{Duration, Instant};

use sync_pair::{Member, Proc};

/// `vox daemon --listen 127.0.0.1:0 --metrics <metrics>` on `m`'s profile.
fn daemon_with_metrics(m: &Member, metrics: &str) -> Proc {
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_vox"))
        .args([
            "daemon",
            "--listen",
            "127.0.0.1:0",
            "--metrics",
            metrics,
            "--passphrase-file",
            m.pass.to_str().expect("APPARATUS: a UTF-8 path"),
        ])
        .env("VOX_DATA_DIR", &m.dir)
        .env("VOX_CONFIG_DIR", m.dir.join("cfg"))
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("APPARATUS: could not spawn {}'s daemon: {e}", m.name));
    let said = sync_pair::drain(&mut child);
    Proc { child, said }
}

/// The first line of `p`'s output that `pred` accepts, waiting up to 60 s for it.
fn line_from(p: &mut Proc, what: &str, pred: impl Fn(&str) -> bool) -> String {
    let until = Instant::now() + Duration::from_secs(60);
    loop {
        if let Some(l) = p
            .transcript()
            .lines()
            .find(|l| pred(l.trim_start_matches("! ")))
        {
            return l.trim_start_matches("! ").to_owned();
        }
        assert!(
            Instant::now() < until,
            "PRODUCT (staging): the daemon never said {what} ({}):\n{}",
            p.state(),
            p.transcript()
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// One scrape of `addr`'s `/metrics`: the body.
fn scrape(addr: &str) -> String {
    let mut sock = std::net::TcpStream::connect(addr).unwrap_or_else(|e| {
        panic!("CANNOT MEASURE: the address the daemon named, {addr}, refused: {e}")
    });
    sock.set_read_timeout(Some(Duration::from_secs(10)))
        .expect("APPARATUS: a read timeout");
    sock.write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .expect("APPARATUS: write a request to a connection just made");
    let mut got = String::new();
    let read = sock.read_to_string(&mut got);
    assert!(
        read.is_ok() && got.starts_with("HTTP/1.1 200"),
        "PRODUCT: the metrics endpoint must answer a scrape: {read:?} {got:?}"
    );
    got.split_once("\r\n\r\n")
        .map(|(_, b)| b.to_owned())
        .unwrap_or_default()
}

/// The value of the sample `name` (with its label set, if any) in a scrape's body.
fn sample(body: &str, name: &str) -> Option<u64> {
    body.lines()
        .filter(|l| !l.starts_with('#'))
        .find_map(|l| l.strip_prefix(name)?.strip_prefix(' ')?.trim().parse().ok())
}

#[test]
#[ignore = "a real vox daemon with production Argon2id; CI runs it in release"]
fn a_metrics_endpoint_the_network_could_reach_is_refused() {
    watchdog::arm();
    let tmp = tempfile::tempdir().expect("APPARATUS: a temp dir");
    let alice = Member::new(tmp.path(), "alice");
    let mut daemon = daemon_with_metrics(&alice, "0.0.0.0:0");
    let until = Instant::now() + Duration::from_secs(60);
    let status = loop {
        if let Ok(Some(s)) = daemon.child.try_wait() {
            break Some(s);
        }
        if Instant::now() >= until {
            break None;
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    let said = daemon.transcript();
    eprintln!("[proof] `vox daemon --metrics 0.0.0.0:0`: exit {status:?}; said:\n{said}");
    assert!(
        status.is_some_and(|s| !s.success()),
        "PRODUCT: a daemon asked to serve metrics on 0.0.0.0 must refuse to start"
    );
    assert!(
        said.contains("loopback only"),
        "PRODUCT: the refusal must say the endpoint binds loopback only"
    );
}

#[test]
#[ignore = "real vox daemons with production Argon2id; CI runs it in release"]
fn the_metrics_count_a_connected_peer_and_a_completed_sync() {
    watchdog::arm();
    let tmp = tempfile::tempdir().expect("APPARATUS: a temp dir");
    let alice = Member::new(tmp.path(), "alice");
    let bob = Member::new(tmp.path(), "bob");
    let mut alice_daemon = daemon_with_metrics(&alice, "127.0.0.1:0");
    let said = line_from(&mut alice_daemon, "the metrics address", |l| {
        l.starts_with("vox daemon: metrics http://")
    });
    let addr = said
        .trim_start_matches("vox daemon: metrics http://")
        .trim_end_matches("/metrics")
        .trim()
        .to_owned();
    // The daemon answers `vox room list` once it is up.
    let until = Instant::now() + Duration::from_secs(90);
    while !alice.vox(&["room", "list"], None).0 {
        assert!(
            Instant::now() < until,
            "PRODUCT (staging): alice's daemon never answered `vox room list`:\n{}",
            alice_daemon.transcript()
        );
        std::thread::sleep(Duration::from_millis(250));
    }
    let room = alice.create("metrics");
    let room_b32 = alice.status()["rooms"]
        .as_array()
        .and_then(|rs| rs.iter().find(|r| r["name"] == "metrics"))
        .and_then(|r| r["id"].as_str())
        .map(str::to_owned)
        .unwrap_or_else(|| panic!("PRODUCT (staging): alice's report lists the room"));
    let last_sync = format!("vox_room_last_sync_seconds{{room=\"{room_b32}\"}}");
    let before = scrape(&addr);
    let (peers0, sync0) = (
        sample(&before, "vox_peers_connected"),
        sample(&before, &last_sync),
    );

    let _bob_daemon = bob.daemon(None);
    alice.trust(&bob);
    bob.trust(&alice);
    bob.join(&alice.invite(&room), "metrics");
    bob.post(&room, "hello from bob");

    let until = Instant::now() + Duration::from_secs(90);
    let after = loop {
        let body = scrape(&addr);
        let moved = sample(&body, "vox_peers_connected").is_some_and(|n| n >= 1)
            && sample(&body, &last_sync).is_some_and(|t| t > 0);
        if moved || Instant::now() >= until {
            break body;
        }
        std::thread::sleep(Duration::from_millis(500));
    };
    let (peers1, sync1) = (
        sample(&after, "vox_peers_connected"),
        sample(&after, &last_sync),
    );
    eprintln!(
        "[proof] before bob joined: vox_peers_connected {peers0:?}, {last_sync} {sync0:?}\n\
         after: vox_peers_connected {peers1:?}, {last_sync} {sync1:?}"
    );
    assert_eq!(
        (peers0, sync0),
        (Some(0), Some(0)),
        "PRODUCT: before anyone joined, alice has no connected peer and no completed sync"
    );
    assert!(
        peers1.is_some_and(|n| n >= 1),
        "PRODUCT: once bob has joined, alice's endpoint must count a connected peer"
    );
    assert!(
        sync1.is_some_and(|t| t > 0),
        "PRODUCT: once bob has joined and posted, alice's endpoint must show a completed sync"
    );
}
