//! **`vox status` shows what the node is doing, and its UDP flows each apart** — PRD-001 R35
//! (#84) and V030-34 (#383, ADR-022 6.9), driven through the shipped `vox` binary.
//!
//! **The staging — real processes only.** A `vox node` anchor on `[::]`, a host on IPv6 loopback
//! and a guest on IPv4 loopback (`support/world.rs`, `PathKind::Relayed`): the only path between
//! them is a circuit the anchor carries. The guest's leg to the anchor runs through a UDP proxy
//! the proof owns, which loses every 10th datagram once switched on — the relay leg drops what it
//! drops. The host serves a UDP sink and a TCP echo, trusts the guest, and is restarted as
//! `vox daemon --metrics 127.0.0.1:0`, so its counters are also served as Prometheus text.
//!
//! **#383: each UDP flow's counts, in `vox status --json` and the metrics.** The guest runs
//! `vox forward <sink>.<host>.<room>.vox` (a `<sink>/udp` service), opens the flow, and then
//! sends [`SENT`] numbered datagrams with the loss switched on. Asserted, against the flow's counts before the blast:
//! - the guest's `vox status --json` lists the flow, and its `to` grew by exactly [`SENT`] (`N`);
//! - the host's lists the guest's flow, and its `from` grew by exactly what the sink received:
//!   `N − M`, where `M` is what the relay leg lost, and `M > 0`;
//! - the host's metrics endpoint shows `vox_udp_flow_from_peer` for that flow equal to the
//!   host's status, and `vox_udp_flow_to_peer` / `vox_udp_flow_dropped` beside it.
//!
//! **#84: `vox status` (the person's form) lists** the room and its last sync, the guest as a
//! peer with its path (`relayed via` the anchor), the live tunnel a TCP connection through a
//! second forward holds, the UDP flow with its counts, and — once the guest stops — the trusted
//! member it can no longer reach, flagged `UNHEALTHY`.
//!
//! **Every red names its side**: `PRODUCT`, `PRODUCT (staging)`, `APPARATUS` or `CANNOT MEASURE`.
//!
//! **Mutations that must turn it red, as PRODUCT:** the status report built with no UDP flows
//! (`udp_flows: Vec::new()` in `NodeActor::status_report`) — no flow listed; every peer reported
//! `direct` — no `relayed via`; `StatusReport::diagnose` finding nothing — no `UNHEALTHY`.
//!
//! It replaces `ops_status_proof`, deleted with the in-process gates (V29-17).

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/world.rs"]
mod world;

use std::io::{Read, Write};
use std::net::{TcpStream, UdpSocket};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::Value;
use world::{args, lossy_proxy, vox_once, PathKind, Setup, World};

/// Numbered datagrams sent with the relay leg's loss on.
const SENT: u64 = 300;
/// One every this long: slow enough that no local queue overflows (CLIENT_QUEUE), so every loss
/// is the relay leg's.
const EVERY: Duration = Duration::from_millis(10);

/// `vox status --json` of the node on `dir`, parsed.
fn status_json(dir: &std::path::Path, who: &str) -> Value {
    let (ok, out, err) = vox_once(dir, &args(&["status", "--json"]));
    assert!(
        ok,
        "PRODUCT: {who}'s `vox status --json` did not answer.\nstdout:\n{out}\nstderr:\n{err}"
    );
    serde_json::from_str(&out).unwrap_or_else(|e| {
        panic!("PRODUCT: {who}'s `vox status --json` is not JSON ({e}):\n{out}")
    })
}

/// `vox status` of the node on `dir`, as a person reads it.
fn status_text(dir: &std::path::Path, who: &str) -> String {
    let (ok, out, err) = vox_once(dir, &args(&["status"]));
    assert!(
        ok,
        "PRODUCT: {who}'s `vox status` did not answer.\nstdout:\n{out}\nstderr:\n{err}"
    );
    out
}

/// The UDP flow with `peer` for the service on `port`, in a status report: (to, from, dropped).
fn flow(report: &Value, peer: &str, port: u16) -> Option<(u64, u64, u64)> {
    report
        .get("udp_flows")?
        .as_array()?
        .iter()
        .find(|f| {
            f.get("peer").and_then(Value::as_str) == Some(peer)
                && f.get("service")
                    .and_then(Value::as_str)
                    .is_some_and(|s| s.contains(&port.to_string()))
        })
        .map(|f| {
            let n = |k: &str| f.get(k).and_then(Value::as_u64).unwrap_or(0);
            (n("to"), n("from"), n("dropped"))
        })
}

/// `GET /metrics` at `addr`: the body.
fn scrape(addr: &str) -> String {
    let mut s = TcpStream::connect(addr)
        .unwrap_or_else(|e| panic!("PRODUCT: nothing answers at the metrics address {addr}: {e}"));
    s.set_read_timeout(Some(Duration::from_secs(10))).ok();
    s.write_all(format!("GET /metrics HTTP/1.0\r\nHost: {addr}\r\n\r\n").as_bytes())
        .unwrap_or_else(|e| panic!("PRODUCT: the metrics endpoint at {addr} took no request: {e}"));
    let mut got = String::new();
    s.read_to_string(&mut got)
        .unwrap_or_else(|e| panic!("PRODUCT: the metrics endpoint at {addr} did not answer: {e}"));
    got.split_once("\r\n\r\n")
        .map_or(got.clone(), |(_, body)| body.to_owned())
}

/// The value of `name{…peer="<peer>"…service="…<port>…"}` in Prometheus text.
fn metric(body: &str, name: &str, peer: &str, port: u16) -> Option<u64> {
    body.lines()
        .filter(|l| l.starts_with(&format!("{name}{{")))
        .find(|l| l.contains(&format!("peer=\"{peer}\"")) && l.contains(&port.to_string()))
        .and_then(|l| l.rsplit(' ').next()?.parse().ok())
}

/// A TCP echo on loopback: what the guest's second forward reaches, so a tunnel is live.
fn echo() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap_or_else(|e| panic!("APPARATUS: no TCP port for the echo: {e}"));
    let port = l.local_addr().map(|a| a.port()).unwrap_or_default();
    std::thread::spawn(move || {
        for s in l.incoming() {
            let Ok(mut s) = s else { continue };
            std::thread::spawn(move || {
                let mut buf = [0u8; 4096];
                while let Ok(n) = s.read(&mut buf) {
                    if n == 0 || s.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
            });
        }
    });
    port
}

#[test]
#[ignore = "real binaries, production Argon2id and a PoW; run in release"]
fn vox_status_shows_rooms_peers_tunnels_udp_flows_and_what_is_unhealthy() {
    watchdog::arm();
    // ---- the sink: counts each numbered datagram it receives ----
    let sink = UdpSocket::bind("127.0.0.1:0")
        .unwrap_or_else(|e| panic!("APPARATUS: no UDP port for the sink: {e}"));
    let sink_port = sink.local_addr().map(|a| a.port()).unwrap_or_default();
    let received = Arc::new(AtomicU64::new(0));
    {
        let received = Arc::clone(&received);
        std::thread::spawn(move || {
            let mut buf = [0u8; 2048];
            while let Ok((n, _)) = sink.recv_from(&mut buf) {
                if n >= 4 {
                    received.fetch_add(1, Ordering::SeqCst);
                }
            }
        });
    }
    let echo_port = echo();
    type Knob = Option<(Arc<AtomicU64>, Arc<AtomicU64>)>;
    let lossy: Arc<Mutex<Knob>> = Arc::default();
    let lossy_in = Arc::clone(&lossy);
    let mut w = World::build(&Setup {
        specs: vec![
            format!("{sink_port}={sink_port}/udp"),
            format!("{echo_port}={echo_port}"),
        ],
        trusted: true,
        path: PathKind::Relayed,
        guest_leg: Some(Box::new(move |anchor| {
            let (addr, dropped, knob, _) = lossy_proxy(anchor, Duration::ZERO);
            *lossy_in
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some((dropped, knob));
            Some(addr)
        })),
    });
    w.restart_host_as_daemon_with(&["--metrics", "127.0.0.1:0"]);
    let metrics_at = w
        .host
        .as_mut()
        .map(world::VoxProc::transcript)
        .unwrap_or_default()
        .lines()
        .find_map(|l| l.strip_prefix("vox daemon: metrics http://"))
        .map(|a| a.trim_end_matches("/metrics").to_owned())
        .unwrap_or_else(|| {
            panic!(
                "PRODUCT (staging): the host's `vox daemon --metrics` never said where it serves"
            )
        });
    let guest = w.guest_dir.clone();
    let host = w.host_dir.clone();

    // ---- open the UDP flow, the loss still off ----
    let (mut fwd, at) = w.forward_service("udp-forward", &guest, &format!("{sink_port}/udp"));
    let client = UdpSocket::bind("127.0.0.1:0")
        .unwrap_or_else(|e| panic!("APPARATUS: no UDP port for the client: {e}"));
    let deadline = Instant::now() + Duration::from_secs(120);
    while received.load(Ordering::SeqCst) == 0 && Instant::now() < deadline {
        let _ = client.send_to(&0u32.to_be_bytes(), at);
        std::thread::sleep(Duration::from_millis(200));
    }
    assert!(
        received.load(Ordering::SeqCst) > 0,
        "PRODUCT (staging): no datagram crossed the UDP forward in 120 s.\nthe forward said:\n{}",
        fwd.transcript()
    );
    std::thread::sleep(Duration::from_secs(1));

    // ---- the counts before, then N numbered datagrams with the relay leg losing every 10th ----
    let guest_before = flow(&status_json(&guest, "the guest"), &w.host_fp, sink_port);
    let host_before = flow(&status_json(&host, "the host"), &w.guest_fp, sink_port);
    let (Some(guest_before), Some(host_before)) = (guest_before, host_before) else {
        panic!(
            "PRODUCT: a UDP flow is carrying datagrams, yet `vox status --json` does not list it: \
             the guest's flow to the host {guest_before:?}, the host's from the guest \
             {host_before:?}.\nguest:\n{}\nhost:\n{}",
            status_json(&guest, "the guest"),
            status_json(&host, "the host")
        );
    };
    let sink_before = received.load(Ordering::SeqCst);
    let (leg_dropped, knob) = lossy
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
        .unwrap_or_else(|| panic!("APPARATUS: the lossy relay leg was never built"));
    let leg_before = leg_dropped.load(Ordering::SeqCst);
    knob.store(10, Ordering::SeqCst);
    let start = Instant::now();
    for seq in 1..=SENT {
        let mut d = u32::try_from(seq)
            .unwrap_or(u32::MAX)
            .to_be_bytes()
            .to_vec();
        d.resize(200, 0);
        client
            .send_to(&d, at)
            .unwrap_or_else(|e| panic!("APPARATUS: the client could not send datagram {seq}: {e}"));
        let next = start + EVERY * u32::try_from(seq).unwrap_or(u32::MAX);
        if let Some(wait) = next.checked_duration_since(Instant::now()) {
            std::thread::sleep(wait);
        }
    }
    std::thread::sleep(Duration::from_secs(2));
    knob.store(0, Ordering::SeqCst);
    let arrived = received.load(Ordering::SeqCst) - sink_before;
    let leg_lost = leg_dropped.load(Ordering::SeqCst) - leg_before;

    let guest_report = status_json(&guest, "the guest");
    let host_report = status_json(&host, "the host");
    let guest_after = flow(&guest_report, &w.host_fp, sink_port);
    let host_after = flow(&host_report, &w.guest_fp, sink_port);
    let body = scrape(&metrics_at);
    let m_from = metric(&body, "vox_udp_flow_from_peer", &w.guest_fp, sink_port);
    let m_to = metric(&body, "vox_udp_flow_to_peer", &w.guest_fp, sink_port);
    let m_dropped = metric(&body, "vox_udp_flow_dropped", &w.guest_fp, sink_port);
    eprintln!(
        "[proof] sent {SENT}; the sink received {arrived}; the relay leg dropped {leg_lost} packet(s). \
         guest flow before {guest_before:?} after {guest_after:?}; host flow before {host_before:?} \
         after {host_after:?}; host metrics to {m_to:?} from {m_from:?} dropped {m_dropped:?}"
    );
    let (Some(guest_after), Some(host_after)) = (guest_after, host_after) else {
        panic!(
            "PRODUCT: the UDP flow left `vox status --json` while it was live: guest \
             {guest_after:?}, host {host_after:?}.\nguest:\n{guest_report}\nhost:\n{host_report}"
        );
    };
    let lost = SENT.saturating_sub(arrived);
    assert!(
        lost > 0,
        "CANNOT MEASURE: the relay leg dropped {leg_lost} packet(s), none of them a datagram the \
         sink was waiting for ({arrived} of {SENT} arrived), so no M to show"
    );
    assert!(
        guest_after.0 - guest_before.0 == SENT,
        "PRODUCT: the guest sent {SENT} datagrams on the flow, yet its `vox status --json` counts \
         {} more `to` ({guest_before:?} → {guest_after:?})",
        guest_after.0 - guest_before.0
    );
    assert!(
        host_after.1 - host_before.1 == arrived,
        "PRODUCT: {arrived} of {SENT} datagrams reached the service ({lost} lost at the relay), yet \
         the host's `vox status --json` counts {} more `from` ({host_before:?} → {host_after:?})",
        host_after.1 - host_before.1
    );
    assert!(
        m_from == Some(host_after.1) && m_to.is_some() && m_dropped.is_some(),
        "PRODUCT: the host's metrics endpoint must show the flow's counts as its status does \
         (from {}): to {m_to:?}, from {m_from:?}, dropped {m_dropped:?}.\n{body}",
        host_after.1
    );

    // ---- #84: the person's `vox status`, first with the UDP flow live ----
    let text = status_text(&host, "the host");
    eprintln!("[proof] the host's `vox status` with the UDP flow live:\n{text}");
    let g = &w.guest_fp[..12];
    let anchor_short = w
        .host_anchor
        .split('@')
        .next()
        .map(|a| a[..12.min(a.len())].to_owned())
        .unwrap_or_default();
    let room_short = &w.room[..12];
    let mut missing = Vec::new();
    let room_line = text
        .lines()
        .find(|l| l.trim_start().starts_with(room_short) && l.contains("last sync"));
    if room_line.is_none_or(|l| l.contains("last sync never")) {
        missing.push(format!(
            "the room {room_short} with a last sync (line: {room_line:?})"
        ));
    }
    if !text.lines().any(|l| {
        l.trim_start().starts_with(g) && l.contains(&format!("relayed via {anchor_short}"))
    }) {
        missing.push(format!(
            "the guest {g} as a peer, relayed via {anchor_short}"
        ));
    }
    if !text.lines().any(|l| {
        l.contains(&sink_port.to_string())
            && l.contains(&format!("with {g}"))
            && l.contains(&format!("from {}", host_after.1))
    }) {
        missing.push(format!(
            "the UDP flow with {g} on {sink_port}, from {}",
            host_after.1
        ));
    }
    assert!(
        missing.is_empty(),
        "PRODUCT: the host's `vox status` does not show {}.\n{text}",
        missing.join("; ")
    );
    assert!(
        text.contains("healthy: nothing needs attention"),
        "PRODUCT: with its guest connected and synced, the host's `vox status` flags something:\n{text}"
    );

    // ---- then with a TCP tunnel live: one vox holds a profile, so the UDP forward goes first ----
    drop(fwd);
    let (tcp_fwd, tcp_at) = w.forward_service("tcp-forward", &guest, &echo_port.to_string());
    let mut held = TcpStream::connect(tcp_at)
        .unwrap_or_else(|e| panic!("PRODUCT (staging): the TCP forward took no connection: {e}"));
    held.set_read_timeout(Some(Duration::from_secs(60))).ok();
    held.write_all(b"held")
        .unwrap_or_else(|e| panic!("PRODUCT (staging): the TCP forward took no bytes: {e}"));
    let mut back = [0u8; 4];
    held.read_exact(&mut back)
        .unwrap_or_else(|e| panic!("PRODUCT (staging): no echo through the TCP forward: {e}"));
    let text = status_text(&host, "the host");
    eprintln!("[proof] the host's `vox status` with a TCP tunnel live:\n{text}");
    assert!(
        text.lines()
            .any(|l| l.starts_with("tunnel ") && l.contains(&format!("from {g}"))),
        "PRODUCT: a TCP connection from the guest {g} is live through the host, yet the host's \
         `vox status` lists no tunnel from it:\n{text}"
    );

    // ---- the guest goes away: the trusted member it cannot reach is flagged ----
    drop(held);
    drop(tcp_fwd);
    let deadline = Instant::now() + Duration::from_secs(120);
    let mut text = String::new();
    while Instant::now() < deadline {
        text = status_text(&host, "the host");
        if text.contains("UNHEALTHY:") {
            break;
        }
        std::thread::sleep(Duration::from_secs(2));
    }
    eprintln!("[proof] the host's `vox status` with the guest gone:\n{text}");
    assert!(
        text.contains("UNHEALTHY:")
            && text
                .lines()
                .any(|l| l.contains(&format!("trusted member {g} unreachable"))),
        "PRODUCT: the host's trusted guest {g} went away, yet in 120 s `vox status` never flagged \
         it unreachable:\n{text}"
    );
}
