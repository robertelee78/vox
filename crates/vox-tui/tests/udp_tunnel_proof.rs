//! **UDP crosses Vox** (ADR-022 M22.3 and M22.4, PRD-001 R25–R26), proved by running the
//! product: real `vox` processes, real UDP sockets, and `dig`.
//!
//! Every property runs on two paths:
//!
//! - **direct** — everyone on IPv4 loopback, so the guest dials the host straight;
//! - **relayed** — the host on IPv6 loopback only, the guest on IPv4 loopback only and the
//!   anchor on both, so no packet can pass between guest and host except through a circuit
//!   the anchor carries. The anchor reporting a carried circuit is checked, not assumed.
//!
//! The proofs are ADR-022's:
//!
//! 1. **DNS** — `dig` through a `53/udp`-style forward to a DNS responder gets the answer.
//! 2. **Denied** — a joiner the host never trusted gets no answer, and the service sees
//!    zero packets.
//! 3. **Revocation** — a query loop stops being answered within 1 s of `vox trust remove`.
//! 4. **Oversize** — 1400- and 4000-byte payloads cross intact, in fragments.
//! 5. **Relay drops, not stalls** — over a relay leg that loses every 10th datagram, what
//!    the leg drops stays lost (so nothing waits behind its retransmission); the gaps and
//!    latencies are recorded. Relayed path only: it is a property of the relay.
//! 6. **TCP and UDP on the same port** both answer, each its own service.
//!
//! and M22.4's SOCKS5 `UDP ASSOCIATE` in `vox up`: `.vox` destinations only, `FRAG ≠ 0`
//! dropped, and the association gone with its TCP control connection.
//!
//! No real DNS server is installed here, so the service `dig` asks is a small responder in
//! this file that answers every `A` query with 10.53.0.1 and counts what it receives; `dig`
//! is the real one. `iperf3` is not installed either, so proof 5's blaster and sink are here
//! too, and report loss and the longest gap.
//!
//! ## Why it is `#[ignore]`d
//! Production Argon2id on three profiles and a real ADR-005 proof of work per world, and
//! the harness's 35 s wait for D8 (see `support/world.rs`). CI runs it in release.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/world.rs"]
mod world;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use world::{args, lossy_proxy, vox_once, PathKind, Setup, World};

/// What the test DNS responder answers every `A` query with.
const ANSWER: [u8; 4] = [10, 53, 0, 1];

/// A DNS responder on UDP loopback: answers every query with one `A` record, [`ANSWER`].
/// Returns its port and how many packets it has received.
fn dns_responder() -> (u16, Arc<AtomicU64>) {
    let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = sock.local_addr().unwrap().port();
    let seen = Arc::new(AtomicU64::new(0));
    let counted = Arc::clone(&seen);
    std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        while let Ok((n, from)) = sock.recv_from(&mut buf) {
            counted.fetch_add(1, Ordering::Relaxed);
            if let Some(reply) = dns_answer(&buf[..n]) {
                let _ = sock.send_to(&reply, from);
            }
        }
    });
    (port, seen)
}

/// A response to `query`: its ID and question, and one `A` record.
fn dns_answer(query: &[u8]) -> Option<Vec<u8>> {
    if query.len() < 12 {
        return None;
    }
    // The question ends after the name's zero label and 4 bytes of type and class.
    let mut i = 12;
    while *query.get(i)? != 0 {
        i += 1 + usize::from(query[i]);
    }
    let question = query.get(12..i + 5)?;
    let mut r = Vec::with_capacity(64);
    r.extend_from_slice(&query[..2]); // id
    r.extend_from_slice(&[0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0]); // flags, 1 q, 1 answer
    r.extend_from_slice(question);
    r.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4]);
    r.extend_from_slice(&ANSWER);
    Some(r)
}

/// A service on the **same port** over TCP and UDP, each answering with its own prefix
/// so a proof can tell which one replied: TCP echoes `TCP:<data>`, UDP `UDP:<data>`.
/// Returns the port and the count of UDP packets received.
fn dual_echo() -> (u16, Arc<AtomicU64>) {
    loop {
        let tcp = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = tcp.local_addr().unwrap().port();
        let Ok(udp) = UdpSocket::bind(("127.0.0.1", port)) else {
            continue;
        };
        std::thread::spawn(move || {
            for stream in tcp.incoming() {
                let Ok(mut s) = stream else { continue };
                std::thread::spawn(move || {
                    let mut buf = [0u8; 4096];
                    while let Ok(n) = s.read(&mut buf) {
                        if n == 0 {
                            break;
                        }
                        let mut out = b"TCP:".to_vec();
                        out.extend_from_slice(&buf[..n]);
                        if s.write_all(&out).is_err() {
                            break;
                        }
                    }
                });
            }
        });
        let seen = Arc::new(AtomicU64::new(0));
        let counted = Arc::clone(&seen);
        std::thread::spawn(move || {
            let mut buf = vec![0u8; 65_535];
            while let Ok((n, from)) = udp.recv_from(&mut buf) {
                counted.fetch_add(1, Ordering::Relaxed);
                let mut out = b"UDP:".to_vec();
                out.extend_from_slice(&buf[..n]);
                let _ = udp.send_to(&out, from);
            }
        });
        return (port, seen);
    }
}

/// `dig` against `at`, once. `Some(answer)` when it printed one.
fn dig(at: SocketAddr) -> Option<String> {
    let out = Command::new("dig")
        .args([
            &format!("@{}", at.ip()),
            "-p",
            &at.port().to_string(),
            "proof.vox.test",
            "A",
            "+short",
            "+time=3",
            "+tries=1",
        ])
        .output()
        .expect("dig is installed");
    let text = String::from_utf8_lossy(&out.stdout).trim().to_owned();
    (out.status.success() && !text.is_empty() && !text.starts_with(';')).then_some(text)
}

/// Ask `dig` until it answers or `within` passes. Returns the answer and how many asks it
/// took, so a proof can print both.
fn dig_until(at: SocketAddr, within: Duration) -> (Option<String>, u32) {
    let deadline = Instant::now() + within;
    let mut tries = 0;
    while Instant::now() < deadline {
        tries += 1;
        if let Some(a) = dig(at) {
            return (Some(a), tries);
        }
    }
    (None, tries)
}

fn world(specs: Vec<String>, trusted: bool, path: PathKind) -> World {
    World::build(&Setup {
        specs,
        trusted,
        path,
        guest_leg: None,
    })
}

/// On a relayed world, check the topology really forbids a direct path rather than
/// assume it: every address the host advertises in its `vox://` address must be IPv6,
/// while the guest runs on IPv4 loopback only, so no packet can pass between them except
/// through the anchor. The anchor's own circuit count is printed as well; it is not
/// asserted, because it is sampled every 500 ms and a short run can finish between samples.
fn check_path(w: &mut World) {
    let host_addrs: Vec<String> = {
        let query = w.address.split('?').nth(1).unwrap_or_default();
        let pairs: Vec<(&str, &str)> = query
            .split('&')
            .filter_map(|kv| kv.split_once('='))
            .collect();
        pairs
            .windows(2)
            .filter(|p| p[0] == ("a", w.host_fp.as_str()) && p[1].0 == "b")
            .map(|p| p[1].1.to_owned())
            .collect()
    };
    let said = w.anchor.transcript();
    let most = said
        .lines()
        .filter_map(|l| l.split(" peer(s) connected, ").nth(1))
        .filter_map(|l| l.split(' ').next()?.parse::<u32>().ok())
        .max()
        .unwrap_or(0);
    eprintln!(
        "[test] path {:?}: the host advertises {host_addrs:?}; the anchor reported at most \
         {most} circuit(s) carried",
        w.path
    );
    if w.path == PathKind::Relayed {
        assert!(
            !host_addrs.is_empty() && host_addrs.iter().all(|a| a.starts_with("/ip6/")),
            "a relayed world's host must advertise IPv6 addresses only, or the guest could \
             reach it directly: {host_addrs:?} in {}",
            w.address
        );
    }
}

/// SOCKS5 to `proxy`: no-auth greeting, then `UDP ASSOCIATE`. Returns the control
/// connection (the association lives as long as it does) and the relay address.
fn socks_associate(proxy: SocketAddr) -> (TcpStream, SocketAddr) {
    let mut s = TcpStream::connect(proxy).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
    s.write_all(&[5, 1, 0]).unwrap();
    let mut hello = [0u8; 2];
    s.read_exact(&mut hello).unwrap();
    assert_eq!(hello, [5, 0]);
    // UDP ASSOCIATE, from "anywhere" (all zeroes, which RFC 1928 allows).
    s.write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0]).unwrap();
    let mut head = [0u8; 4];
    s.read_exact(&mut head).unwrap();
    assert_eq!(
        head[1], 0,
        "UDP ASSOCIATE must succeed, got code {}",
        head[1]
    );
    assert_eq!(head[3], 1, "an IPv4 relay address");
    let mut a = [0u8; 6];
    s.read_exact(&mut a).unwrap();
    let relay = SocketAddr::from(([a[0], a[1], a[2], a[3]], u16::from_be_bytes([a[4], a[5]])));
    (s, relay)
}

/// An RFC 1928 §7 datagram to `name:port`.
fn socks_udp(frag: u8, name: &str, port: u16, data: &[u8]) -> Vec<u8> {
    let mut d = vec![0, 0, frag, 3, u8::try_from(name.len()).unwrap()];
    d.extend_from_slice(name.as_bytes());
    d.extend_from_slice(&port.to_be_bytes());
    d.extend_from_slice(data);
    d
}

/// Strip an RFC 1928 §7 header off a reply, asserting it names `name:port`.
fn socks_payload<'a>(reply: &'a [u8], name: &str, port: u16) -> &'a [u8] {
    assert_eq!(&reply[..4], &[0, 0, 0, 3], "a domain-addressed reply");
    let len = usize::from(reply[4]);
    assert_eq!(&reply[5..5 + len], name.as_bytes(), "from the name asked");
    assert_eq!(&reply[5 + len..7 + len], &port.to_be_bytes());
    &reply[7 + len..]
}

/// Proofs 1, 4 and 6, and M22.4, in one world.
fn serves_udp(path: PathKind) {
    watchdog::arm();
    let (dns, dns_seen) = dns_responder();
    let (dual, dual_udp_seen) = dual_echo();
    let mut w = world(
        vec![
            format!("{dns}/udp"),
            dual.to_string(),
            format!("{dual}/udp"),
        ],
        true,
        path,
    );
    let guest = w.guest_dir.clone();

    // ---- proof 1: dig through a UDP forward ----
    let (fwd, at) = w.forward_vox("forward", &guest, &format!("{dns}/udp"));
    let t0 = Instant::now();
    let (answer, tries) = dig_until(at, Duration::from_secs(120));
    eprintln!(
        "[test] proof 1 ({path:?}): dig answered {answer:?} after {tries} ask(s), {:?}; the \
         responder saw {} packet(s)",
        t0.elapsed(),
        dns_seen.load(Ordering::Relaxed)
    );
    assert_eq!(
        answer.as_deref(),
        Some("10.53.0.1"),
        "dig through `vox forward <room>.vox {dns}/udp` must get the responder's answer"
    );
    // And every later query is answered first time: the flow is up.
    let answered = (0..5).filter(|_| dig(at).is_some()).count();
    eprintln!("[test] proof 1 ({path:?}): {answered}/5 further queries answered");
    assert_eq!(answered, 5, "a live UDP flow must answer every query");
    drop(fwd);

    // ---- vox up: TCP and UDP on the same port (proof 6), oversize (proof 4), M22.4 ----
    let (_up, proxy) = w.up("up", &guest);
    let name = format!("{}.vox", w.room);
    let mut tcp = TcpStream::connect(proxy).unwrap();
    tcp.set_read_timeout(Some(Duration::from_secs(330)))
        .unwrap();
    tcp.write_all(&[5, 1, 0]).unwrap();
    let mut hello = [0u8; 2];
    tcp.read_exact(&mut hello).unwrap();
    let mut req = vec![5, 1, 0, 3, u8::try_from(name.len()).unwrap()];
    req.extend_from_slice(name.as_bytes());
    req.extend_from_slice(&dual.to_be_bytes());
    tcp.write_all(&req).unwrap();
    let mut head = [0u8; 10];
    tcp.read_exact(&mut head).unwrap();
    assert_eq!(head[1], 0, "the TCP service on port {dual} must be reached");
    tcp.write_all(b"same port").unwrap();
    let mut back = [0u8; 13];
    tcp.read_exact(&mut back).unwrap();

    let (control, relay) = socks_associate(proxy);
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut buf = vec![0u8; 65_535];
    let mut ask = |data: &[u8]| -> Option<Vec<u8>> {
        client
            .send_to(&socks_udp(0, &name, dual, data), relay)
            .unwrap();
        let (n, _) = client.recv_from(&mut buf).ok()?;
        Some(socks_payload(&buf[..n], &name, dual).to_vec())
    };
    // The first datagram opens the flow; allow it a few tries while the tunnel opens.
    let first = (0..20).find_map(|_| ask(b"same port"));
    eprintln!(
        "[test] proof 6 ({path:?}): TCP {:?}, UDP {:?}",
        String::from_utf8_lossy(&back),
        first.as_deref().map(String::from_utf8_lossy)
    );
    assert_eq!(
        &back, b"TCP:same port",
        "TCP {dual} answers as the TCP service"
    );
    assert_eq!(
        first.as_deref(),
        Some(&b"UDP:same port"[..]),
        "UDP {dual} answers as the UDP service, through UDP ASSOCIATE"
    );

    // Proof 4: payloads larger than one datagram, byte for byte.
    let mut intact = 0;
    for size in [1400usize, 4000] {
        let payload: Vec<u8> = (0..size).map(|i| u8::try_from(i % 251).unwrap()).collect();
        let got = ask(&payload);
        let ok = got
            .as_ref()
            .is_some_and(|g| g[..4] == *b"UDP:" && g[4..] == payload[..]);
        eprintln!(
            "[test] proof 4 ({path:?}): {size}-byte payload came back {}",
            match &got {
                Some(g) if ok => format!("intact ({} bytes)", g.len() - 4),
                Some(g) => format!("CORRUPT ({} bytes)", g.len()),
                None => "NOT AT ALL".to_owned(),
            }
        );
        intact += usize::from(ok);
    }
    assert_eq!(intact, 2, "both oversize payloads must cross intact");

    // M22.4: FRAG ≠ 0 is dropped, and never reaches the service.
    let before = dual_udp_seen.load(Ordering::Relaxed);
    client
        .send_to(&socks_udp(1, &name, dual, b"a fragment"), relay)
        .unwrap();
    std::thread::sleep(Duration::from_secs(2));
    let after = dual_udp_seen.load(Ordering::Relaxed);
    eprintln!(
        "[test] M22.4 ({path:?}): FRAG=1 datagram reached the service {} time(s)",
        after - before
    );
    assert_eq!(
        after, before,
        "a SOCKS datagram with FRAG ≠ 0 must be dropped"
    );

    // M22.4: the association dies with its TCP control connection.
    drop(control);
    std::thread::sleep(Duration::from_secs(2));
    let before = dual_udp_seen.load(Ordering::Relaxed);
    let _ = client.send_to(&socks_udp(0, &name, dual, b"after close"), relay);
    let late = client.recv_from(&mut buf).ok().map(|(n, _)| n);
    let after = dual_udp_seen.load(Ordering::Relaxed);
    eprintln!(
        "[test] M22.4 ({path:?}): after the control connection closed, the service saw {} \
         packet(s) and the client got {late:?}",
        after - before
    );
    assert_eq!(
        after, before,
        "the association must end with its control connection"
    );
    assert!(late.is_none(), "nothing may answer on a closed association");

    check_path(&mut w);
}

#[test]
#[ignore = "real binaries, production Argon2id and a PoW; CI runs it in release"]
fn udp_is_carried_on_a_direct_path() {
    serves_udp(PathKind::Direct);
}

#[test]
#[ignore = "real binaries, production Argon2id and a PoW; CI runs it in release"]
fn udp_is_carried_on_a_relayed_path() {
    serves_udp(PathKind::Relayed);
}

/// Proof 2.
fn denied(path: PathKind) {
    watchdog::arm();
    let (dns, dns_seen) = dns_responder();
    let mut w = world(vec![format!("{dns}/udp")], false, path);
    let guest = w.guest_dir.clone();
    let (mut fwd, at) = w.forward_vox("stranger-forward", &guest, &format!("{dns}/udp"));
    let (answer, tries) = dig_until(at, Duration::from_secs(15));
    let seen = dns_seen.load(Ordering::Relaxed);
    eprintln!(
        "[test] proof 2 ({path:?}): {tries} dig(s), answer {answer:?}, the service saw {seen} \
         packet(s)"
    );
    assert!(answer.is_none(), "an untrusted joiner must get no answer");
    assert_eq!(
        seen, 0,
        "the host's service must see zero packets from an untrusted joiner"
    );
    let why = fwd.expect_within(Duration::from_secs(10), "the refusal, on stderr", |l| {
        l.starts_with("! ") && l.contains("the host refused")
    });
    eprintln!("[test] proof 2 ({path:?}): the forward said: {why}");
    check_path(&mut w);
}

#[test]
#[ignore = "real binaries, production Argon2id and a PoW; CI runs it in release"]
fn an_untrusted_joiner_reaches_no_udp_service_direct() {
    denied(PathKind::Direct);
}

#[test]
#[ignore = "real binaries, production Argon2id and a PoW; CI runs it in release"]
fn an_untrusted_joiner_reaches_no_udp_service_relayed() {
    denied(PathKind::Relayed);
}

/// Proof 3: a query loop on one flow, and `vox trust remove` on the host mid-loop.
fn revocation(path: PathKind) {
    watchdog::arm();
    let (dns, _) = dns_responder();
    let mut w = world(vec![format!("{dns}/udp")], true, path);
    // `vox trust remove` must reach the running host, which `vox serve` cannot be asked.
    w.restart_host_as_daemon();
    let guest = w.guest_dir.clone();
    let (_fwd, at) = w.forward_vox("forward", &guest, &format!("{dns}/udp"));
    let (answer, _) = dig_until(at, Duration::from_secs(180));
    assert!(
        answer.is_some(),
        "the flow must answer before trust is withdrawn"
    );

    // One client socket, one flow, a query every 50 ms, and every answer timestamped.
    let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    sock.set_read_timeout(Some(Duration::from_millis(50)))
        .unwrap();
    let answers: Arc<Mutex<Vec<Instant>>> = Arc::default();
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let looper = {
        let (answers, stop) = (Arc::clone(&answers), Arc::clone(&stop));
        std::thread::spawn(move || {
            let query = hex_query();
            let mut buf = [0u8; 512];
            while !stop.load(Ordering::Relaxed) {
                let _ = sock.send_to(&query, at);
                if sock.recv_from(&mut buf).is_ok() {
                    answers.lock().unwrap().push(Instant::now());
                }
            }
        })
    };
    let deadline = Instant::now() + Duration::from_secs(60);
    while answers.lock().unwrap().len() < 10 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    let before = answers.lock().unwrap().len();
    assert!(
        before >= 10,
        "the loop must be answered before the revocation: {before}"
    );

    let asked = Instant::now();
    let (ok, out, err) = vox_once(&w.host_dir, &args(&["trust", "remove", &w.guest_fp]));
    let removed = Instant::now();
    let last_before = answers.lock().unwrap().last().copied();
    eprintln!(
        "[test] proof 3 ({path:?}): `vox trust remove` took {:?} (it checks the identity \
         passphrase); the last answer before it returned came {:?} after it was typed",
        removed.duration_since(asked),
        last_before.map(|t| t.saturating_duration_since(asked))
    );
    assert!(ok, "`vox trust remove` on the running host: {out}\n{err}");
    std::thread::sleep(Duration::from_secs(3));
    stop.store(true, Ordering::Relaxed);
    looper.join().unwrap();
    let all = answers.lock().unwrap().clone();
    let after: Vec<Duration> = all
        .iter()
        .filter(|t| **t > removed)
        .map(|t| t.duration_since(removed))
        .collect();
    let last = after.iter().max().copied();
    eprintln!(
        "[test] proof 3 ({path:?}): {before} answers before `vox trust remove`, {} after it, \
         the last {last:?} after",
        after.len()
    );
    assert!(
        last.is_none_or(|l| l <= Duration::from_secs(1)),
        "answers must stop within 1 s of `vox trust remove`; the last came {last:?} after"
    );
    check_path(&mut w);
}

/// A fixed `A` query for `proof.vox.test`.
fn hex_query() -> Vec<u8> {
    let mut q = vec![0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in ["proof", "vox", "test"] {
        q.push(u8::try_from(label.len()).unwrap());
        q.extend_from_slice(label.as_bytes());
    }
    q.extend_from_slice(&[0, 0, 1, 0, 1]);
    q
}

#[test]
#[ignore = "real binaries, production Argon2id and a PoW; CI runs it in release"]
fn untrusting_the_dialer_stops_its_udp_within_a_second_direct() {
    revocation(PathKind::Direct);
}

#[test]
#[ignore = "real binaries, production Argon2id and a PoW; CI runs it in release"]
fn untrusting_the_dialer_stops_its_udp_within_a_second_relayed() {
    revocation(PathKind::Relayed);
}

/// How often proof 5's blaster sends, how many, and how many it ignores at the start
/// while congestion control settles on the new loss rate (ADR-022 M22.2 measured one
/// early hold of up to ~80 ms as the outer window falls to its floor).
const BLAST_EVERY: Duration = Duration::from_millis(10);
const BLAST_COUNT: u32 = 400;
const BLAST_WARMUP: u32 = 100;

/// Proof 5: a relay leg that loses every 10th datagram, 20 ms each way; a numbered stream
/// through a UDP forward; the sink reports loss and the longest gap between arrivals.
#[test]
#[ignore = "real binaries, production Argon2id and a PoW; CI runs it in release"]
fn a_lossy_relay_leg_loses_udp_instead_of_stalling_it() {
    watchdog::arm();
    // The sink: records each numbered datagram's arrival.
    let sink = UdpSocket::bind("127.0.0.1:0").unwrap();
    let sink_port = sink.local_addr().unwrap().port();
    let arrivals: Arc<Mutex<Vec<(u32, Instant)>>> = Arc::default();
    {
        let arrivals = Arc::clone(&arrivals);
        std::thread::spawn(move || {
            let mut buf = [0u8; 2048];
            while let Ok((n, _)) = sink.recv_from(&mut buf) {
                if n >= 4 {
                    let seq = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
                    arrivals.lock().unwrap().push((seq, Instant::now()));
                }
            }
        });
    }
    type Knobs = Option<(Arc<AtomicU64>, Arc<AtomicU64>)>;
    let lossy: Arc<Mutex<Knobs>> = Arc::default();
    let lossy_in = Arc::clone(&lossy);
    let mut w = World::build(&Setup {
        specs: vec![format!("{sink_port}/udp")],
        trusted: true,
        path: PathKind::Relayed,
        guest_leg: Some(Box::new(move |anchor| {
            let (addr, count, knob) = lossy_proxy(anchor, Duration::from_millis(20));
            *lossy_in.lock().unwrap() = Some((count, knob));
            Some(addr)
        })),
    });
    let guest = w.guest_dir.clone();
    let (_fwd, at) = w.forward_vox("forward", &guest, &format!("{sink_port}/udp"));

    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    // Open the flow: seq 0 until the sink hears one.
    let deadline = Instant::now() + Duration::from_secs(300);
    while arrivals.lock().unwrap().is_empty() && Instant::now() < deadline {
        client.send_to(&0u32.to_be_bytes(), at).unwrap();
        std::thread::sleep(Duration::from_millis(200));
    }
    assert!(
        !arrivals.lock().unwrap().is_empty(),
        "the flow never opened"
    );
    arrivals.lock().unwrap().clear();
    // The loss starts now, not during setup: joining over a lossy leg is its own open
    // defect (ADR-018, a joining node holding its actor for 30 s), and this proof is about
    // what the relay does to traffic, not about joining.
    let (dropped, knob) = lossy.lock().unwrap().clone().unwrap();
    knob.store(10, Ordering::Relaxed);
    // And congestion control is given the loss to settle on before anything is measured:
    // both connections' windows fall to their floor within the first second or so of a new
    // loss rate and hold datagrams while they do (ADR-022 M22.2), which is a reaction to
    // loss and not the carriage this proof is about. Three seconds of the same traffic,
    // unmeasured.
    let warm = Instant::now();
    for seq in 0..300u32 {
        let mut d = u32::MAX.to_be_bytes().to_vec();
        d.resize(200, 0);
        client.send_to(&d, at).unwrap();
        if let Some(wait) = (warm + BLAST_EVERY * (seq + 1)).checked_duration_since(Instant::now())
        {
            std::thread::sleep(wait);
        }
    }
    std::thread::sleep(Duration::from_millis(500));
    arrivals.lock().unwrap().clear();
    let proxy_drops_before = dropped.load(Ordering::Relaxed);

    let start = Instant::now();
    for seq in 1..=BLAST_COUNT {
        let mut d = seq.to_be_bytes().to_vec();
        d.resize(200, 0);
        client.send_to(&d, at).unwrap();
        let next = start + BLAST_EVERY * seq;
        if let Some(wait) = next.checked_duration_since(Instant::now()) {
            std::thread::sleep(wait);
        }
    }
    std::thread::sleep(Duration::from_secs(2));
    let got = arrivals.lock().unwrap().clone();
    let proxy_drops = dropped.load(Ordering::Relaxed) - proxy_drops_before;
    let received = got.len();
    let measured: Vec<&(u32, Instant)> = got.iter().filter(|(s, _)| *s > BLAST_WARMUP).collect();
    let max_gap = measured
        .windows(2)
        .map(|p| p[1].1.duration_since(p[0].1))
        .max()
        .unwrap_or_default();
    let mut gaps: Vec<Duration> = measured
        .windows(2)
        .map(|p| p[1].1.duration_since(p[0].1))
        .collect();
    gaps.sort();
    let p99 = gaps.get(gaps.len() * 99 / 100).copied().unwrap_or_default();
    eprintln!(
        "[test] proof 5: sent {BLAST_COUNT}, received {received}, lost {}; the lossy leg \
         dropped {proxy_drops} datagram(s); after the first {BLAST_WARMUP}: longest gap \
         {max_gap:?}, 99th percentile {p99:?}",
        BLAST_COUNT as usize - received.min(BLAST_COUNT as usize)
    );
    // One-way latency of each datagram: arrival less its scheduled send time. A stall
    // shows as latency climbing and then a burst arriving together; loss without a stall
    // leaves the latency of everything that did arrive flat.
    let mut lat: Vec<(u32, Duration)> = measured
        .iter()
        .map(|(s, t)| (*s, t.saturating_duration_since(start + BLAST_EVERY * *s)))
        .collect();
    lat.sort_by_key(|(_, l)| *l);
    let pct = |p: usize| {
        lat.get(lat.len() * p / 100)
            .map(|x| x.1)
            .unwrap_or_default()
    };
    eprintln!(
        "[test] proof 5: latency p1 {:?} p50 {:?} p99 {:?} max {:?}; gap p50 {:?}",
        pct(1),
        pct(50),
        pct(99),
        lat.last().map(|x| x.1).unwrap_or_default(),
        gaps.get(gaps.len() / 2).copied().unwrap_or_default()
    );
    check_path(&mut w);
    assert!(
        proxy_drops > 0,
        "the lossy leg must actually have dropped something, or this measured nothing"
    );
    // **Every dropped datagram stays dropped**, which is the whole claim: nothing
    // retransmits it, so nothing can be held behind its retransmission. With the stream
    // carriage restored as a mutation, the outer stream retransmits every loss — 400 of 400
    // arrive — and later datagrams wait behind each one. The proxy also drops the outer
    // connection's own packets (acknowledgements, the inner handshake's), so not every one
    // of its drops costs a numbered datagram; at least half must.
    //
    // The gaps and latencies are printed, not bounded: congestion control on the outer and
    // inner connections, reacting to a 10% loss rate, holds and releases datagrams on its
    // own schedule (ADR-022 "Negative"), and under a loaded machine those holds reach
    // ~100 ms with no stream anywhere in the path.
    let lost = BLAST_COUNT as usize - received.min(BLAST_COUNT as usize);
    assert!(
        lost as u64 * 2 >= proxy_drops,
        "a relay must lose what the lossy leg drops, not recover it: {lost} lost for \
         {proxy_drops} dropped on the leg"
    );
}
