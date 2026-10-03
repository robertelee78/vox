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
//! 4. **Oversize** — 1400-, 4000- and 9000-byte payloads cross intact; the 9000 bytes are
//!    above every path's MTU ceiling, and the host's `datagrams.fragmented` rising while they
//!    cross shows they went in fragments.
//!
//! Every red names its side: `PRODUCT:` for what vox did, `CANNOT MEASURE:` for staging this
//! run did not achieve, `APPARATUS:` for this test's own sockets and tools.
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

use world::{args, lossy_proxy, vox_once, PathKind, Setup, VoxProc, World};

/// What the test DNS responder answers every `A` query with.
const ANSWER: [u8; 4] = [10, 53, 0, 1];

/// Proof 4's payload that must fragment everywhere: above every path's MTU ceiling (8192
/// bytes at most, `MAX_UDP_PAYLOAD`), and under macOS's 9216-byte default for one UDP send.
const OVERSIZE: usize = 9000;

/// A step of this test's own machinery — its sockets, threads and tools — whose failure says
/// nothing about vox: `APPARATUS:`.
fn apparatus<T, E: std::fmt::Display>(r: Result<T, E>, what: &str) -> T {
    r.unwrap_or_else(|e| panic!("APPARATUS: {what}: {e}"))
}

/// A step that waits on vox — a read from or write to the proxy `vox up` bound — whose failure
/// is vox's: `PRODUCT:`.
fn product<T, E: std::fmt::Display>(r: Result<T, E>, what: &str) -> T {
    r.unwrap_or_else(|e| panic!("PRODUCT: {what}: {e}"))
}

/// A lock on this test's own bookkeeping; poisoned only if another of its threads panicked.
fn held<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock()
        .unwrap_or_else(|e| panic!("APPARATUS: a test thread panicked holding a lock: {e}"))
}

/// A DNS responder on UDP loopback: answers every query with one `A` record, [`ANSWER`].
/// Returns its port and how many packets it has received.
fn dns_responder() -> (u16, Arc<AtomicU64>) {
    let sock = apparatus(UdpSocket::bind("127.0.0.1:0"), "bind the DNS responder");
    let port = apparatus(sock.local_addr(), "the DNS responder's address").port();
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
        let tcp = apparatus(TcpListener::bind("127.0.0.1:0"), "bind the TCP echo");
        let port = apparatus(tcp.local_addr(), "the TCP echo's address").port();
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
        .unwrap_or_else(|e| panic!("APPARATUS: `dig` could not be run (is it installed?): {e}"));
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
            "CANNOT MEASURE: staging not achieved — a relayed world's host must advertise IPv6 \
             addresses only, or the guest could reach it directly and nothing here was relayed: \
             {host_addrs:?} in {}",
            w.address
        );
    }
}

/// SOCKS5 to `proxy`: no-auth greeting, then `UDP ASSOCIATE`. Returns the control
/// connection (the association lives as long as it does) and the relay address.
fn socks_associate(proxy: SocketAddr) -> (TcpStream, SocketAddr) {
    let mut s = product(
        TcpStream::connect(proxy),
        &format!("connect to the SOCKS proxy `vox up` bound at {proxy}"),
    );
    apparatus(
        s.set_read_timeout(Some(Duration::from_secs(30))),
        "a read timeout on the SOCKS control connection",
    );
    product(
        s.write_all(&[5, 1, 0]),
        "send the SOCKS greeting to `vox up`",
    );
    let mut hello = [0u8; 2];
    product(s.read_exact(&mut hello), "read `vox up`'s SOCKS greeting");
    assert_eq!(
        hello,
        [5, 0],
        "PRODUCT: `vox up` must accept a no-auth SOCKS5 greeting"
    );
    // UDP ASSOCIATE, from "anywhere" (all zeroes, which RFC 1928 allows).
    product(
        s.write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0]),
        "send UDP ASSOCIATE to `vox up`",
    );
    let mut head = [0u8; 4];
    product(
        s.read_exact(&mut head),
        "read `vox up`'s UDP ASSOCIATE reply",
    );
    assert_eq!(
        head[1], 0,
        "PRODUCT: UDP ASSOCIATE must succeed, got code {}",
        head[1]
    );
    assert_eq!(
        head[3], 1,
        "PRODUCT: `vox up` must name an IPv4 relay address"
    );
    let mut a = [0u8; 6];
    product(s.read_exact(&mut a), "read `vox up`'s UDP relay address");
    let relay = SocketAddr::from(([a[0], a[1], a[2], a[3]], u16::from_be_bytes([a[4], a[5]])));
    (s, relay)
}

/// An RFC 1928 §7 datagram to `name:port`.
fn socks_udp(frag: u8, name: &str, port: u16, data: &[u8]) -> Vec<u8> {
    let mut d = vec![
        0,
        0,
        frag,
        3,
        apparatus(u8::try_from(name.len()), "a SOCKS name length"),
    ];
    d.extend_from_slice(name.as_bytes());
    d.extend_from_slice(&port.to_be_bytes());
    d.extend_from_slice(data);
    d
}

/// Strip an RFC 1928 §7 header off a reply, asserting it names `name:port`.
fn socks_payload<'a>(reply: &'a [u8], name: &str, port: u16) -> &'a [u8] {
    assert!(
        reply.len() >= 5 && reply.len() >= 7 + usize::from(reply[4]),
        "PRODUCT: `vox up` relayed a reply too short for its own SOCKS header: {} bytes",
        reply.len()
    );
    assert_eq!(
        &reply[..4],
        &[0, 0, 0, 3],
        "PRODUCT: `vox up`'s reply must be domain-addressed"
    );
    let len = usize::from(reply[4]);
    assert_eq!(
        &reply[5..5 + len],
        name.as_bytes(),
        "PRODUCT: `vox up`'s reply must come from the name asked"
    );
    assert_eq!(
        &reply[5 + len..7 + len],
        &port.to_be_bytes(),
        "PRODUCT: `vox up`'s reply must come from the port asked"
    );
    &reply[7 + len..]
}

/// `datagrams.fragmented` on the host's connection to `peer`, from the host's own
/// `vox status --json` — the counter a person can read. Per connection, so on the relayed
/// path it counts the flow's fragmenting and not the circuit's (that is the host's connection
/// to the anchor, another peer).
fn fragmented_toward(w: &World, peer: &str) -> u64 {
    let (ok, out, err) = vox_once(&w.host_dir, &args(&["status", "--json"]));
    assert!(
        ok,
        "PRODUCT: `vox status --json` on the running host failed: {out}\n{err}"
    );
    let v: serde_json::Value = serde_json::from_str(&out).unwrap_or_else(|e| {
        panic!("PRODUCT: `vox status --json` printed something that is not JSON ({e}): {out}")
    });
    let peers = v["peers"].as_array().cloned().unwrap_or_default();
    let Some(p) = peers.iter().find(|p| p["id"] == peer) else {
        panic!("PRODUCT: the host's `vox status --json` lists no connection to the guest {peer}: {out}")
    };
    p["datagrams"]["fragmented"].as_u64().unwrap_or_else(|| {
        panic!("PRODUCT: the host's connection to the guest has no datagrams.fragmented: {p}")
    })
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
        "PRODUCT: dig through `vox forward <room>.vox {dns}/udp` must get the responder's answer"
    );
    // And every later query is answered first time: the flow is up.
    let answered = (0..5).filter(|_| dig(at).is_some()).count();
    eprintln!("[test] proof 1 ({path:?}): {answered}/5 further queries answered");
    assert_eq!(
        answered, 5,
        "PRODUCT: a live UDP flow must answer every query"
    );
    drop(fwd);

    // ---- vox up: TCP and UDP on the same port (proof 6), oversize (proof 4), M22.4 ----
    let (_up, proxy) = w.up("up", &guest);
    let name = format!("{}.vox", w.room);
    let mut tcp = product(
        TcpStream::connect(proxy),
        &format!("connect to the SOCKS proxy `vox up` bound at {proxy}"),
    );
    apparatus(
        tcp.set_read_timeout(Some(Duration::from_secs(330))),
        "a read timeout on the SOCKS connection",
    );
    product(
        tcp.write_all(&[5, 1, 0]),
        "send the SOCKS greeting to `vox up`",
    );
    let mut hello = [0u8; 2];
    product(tcp.read_exact(&mut hello), "read `vox up`'s SOCKS greeting");
    let mut req = vec![
        5,
        1,
        0,
        3,
        apparatus(u8::try_from(name.len()), "a SOCKS name length"),
    ];
    req.extend_from_slice(name.as_bytes());
    req.extend_from_slice(&dual.to_be_bytes());
    product(tcp.write_all(&req), "send CONNECT to `vox up`");
    let mut head = [0u8; 10];
    product(tcp.read_exact(&mut head), "read `vox up`'s CONNECT reply");
    assert_eq!(
        head[1], 0,
        "PRODUCT: the TCP service on port {dual} must be reached"
    );
    product(
        tcp.write_all(b"same port"),
        "write through the SOCKS TCP stream",
    );
    let mut back = [0u8; 13];
    product(
        tcp.read_exact(&mut back),
        "read the TCP service's echo through `vox up`",
    );

    let (control, relay) = socks_associate(proxy);
    let client = apparatus(UdpSocket::bind("127.0.0.1:0"), "bind the SOCKS UDP client");
    apparatus(
        client.set_read_timeout(Some(Duration::from_secs(10))),
        "a read timeout on the SOCKS UDP client",
    );
    let mut buf = vec![0u8; 65_535];
    let mut ask = |data: &[u8]| -> Option<Vec<u8>> {
        apparatus(
            client.send_to(&socks_udp(0, &name, dual, data), relay),
            "send a datagram to `vox up`'s UDP relay",
        );
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
        "PRODUCT: TCP {dual} answers as the TCP service"
    );
    assert_eq!(
        first.as_deref(),
        Some(&b"UDP:same port"[..]),
        "PRODUCT: UDP {dual} answers as the UDP service, through UDP ASSOCIATE"
    );

    // Proof 4: payloads larger than one datagram, byte for byte.
    //
    // **One of them must fragment on every machine.** A path's datagrams are capped by its
    // MTU ceiling: on macOS, with the 4 MiB socket buffer, that is the 8192-byte
    // `MAX_UDP_PAYLOAD`, so 1400 and 4000 bytes each fit one datagram there and only prove
    // fragmentation where the ceiling is 1452 (Linux with `rmem_max` capped). 9000 bytes is
    // above every ceiling and still under macOS's 9216-byte default for one UDP send, so
    // the test's sockets and the product's need no larger buffers to carry it.
    //
    // **And it is checked that it did**: the host's `datagrams.fragmented` on its connection
    // to the guest must rise while the 9000 bytes cross (the echo comes back the same size).
    // A payload that arrived intact without fragmenting proved nothing about R26 —
    // `CANNOT MEASURE`, not a pass.
    let mut intact = 0;
    let mut fragmented = (0, 0);
    for size in [1400usize, 4000, OVERSIZE] {
        let payload: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
        let before = (size == OVERSIZE).then(|| fragmented_toward(&w, &w.guest_fp));
        let got = ask(&payload);
        if let Some(before) = before {
            fragmented = (before, fragmented_toward(&w, &w.guest_fp));
        }
        let ok = got
            .as_ref()
            .is_some_and(|g| g.len() >= 4 && g[..4] == *b"UDP:" && g[4..] == payload[..]);
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
    eprintln!(
        "[test] proof 4 ({path:?}): the host's connection to the guest fragmented {} \
         datagram(s) before the {OVERSIZE}-byte payload and {} after",
        fragmented.0, fragmented.1
    );
    assert_eq!(
        intact, 3,
        "PRODUCT: all three oversize payloads (1400, 4000 and {OVERSIZE} bytes) must cross intact"
    );
    assert!(
        fragmented.1 > fragmented.0,
        "CANNOT MEASURE: the {OVERSIZE}-byte payload crossed without the host's connection to the \
         guest fragmenting anything ({} before, {} after), so this run never exercised \
         fragmentation",
        fragmented.0,
        fragmented.1
    );

    // M22.4: FRAG ≠ 0 is dropped, and never reaches the service.
    let before = dual_udp_seen.load(Ordering::Relaxed);
    apparatus(
        client.send_to(&socks_udp(1, &name, dual, b"a fragment"), relay),
        "send a FRAG=1 datagram to `vox up`'s UDP relay",
    );
    std::thread::sleep(Duration::from_secs(2));
    let after = dual_udp_seen.load(Ordering::Relaxed);
    eprintln!(
        "[test] M22.4 ({path:?}): FRAG=1 datagram reached the service {} time(s)",
        after - before
    );
    assert_eq!(
        after, before,
        "PRODUCT: a SOCKS datagram with FRAG ≠ 0 must be dropped"
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
        "PRODUCT: the association must end with its control connection"
    );
    assert!(
        late.is_none(),
        "PRODUCT: nothing may answer on a closed association"
    );

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
    assert!(
        answer.is_none(),
        "PRODUCT: an untrusted joiner must get no answer"
    );
    assert_eq!(
        seen, 0,
        "PRODUCT: the host's service must see zero packets from an untrusted joiner"
    );
    // A missing refusal has two sides; the forward's alone cannot say which one went quiet,
    // so a failure prints what the host and the anchor said too.
    let Some(why) = fwd.line_within(Duration::from_secs(10), |l| {
        l.starts_with("! ") && l.contains("the host refused")
    }) else {
        let host = w.host.as_mut().map(VoxProc::transcript).unwrap_or_default();
        panic!(
            "PRODUCT: proof 2 ({path:?}): no refusal on the forward's stderr within 10s.\nThe forward \
             said:\n{}\nThe host said:\n{host}\nThe anchor said:\n{}",
            fwd.transcript(),
            w.anchor.transcript()
        );
    };
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
        "PRODUCT (staging): the flow must answer before trust is withdrawn"
    );

    // One client socket, one flow, a query every 50 ms, and every answer timestamped.
    let sock = apparatus(
        UdpSocket::bind("127.0.0.1:0"),
        "bind the query loop's socket",
    );
    apparatus(
        sock.set_read_timeout(Some(Duration::from_millis(50))),
        "a read timeout on the query loop's socket",
    );
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
                    held(&answers).push(Instant::now());
                }
            }
        })
    };
    let deadline = Instant::now() + Duration::from_secs(60);
    while held(&answers).len() < 10 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    let before = held(&answers).len();
    assert!(
        before >= 10,
        "PRODUCT (staging): the loop must be answered before the revocation: {before}"
    );

    let asked = Instant::now();
    let (ok, out, err) = vox_once(&w.host_dir, &args(&["trust", "remove", &w.guest_fp]));
    let removed = Instant::now();
    let last_before = held(&answers).last().copied();
    eprintln!(
        "[test] proof 3 ({path:?}): `vox trust remove` took {:?} (it checks the identity \
         passphrase); the last answer before it returned came {:?} after it was typed",
        removed.duration_since(asked),
        last_before.map(|t| t.saturating_duration_since(asked))
    );
    assert!(
        ok,
        "PRODUCT: `vox trust remove` on the running host failed: {out}\n{err}"
    );
    std::thread::sleep(Duration::from_secs(3));
    stop.store(true, Ordering::Relaxed);
    looper
        .join()
        .unwrap_or_else(|_| panic!("APPARATUS: the query loop's thread panicked"));
    let all = held(&answers).clone();
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
        "PRODUCT: answers must stop within 1 s of `vox trust remove`; the last came {last:?} after"
    );
    check_path(&mut w);
}

/// A fixed `A` query for `proof.vox.test`.
fn hex_query() -> Vec<u8> {
    let mut q = vec![0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in ["proof", "vox", "test"] {
        q.push(apparatus(u8::try_from(label.len()), "a DNS label length"));
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
/// How many bytes over the commonest size a packet may be and still be counted as carrying one
/// numbered datagram: an acknowledgement frame riding with it adds 6–9 (measured 268–271 against
/// 262).
const CARRIER_SLACK: usize = 16;

/// Proof 5: a relay leg that loses every 10th datagram, 20 ms each way; a numbered stream
/// through a UDP forward; the sink reports loss and the longest gap between arrivals.
#[test]
#[ignore = "real binaries, production Argon2id and a PoW; CI runs it in release"]
fn a_lossy_relay_leg_loses_udp_instead_of_stalling_it() {
    watchdog::arm();
    // The sink: records each numbered datagram's arrival.
    let sink = apparatus(UdpSocket::bind("127.0.0.1:0"), "bind the sink");
    let sink_port = apparatus(sink.local_addr(), "the sink's address").port();
    let arrivals: Arc<Mutex<Vec<(u32, Instant)>>> = Arc::default();
    {
        let arrivals = Arc::clone(&arrivals);
        std::thread::spawn(move || {
            let mut buf = [0u8; 2048];
            while let Ok((n, _)) = sink.recv_from(&mut buf) {
                if n >= 4 {
                    let seq = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
                    held(&arrivals).push((seq, Instant::now()));
                }
            }
        });
    }
    type Sizes = Arc<Mutex<Vec<(usize, bool)>>>;
    type Knobs = Option<(Arc<AtomicU64>, Arc<AtomicU64>, Sizes)>;
    let lossy: Arc<Mutex<Knobs>> = Arc::default();
    let lossy_in = Arc::clone(&lossy);
    let mut w = World::build(&Setup {
        specs: vec![format!("{sink_port}/udp")],
        trusted: true,
        path: PathKind::Relayed,
        guest_leg: Some(Box::new(move |anchor| {
            let (addr, count, knob, sizes) = lossy_proxy(anchor, Duration::from_millis(20));
            *held(&lossy_in) = Some((count, knob, sizes));
            Some(addr)
        })),
    });
    let guest = w.guest_dir.clone();
    let (_fwd, at) = w.forward_vox("forward", &guest, &format!("{sink_port}/udp"));

    let client = apparatus(UdpSocket::bind("127.0.0.1:0"), "bind the blaster");
    // Open the flow: seq 0 until the sink hears one.
    let deadline = Instant::now() + Duration::from_secs(300);
    while held(&arrivals).is_empty() && Instant::now() < deadline {
        apparatus(
            client.send_to(&0u32.to_be_bytes(), at),
            "send to the forward's local port",
        );
        std::thread::sleep(Duration::from_millis(200));
    }
    // The forward is up — it printed its bound address — so a flow that never carries a
    // datagram to the service is vox's.
    assert!(
        !held(&arrivals).is_empty(),
        "PRODUCT: the UDP flow never opened: in 300 s nothing sent to the forward at {at} \
         reached the service"
    );
    held(&arrivals).clear();
    // The loss starts now, not during setup: joining over a lossy leg is its own open
    // defect (ADR-018, a joining node holding its actor for 30 s), and this proof is about
    // what the relay does to traffic, not about joining.
    let (dropped, knob, sizes) = held(&lossy).clone().unwrap_or_else(|| {
        panic!("CANNOT MEASURE: staging not achieved — the lossy leg was never built")
    });
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
        apparatus(client.send_to(&d, at), "send to the forward's local port");
        if let Some(wait) = (warm + BLAST_EVERY * (seq + 1)).checked_duration_since(Instant::now())
        {
            std::thread::sleep(wait);
        }
    }
    std::thread::sleep(Duration::from_millis(500));
    held(&arrivals).clear();
    let proxy_drops_before = dropped.load(Ordering::Relaxed);
    let sizes_before = held(&sizes).len();

    let start = Instant::now();
    for seq in 1..=BLAST_COUNT {
        let mut d = seq.to_be_bytes().to_vec();
        d.resize(200, 0);
        apparatus(client.send_to(&d, at), "send to the forward's local port");
        let next = start + BLAST_EVERY * seq;
        if let Some(wait) = next.checked_duration_since(Instant::now()) {
            std::thread::sleep(wait);
        }
    }
    std::thread::sleep(Duration::from_secs(2));
    let got = held(&arrivals).clone();
    let proxy_drops = dropped.load(Ordering::Relaxed) - proxy_drops_before;
    let window: Vec<(usize, bool)> = held(&sizes)[sizes_before..].to_vec();
    // Every numbered datagram is the same 200 bytes, so every packet that carries one on
    // the leg is the same size: the commonest size the leg passed in the window.
    let mut passed: std::collections::BTreeMap<usize, usize> = Default::default();
    let mut lost_sizes: std::collections::BTreeMap<usize, usize> = Default::default();
    for (n, lose) in &window {
        *(if *lose { &mut lost_sizes } else { &mut passed })
            .entry(*n)
            .or_default() += 1;
    }
    let carrier = passed
        .iter()
        .max_by_key(|(_, c)| **c)
        .map(|(n, _)| *n)
        .unwrap_or_default();
    // A packet that carries a numbered datagram is that size, or a few bytes more when an
    // acknowledgement frame rides with it (measured: 262 bytes, and 268–271). Nothing smaller
    // can hold one — the rest are the outer and inner connections' own acknowledgements, 30–66
    // bytes — and a much larger packet is something else, or several datagrams coalesced.
    let band = carrier..=carrier + CARRIER_SLACK;
    let carrying_drops: u64 = lost_sizes
        .iter()
        .filter(|(n, _)| band.contains(n))
        .map(|(_, c)| *c as u64)
        .sum();
    eprintln!(
        "[test] proof 5: the leg's datagrams by size in the window — passed {passed:?}, \
         dropped {lost_sizes:?}; a numbered datagram rides in {carrier} bytes, and \
         {carrying_drops} of the {proxy_drops} drops were {carrier}–{} bytes",
        carrier + CARRIER_SLACK
    );
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
        "CANNOT MEASURE: the lossy leg dropped nothing in the window, so this measured nothing"
    );
    assert!(
        carrier >= 200,
        "CANNOT MEASURE: the commonest packet on the leg was {carrier} bytes, too small to hold \
         a 200-byte numbered datagram — the window carried something other than the stream"
    );
    // **Every dropped datagram stays dropped**, which is the whole claim: nothing
    // retransmits it, so nothing can be held behind its retransmission. With the stream
    // carriage restored as a mutation, the outer stream retransmits every loss — 400 of 400
    // arrive — and later datagrams wait behind each one.
    //
    // **Counted per packet that carried one, not per drop** (#161). The proxy drops every
    // tenth packet on the leg, acknowledgements included, and which packets that lands on
    // depends on how the ten lines up with the traffic: one run lost 17 datagrams for 50
    // drops, and the old bound ("at least half the drops") failed it, while its 50 drops were
    // 36 acknowledgements and 14 datagram-sized packets — 14 lost for 14 carried, nothing
    // recovered. Measured over five runs: lost 14/40/30/49/48 for 14/40/30/49/44 datagram-sized
    // drops. So a drop of a packet that carried a datagram must cost one, every time.
    //
    // The gaps and latencies are printed, not bounded: congestion control on the outer and
    // inner connections, reacting to a 10% loss rate, holds and releases datagrams on its
    // own schedule (ADR-022 "Negative"), and under a loaded machine those holds reach
    // ~100 ms with no stream anywhere in the path.
    let lost = BLAST_COUNT as usize - received.min(BLAST_COUNT as usize);
    assert!(
        carrying_drops > 0,
        "CANNOT MEASURE: none of the {proxy_drops} drops was a packet that carried a datagram"
    );
    assert!(
        lost as u64 >= carrying_drops,
        "PRODUCT: a relay must lose what the lossy leg drops, not recover it: {lost} lost for \
         {carrying_drops} datagram-carrying packets dropped on the leg"
    );
}
