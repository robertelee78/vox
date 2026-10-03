//! V210-47 (#222) and V210-48 (#223) — **a node dials only addresses its socket can reach, and
//! advertises only addresses its socket listens on**, driven through the shipped `vox` binary.
//!
//! Both are the same mistake seen from the two ends of a dial: an address that the bound socket
//! cannot use. A dial to such an address never fails fast; it waits out the whole per-attempt
//! timeout, and every one of them is a person waiting.
//!
//! ## #222 — a guest bound to `[::1]` never dials an IPv4-mapped candidate
//!
//! **The staging — real processes only** (`support/port_forward.rs`, as RP-22 and RP-25 use it). A
//! `vox node` anchor on `[::]` (dual-stack), a `vox serve` host on `127.0.0.1`, and the guest on
//! `[::1]`, set up with `vox id`, `vox trust add` and `vox connect`. The dual-stack anchor sees the
//! IPv4 host as `::ffff:127.0.0.1` and reports that as the host's observed address. A socket bound
//! to `[::1]` cannot send there at all (the kernel refuses with `EADDRNOTAVAIL`), so the dial can
//! only time out. The host advertises a **closed** port forward on `[::1]` (the proof-only
//! `VOX_TEST_ADVERTISE`), so no direct attempt succeeds and `vox up` reports **every** candidate
//! it tried, with what became of it, in its `still relayed to … — <reason>` line.
//!
//! **Asserted:** every address that line names is one a `[::1]` socket can reach: `::1` itself, or
//! a relay circuit's synthetic address in `240.0.0.0/4` (a circuit rides the anchor's connection,
//! whatever the socket's family, #173/#197). No `::ffff:` address and no other scope.
//!
//! ## #223 — a host bound to `[::1]` advertises no address it does not listen on
//!
//! **The staging.** The same anchor; a `vox serve` host bound to `[::1]:P` with **no** advertise
//! override, and a guest bound to `127.0.0.1`. Before the host starts, the proof binds a **trap** at
//! `127.0.0.1:P`: the same port on the IPv4 loopback, which is not the host's socket. The guest can
//! send there, but never to the host's `[::1]`, so the pair stays relayed and the guest keeps
//! running its ladder on what the host published. A datagram at the trap is the guest dialling an
//! address the host advertised but does not listen on; and `vox up`'s `still relayed to … —
//! <reason>` names the candidates it tried, which must not include the box's other addresses at
//! port `P` either (its routable IPv6 and IPv4 addresses, found without sending a packet).
//!
//! **Why loopback only.** This box runs the macOS application firewall, which drops inbound traffic
//! on non-loopback addresses to any binary not on its list — a freshly built `vox` or proof binary
//! is not. A staging that needs a datagram to arrive at the LAN or global address measures the
//! firewall (a first version of this proof did: the guest could not even reach the anchor at the
//! LAN address). Loopback is exempt, so the trap on `127.0.0.1` is a real receiver, and the global
//! and LAN addresses are checked by name in the guest's report instead.
//!
//! **Asserted:** the request is answered (over the circuit); in [`WATCH_223`], the trap received
//! **0** datagrams and no report names an address of this box at port `P` other than the host's own
//! `[::1]:P`. The mutant run on the same staging is the control that the trap and the report can
//! see a wrong advertisement.
//!
//! **Bounds are numbers**, never product constants. Every run prints its counts (`[proof] …`).
//!
//! **The mutations that must turn it red:**
//! - #222: `nat::reachability::connect_direct_within` keeps a candidate whenever the local socket is
//!   IPv6 and the candidate is IPv6 (the old `c.is_ipv6() || l.ip().is_unspecified()`): the guest
//!   names `[::ffff:127.0.0.1]:…` again.
//! - #223: `NodeNet::refresh_advertised` enumerates the box's addresses for a socket bound to a
//!   specific address (the old `advertise_endpoints(bound.port())`): the trap receives datagrams.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/test_knobs.rs"]
mod test_knobs;

#[path = "support/world.rs"]
mod world;

#[path = "support/relay.rs"]
mod relay;

#[path = "support/port_forward.rs"]
mod port_forward;

use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use port_forward::{echo_over, interrupt, ForwardedWorld};
use world::{after_label, args, echo_service, socks5_connect, vox_once, VoxProc};

/// How long the first `still relayed` report may take: the connect-time ladder, on a loaded box.
const FIRST_ATTEMPT_WITHIN: Duration = Duration::from_secs(90);
/// How long #223's proof watches the trap and the guest's reports after the first answer: long
/// enough for the host's endpoint ladder to publish and the guest's connect-time ladder and first
/// retry to run on what it published.
const WATCH_223: Duration = Duration::from_secs(60);
/// How long #223's host is left to publish its discovered endpoints before the guest looks them up.
const PUBLISH_SETTLE: Duration = Duration::from_secs(15);
const PAYLOAD: usize = 4 * 1024;

/// Every `ip:port` / `[ip]:port` token a line names.
fn addresses_named(line: &str) -> Vec<SocketAddr> {
    line.split(|c: char| c.is_whitespace() || c == ',' || c == '(' || c == ')' || c == ';')
        .filter_map(|t| {
            let t = t.trim_end_matches(':');
            t.parse::<SocketAddr>().ok()
        })
        .collect()
}

/// Can a UDP socket bound to `[::1]` send to `a`? Written out here, not taken from the product.
fn reachable_from_v6_loopback(a: &SocketAddr) -> bool {
    match a.ip() {
        IpAddr::V6(ip) => ip == std::net::Ipv6Addr::LOCALHOST,
        // A relay circuit's synthetic address (240.0.0.0/4): it rides the anchor's connection.
        IpAddr::V4(ip) => ip.octets()[0] & 0xf0 == 240,
    }
}

#[test]
#[ignore = "production Argon2id + a real PoW, a relayed pair; run in release"]
fn a_guest_bound_to_v6_loopback_never_dials_an_ipv4_mapped_candidate() {
    watchdog::arm();
    let w = ForwardedWorld::new(false);
    eprintln!(
        "[proof] guest on [::1] joined in {:?}; the host at {} advertises only the closed forward {}",
        w.joined_in, w.forward.host, w.forward.public
    );
    let hostname = w.hostname();
    let (mut up, proxy, _ready) = w.up("up");
    let (code, mut s) = socks5_connect(proxy, &hostname, w.service_port);
    assert_eq!(
        code,
        0,
        "PRODUCT (staging): the guest's request to {hostname} was refused (SOCKS {code}).\nup:\n{}",
        up.transcript()
    );
    let payload: Vec<u8> = (0..PAYLOAD).map(|i| (i % 251) as u8).collect();
    assert!(
        echo_over(&mut s, &payload, Duration::from_secs(60)),
        "PRODUCT (staging): no echo over the relayed path.\nup:\n{}",
        up.transcript()
    );
    drop(s);
    let line = up.expect_within(
        FIRST_ATTEMPT_WITHIN,
        "`still relayed` naming every direct candidate tried",
        |l| l.starts_with("! vox: still relayed to"),
    );
    eprintln!("[proof] {line}");
    let named = addresses_named(&line);
    let unreachable: Vec<&SocketAddr> = named
        .iter()
        .filter(|a| !reachable_from_v6_loopback(a))
        .collect();
    let mapped = named
        .iter()
        .filter(|a| matches!(a.ip(), IpAddr::V6(ip) if ip.to_ipv4_mapped().is_some()))
        .count();
    let at_forward = named.iter().filter(|a| **a == w.forward.public).count();
    eprintln!(
        "[proof] the report names {} address(es): {} at the forward, {} IPv4-mapped, {} a [::1] \
         socket cannot reach",
        named.len(),
        at_forward,
        mapped,
        unreachable.len()
    );
    assert!(
        at_forward >= 1,
        "PRODUCT (staging): the `still relayed` report does not name the forward {} — it is not the \
         per-candidate report this proof reads.\n{line}",
        w.forward.public
    );
    assert!(
        unreachable.is_empty(),
        "PRODUCT: DIALLED UNREACHABLE (#222): the guest, bound to [::1], tried {} candidate(s) its socket \
         cannot send to, each waiting out a timeout: {unreachable:?}\n{line}",
        unreachable.len()
    );
    interrupt(&mut up, Duration::from_secs(15));
    drop(up);
}

/// A UDP socket that counts what arrives at it and never answers.
struct Trap {
    at: SocketAddr,
    got: Arc<AtomicU64>,
    from: Arc<Mutex<Vec<SocketAddr>>>,
}

impl Trap {
    fn bind(at: SocketAddr) -> Self {
        let sock = UdpSocket::bind(at)
            .unwrap_or_else(|e| panic!("APPARATUS: could not bind a trap at {at}: {e}"));
        sock.set_read_timeout(Some(Duration::from_millis(100)))
            .expect("APPARATUS: set a read timeout");
        let got = Arc::new(AtomicU64::new(0));
        let from = Arc::new(Mutex::new(Vec::new()));
        let (g, f) = (Arc::clone(&got), Arc::clone(&from));
        std::thread::spawn(move || {
            let mut buf = vec![0u8; 65536];
            loop {
                if let Ok((_, src)) = sock.recv_from(&mut buf) {
                    g.fetch_add(1, Ordering::SeqCst);
                    f.lock()
                        .expect("APPARATUS: a lock the proof holds was poisoned")
                        .push(src);
                }
                if Arc::strong_count(&g) == 1 {
                    return;
                }
            }
        });
        Self { at, got, from }
    }

    fn got(&self) -> u64 {
        self.got.load(Ordering::SeqCst)
    }
}

/// The address the OS would route to `probe` from, found without sending a packet.
fn route_ip(probe: &str, bind: &str) -> Option<IpAddr> {
    let s = UdpSocket::bind(bind).ok()?;
    s.connect(probe).ok()?;
    let ip = s.local_addr().ok()?.ip();
    (!ip.is_unspecified() && !ip.is_loopback()).then_some(ip)
}

#[test]
#[ignore = "production Argon2id + a real PoW; run in release"]
fn a_host_bound_to_v6_loopback_advertises_no_address_it_does_not_listen_on() {
    watchdog::arm();
    let tmp = tempfile::tempdir().expect("APPARATUS: no temp dir");
    let (anchor_dir, host_dir, guest_dir) = (
        tmp.path().join("anchor"),
        tmp.path().join("host"),
        tmp.path().join("guest"),
    );
    for d in [&anchor_dir, &host_dir, &guest_dir] {
        std::fs::create_dir_all(d.join("cfg")).expect("APPARATUS: create a staging directory");
    }
    let anchor = relay::Anchor::start(&anchor_dir);

    let (ok, guest_fp, err) = vox_once(&guest_dir, &args(&["id"]));
    assert!(ok, "PRODUCT (staging): vox id (guest): {err}");
    let (ok, _, err) = vox_once(&host_dir, &args(&["id"]));
    assert!(ok, "PRODUCT (staging): vox id (host): {err}");
    let (ok, out, err) = vox_once(
        &host_dir,
        &args(&["trust", "add", guest_fp.trim(), "--name", "the guest"]),
    );
    assert!(ok, "PRODUCT (staging): trust add: {out}\n{err}");

    // The host's port, and a trap at that port on every other address of this box.
    let port = UdpSocket::bind("[::1]:0")
        .expect("APPARATUS: bind a socket")
        .local_addr()
        .expect("APPARATUS: read a socket the proof bound")
        .port();
    let routable: Vec<IpAddr> = [
        route_ip("[2001:db8::1]:9", "[::]:0"),
        route_ip("192.0.2.1:9", "0.0.0.0:0"),
    ]
    .into_iter()
    .flatten()
    .collect();
    assert!(
        !routable.is_empty(),
        "APPARATUS (precondition not met): this box has no routable address, so there is nothing a [::1] host could \
         wrongly advertise"
    );
    let foreign: Vec<SocketAddr> = routable
        .iter()
        .copied()
        .chain([IpAddr::from([127, 0, 0, 1])])
        .map(|ip| SocketAddr::new(ip, port))
        .collect();
    let guest_spec = anchor.v4_spec.clone();
    let guest_listen = "127.0.0.1:0".to_owned();
    let trap = Trap::bind(SocketAddr::from(([127, 0, 0, 1], port)));
    eprintln!(
        "[proof] host on [::1]:{port}; trap at {}; addresses it must not publish {foreign:?}",
        trap.at
    );

    let service_port = echo_service();
    let mut host = VoxProc::spawn(
        "host",
        &host_dir,
        &args(&[
            "serve",
            &service_port.to_string(),
            "--anchor",
            &anchor.v6_spec,
            "--listen",
            &format!("[::1]:{port}"),
        ]),
    );
    let room = after_label(
        &host.expect_line("room", |l| l.starts_with("room ")),
        "room",
    );
    let address = after_label(
        &host.expect_line("address", |l| l.starts_with("address ")),
        "address",
    );
    let passphrase = after_label(
        &host.expect_line("passphrase", |l| l.starts_with("passphrase ")),
        "passphrase",
    );
    let t0 = Instant::now();
    let (ok, out, err) = vox_once(
        &guest_dir,
        &args(&[
            "connect",
            &address,
            "--passphrase-file",
            &world::room_pass_file(&guest_dir, &passphrase),
            "--anchor",
            &guest_spec,
            "--listen",
            &guest_listen,
        ]),
    );
    assert!(
        ok,
        "PRODUCT (staging): the guest could not join the host's room (after {:?}).\nstdout:\n{out}\n\
         stderr:\n{err}\nhost:\n{}",
        t0.elapsed(),
        host.transcript()
    );
    eprintln!("[proof] guest on 127.0.0.1 joined in {:?}", t0.elapsed());
    // The host's endpoint ladder runs after it starts; let what it found reach the board before
    // the guest looks the host up, so the guest dials what the host *published*.
    std::thread::sleep(PUBLISH_SETTLE);

    let mut up = VoxProc::spawn(
        "up",
        &guest_dir,
        &args(&[
            "up",
            &room,
            "--passphrase-file",
            &world::room_pass_file(&guest_dir, &passphrase),
            "--bind",
            "127.0.0.1:0",
            "--anchor",
            &guest_spec,
            "--listen",
            &guest_listen,
        ]),
    );
    let line = up.expect_line("the proxy's bound address", |l| l.starts_with("vox up on "));
    let proxy: SocketAddr = line
        .split_whitespace()
        .nth(3)
        .expect("PRODUCT: an address in the up line")
        .parse()
        .expect("PRODUCT: a socket address");
    let hostname = format!("{room}.vox");
    let (code, mut s) = socks5_connect(proxy, &hostname, service_port);
    assert_eq!(
        code,
        0,
        "PRODUCT (staging): the guest's request to {hostname} was refused (SOCKS {code}).\nup:\n{}",
        up.transcript()
    );
    let payload: Vec<u8> = (0..PAYLOAD).map(|i| (i % 251) as u8).collect();
    assert!(
        echo_over(&mut s, &payload, Duration::from_secs(60)),
        "PRODUCT (staging): no echo from the host's service.\nup:\n{}",
        up.transcript()
    );
    drop(s);
    let answered = Instant::now();
    let mut relayed = Vec::new();
    while answered.elapsed() < WATCH_223 {
        if let Ok(l) = up.lines.recv_timeout(Duration::from_millis(200)) {
            eprintln!("[up] {l}");
            if l.starts_with("! vox: still relayed to") {
                relayed.push(l.clone());
            }
            up.seen.push(l);
        }
    }
    let got = trap.got();
    let named: Vec<SocketAddr> = relayed
        .iter()
        .flat_map(|l| addresses_named(l))
        .filter(|a| foreign.contains(a))
        .collect();
    eprintln!(
        "[proof] trap {}: {got} datagram(s) from {:?}; {} `still relayed` report(s) naming {} \
         address(es) the host does not listen on",
        trap.at,
        trap.from
            .lock()
            .expect("APPARATUS: a lock the proof holds was poisoned")
            .iter()
            .collect::<std::collections::BTreeSet<_>>(),
        relayed.len(),
        named.len()
    );
    assert!(
        !relayed.is_empty(),
        "PRODUCT (staging): in {WATCH_223:?} `vox up` never reported a direct attempt at the host, so \
         nothing shows which addresses it took from the board.\nup:\n{}",
        up.transcript()
    );
    assert!(
        got == 0 && named.is_empty(),
        "PRODUCT: ADVERTISED UNREACHABLE (#223): the guest dialled {got} datagram(s) at {} and its reports \
         name {named:?} — addresses the [::1]-bound host published but does not listen on.\n{}",
        trap.at,
        relayed.join("\n")
    );
    interrupt(&mut up, Duration::from_secs(15));
    drop(up);
    drop(host);
    drop(trap);
}
