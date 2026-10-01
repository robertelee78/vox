//! **A relay circuit carries a node that listens on an IPv6 socket**, driven through the shipped
//! binary.
//!
//! A circuit's address is a synthetic IPv4 address in the mux's table. On an IPv6 socket quinn
//! dials it as the IPv4-mapped `::ffff:a.b.c.d`, and records that as the connection's remote; the
//! mux handed the circuit's inbound datagrams up from the plain IPv4 address. A QUIC client
//! discards packets from any address but its recorded remote, so every handshake over a circuit
//! from a node bound to `[::1]` — or to the dual-stack `[::]` — timed out, and the relay rung was
//! dead for it: `circuit via <anchor>: … 251.x.y.z:1: direct attempt timed out`.
//!
//! **The only path is the circuit.** On loopback, split by address family with the product's own
//! `--listen`: the anchor on `[::]` (dual-stack), the host on `127.0.0.1` (an IPv4 socket), the
//! guest on `[::1]`. Each reaches the anchor; neither can send a datagram to the other — an IPv4
//! socket cannot address `::1`, and a socket bound to `::1` cannot send to `127.0.0.1` — so no
//! direct dial and no hole punch connects them. That is checked first, as a precondition
//! (`support/family_split.rs`), and the gate asserts the product itself says the path is relayed,
//! so a split that stopped splitting cannot pass it.
//!
//! What must hold: the guest joins the host's room, and bytes cross a `vox forward` both ways.
//!
//! **RP-15 — two hosts behind symmetric NATs talk through the anchor**
//! (`two_hosts_behind_symmetric_nats_reach_a_service_through_the_anchor`). This is what an anchor
//! is for: bridging two hosts that cannot otherwise find each other. `support/nat.rs` puts a
//! **symmetric** NAT in userspace in front of each `vox` process (a new public port for every
//! destination, and an unsolicited datagram dropped), so the address the anchor observes is
//! useless to the peer and no hole punch can work: the only path is the anchor's relay. With the
//! shipped binary as a person runs it — `vox node`, `vox serve` on the host, `vox id`,
//! `vox trust add`, `vox connect` and `vox up` on the guest — the guest must join the host's room
//! and reach its service over SOCKS5 (`<room>.vox`), [`SYM_REQUESTS`] times, every byte through the
//! anchor and none peer to peer.
//! - A process that never used its NAT, or a single payload byte peer to peer, is `CANNOT
//!   MEASURE`: the emulator would not be what is being measured.
//! - The join failing is a PRODUCT red naming the relay path: behind symmetric NATs the relay is the
//!   only path, so a failed join is that path not being established.
//! - A request not answered, once the join has proved the relay up, is a PRODUCT red that names the
//!   failing side from what the request showed — a refused tunnel (the host or its tunnel), a broken
//!   SOCKS exchange (the guest's proxy) or a lost echo — and does not blame the anchor for it.
//! - **The mutation that must turn it red:** the anchor refuses to carry any circuit
//!   (`serve_circuit`'s open arm refuses). The guest cannot reach its host, and the join fails.
//!
//! `#[ignore]`d: production Argon2id and a real PoW. Run it in release.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/world.rs"]
mod world;

#[path = "support/relay.rs"]
mod relay;

#[path = "support/nat.rs"]
mod nat;

#[path = "support/test_knobs.rs"]
mod test_knobs;

#[path = "support/family_split.rs"]
mod family_split;

use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

use nat::{Kind, TwoNats};
use relay::{RelayWorld, Split};
use world::{after_label, args, echo_service, round_trip, vox_once, VoxProc};

/// How many requests the guest makes to the host's service behind the symmetric NATs.
const SYM_REQUESTS: usize = 3;
/// A request's echo payload.
const SYM_PAYLOAD: usize = 16 * 1024;

#[test]
#[ignore = "production Argon2id + a real PoW, three real `vox` processes; run in release"]
fn a_guest_on_an_ipv6_socket_reaches_its_host_through_a_relay_circuit() {
    watchdog::arm();
    family_split::assert_the_families_are_split();
    let mut w = RelayWorld::new(Split::Families);
    let (ok, took, out, err) = w.join_guest();
    assert!(
        ok,
        "the guest on [::1] could not join its host through the relay (after {took:?}).\n\
         stdout:\n{out}\nstderr:\n{err}"
    );
    eprintln!(
        "[test] joined through the relay in {:.1}s",
        took.as_secs_f64()
    );
    let at = w.forward();
    let back =
        round_trip(at, b"across the circuit", Duration::from_secs(120)).unwrap_or_else(|e| {
            panic!(
                "no echo through the forward ({e}).\nforward:\n{}",
                w.fwd.as_mut().unwrap().transcript()
            )
        });
    assert_eq!(back, b"across the circuit", "bytes must cross unchanged");
    w.assert_relayed("after the echo");
    w.expect_still_relayed();
    eprintln!("[test] echo crossed the circuit, and the forward reports the path relayed");
}

/// What one request through `vox up` to the host's echo service came to.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Outcome {
    /// The whole payload came back.
    Echoed,
    /// `vox up` answered the CONNECT with this non-zero SOCKS reply.
    Refused(u8),
    /// The tunnel opened (reply 0), but the payload did not come back whole.
    EchoLost,
    /// The SOCKS exchange with `vox up` did not complete: it closed, ran past the 90 s read
    /// timeout, or answered something that is not SOCKS5.
    ProxyBroke(String),
}

/// One request through `vox up` (`socks5h`, CONNECT by name) to the host's echo service. A local
/// socket that cannot even be opened is the harness's fault; anything `vox up` does once the
/// connection is up is reported as an [`Outcome`].
fn sym_request(proxy: SocketAddr, host: &str, port: u16, payload: &[u8]) -> Outcome {
    use std::io::{Read, Write};
    let mut s = std::net::TcpStream::connect(proxy).unwrap_or_else(|e| {
        panic!("CANNOT MEASURE (harness error): could not open a TCP connection to vox up at {proxy}: {e}")
    });
    let _ = s.set_read_timeout(Some(Duration::from_secs(90)));
    let io = |what: &str, e: std::io::Error| Outcome::ProxyBroke(format!("{what}: {e}"));
    if let Err(e) = s.write_all(&[0x05, 0x01, 0x00]) {
        return io("sending the SOCKS greeting", e);
    }
    let mut hello = [0u8; 2];
    if let Err(e) = s.read_exact(&mut hello) {
        return io("reading the SOCKS method", e);
    }
    if hello != [0x05, 0x00] {
        return Outcome::ProxyBroke(format!("method reply {hello:?}, not no-auth"));
    }
    let Ok(len) = u8::try_from(host.len()) else {
        panic!("CANNOT MEASURE (harness error): host name {host:?} is too long for SOCKS5");
    };
    let mut req = vec![0x05, 0x01, 0x00, 0x03, len];
    req.extend_from_slice(host.as_bytes());
    req.extend_from_slice(&port.to_be_bytes());
    if let Err(e) = s.write_all(&req) {
        return io("sending the CONNECT", e);
    }
    let mut head = [0u8; 4];
    if let Err(e) = s.read_exact(&mut head) {
        return io("reading the CONNECT reply", e);
    }
    if head[0] != 0x05 {
        return Outcome::ProxyBroke(format!("reply version {}", head[0]));
    }
    let skip = match head[3] {
        0x01 => 4 + 2,
        0x04 => 16 + 2,
        other => return Outcome::ProxyBroke(format!("reply address type {other}")),
    };
    let mut sink = vec![0u8; skip];
    if let Err(e) = s.read_exact(&mut sink) {
        return io("reading the bound address", e);
    }
    if head[1] != 0 {
        return Outcome::Refused(head[1]);
    }
    if s.write_all(payload).is_err() {
        return Outcome::EchoLost;
    }
    let mut back = vec![0u8; payload.len()];
    if s.read_exact(&mut back).is_ok() && back == payload {
        Outcome::Echoed
    } else {
        Outcome::EchoLost
    }
}

#[test]
#[ignore = "production Argon2id + a real PoW, two userspace NATs and four real `vox` processes; run in release"]
fn two_hosts_behind_symmetric_nats_reach_a_service_through_the_anchor() {
    test_knobs::require(&["VOX_TEST_ADVERTISE"]);
    watchdog::arm();
    let tmp = tempfile::tempdir()
        .unwrap_or_else(|e| panic!("CANNOT MEASURE (harness error): no temp dir: {e}"));
    let (anchor_dir, host_dir, guest_dir) = (
        tmp.path().join("anchor"),
        tmp.path().join("host"),
        tmp.path().join("guest"),
    );
    for d in [&anchor_dir, &host_dir, &guest_dir] {
        std::fs::create_dir_all(d.join("cfg")).unwrap_or_else(|e| {
            panic!(
                "CANNOT MEASURE (harness error): could not make {}: {e}",
                d.display()
            )
        });
    }
    let anchor_port = UdpSocket::bind("[::]:0")
        .and_then(|s| s.local_addr())
        .unwrap_or_else(|e| panic!("CANNOT MEASURE (harness error): no free UDP port: {e}"))
        .port();
    let nats = TwoNats::start(Kind::Symmetric, anchor_port);
    let advertise = format!("{},{}", nats.anchor_for_host, nats.anchor_for_guest);
    let mut anchor = VoxProc::spawn_env(
        "anchor",
        &anchor_dir,
        &args(&["node", "--listen", &format!("[::]:{anchor_port}")]),
        &[("VOX_TEST_ADVERTISE", advertise.as_str())],
    );
    let spec = anchor
        .expect_line("an --anchor spec", |l| {
            !l.starts_with("! ")
                && l.trim_start().contains('@')
                && l.trim_start().starts_with(|c: char| c.is_alphanumeric())
        })
        .trim()
        .to_owned();
    let Some((fp, _)) = spec.split_once('@') else {
        panic!("PRODUCT: vox node printed an --anchor spec with no fingerprint: {spec:?}");
    };
    let host_spec = format!("{fp}@/ip4/127.0.0.1/udp/{}", nats.anchor_for_host.port());
    let guest_spec = format!("{fp}@/ip6/::1/udp/{}", nats.anchor_for_guest.port());

    let (ok, guest_fp, err) = vox_once(&guest_dir, &args(&["id"]));
    assert!(ok, "CANNOT MEASURE: vox id (guest): {err}");
    let (ok, _, err) = vox_once(&host_dir, &args(&["id"]));
    assert!(ok, "CANNOT MEASURE: vox id (host): {err}");
    let (ok, out, err) = vox_once(
        &host_dir,
        &args(&["trust", "add", guest_fp.trim(), "--name", "the guest"]),
    );
    assert!(ok, "CANNOT MEASURE: trust add: {out}\n{err}");
    let service_port = echo_service();
    let mut host = VoxProc::spawn(
        "host",
        &host_dir,
        &args(&[
            "serve",
            &service_port.to_string(),
            "--anchor",
            &host_spec,
            "--listen",
            "127.0.0.1:0",
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
    let pass_file = world::room_pass_file(&guest_dir, &passphrase);
    let (joined, out, err) = vox_once(
        &guest_dir,
        &args(&[
            "connect",
            &address,
            "--passphrase-file",
            &pass_file,
            "--anchor",
            &guest_spec,
            "--listen",
            "[::1]:0",
        ]),
    );
    let (host_maps, guest_maps) = nats.mappings();
    eprintln!(
        "[proof] symmetric NATs: guest joined {joined}; NAT mappings host {host_maps}, guest \
         {guest_maps}; unsolicited peer datagrams dropped {}",
        nats.p2p_filtered()
    );
    assert!(
        host_maps > 0 && guest_maps > 0,
        "CANNOT MEASURE: a process never sent through its NAT (host {host_maps}, guest \
         {guest_maps} mappings), so the NATs are not in the path"
    );
    // Behind symmetric NATs the anchor's relay is the only path, so a join that fails is the
    // relay path not being established between them.
    assert!(
        joined,
        "PRODUCT: behind symmetric NATs the guest could not join its host's room — the anchor's \
         relay, the only path between them, was not established.\nstdout:\n{out}\nstderr:\n\
         {err}\nhost:\n{}",
        host.transcript()
    );

    let mut up = VoxProc::spawn(
        "up",
        &guest_dir,
        &args(&[
            "up",
            &room,
            "--passphrase-file",
            &pass_file,
            "--bind",
            "127.0.0.1:0",
            "--anchor",
            &guest_spec,
            "--listen",
            "[::1]:0",
        ]),
    );
    let line = up.expect_line("the proxy's bound address", |l| l.starts_with("vox up on "));
    let proxy: SocketAddr = line
        .split_whitespace()
        .nth(3)
        .and_then(|a| a.parse().ok())
        .unwrap_or_else(|| panic!("PRODUCT: vox up printed no bound address: {line:?}"));
    let payload: Vec<u8> = (0..SYM_PAYLOAD).map(|i| (i % 251) as u8).collect();
    let hostname = format!("{room}.vox");
    let outcomes: Vec<Outcome> = (0..SYM_REQUESTS)
        .map(|_| sym_request(proxy, &hostname, service_port, &payload))
        .collect();
    let answered = outcomes.iter().filter(|o| **o == Outcome::Echoed).count();
    let p2p = nats.p2p_to_host() + nats.p2p_to_guest();
    eprintln!(
        "[proof] symmetric NATs: {answered}/{SYM_REQUESTS} requests to the host's service \
         answered ({outcomes:?}); peer to peer {p2p} B; unsolicited peer datagrams dropped {}",
        nats.p2p_filtered()
    );
    assert!(
        p2p == 0,
        "CANNOT MEASURE: behind symmetric NATs the pair moved {p2p} B peer to peer — a path leaks \
         around the emulator, so the anchor was not the only path"
    );
    // A shortfall says only what the requests showed. The join ran over its own circuit, so it
    // says nothing about vox up's path; the reason for a failure is in vox up's own transcript.
    let mut seen: Vec<String> = Vec::new();
    for o in &outcomes {
        let what = match o {
            Outcome::Echoed => continue,
            Outcome::Refused(2) => "vox up answered SOCKS reply 2 (not allowed): the host refused \
                                   the tunnel, or vox up knows no room by that name"
                .to_string(),
            Outcome::Refused(n) => format!("vox up answered SOCKS reply {n}"),
            Outcome::EchoLost => {
                "the CONNECT succeeded, but the echo did not come back whole".into()
            }
            Outcome::ProxyBroke(why) => format!("the SOCKS exchange did not complete ({why})"),
        };
        if !seen.contains(&what) {
            seen.push(what);
        }
    }
    assert_eq!(
        answered,
        SYM_REQUESTS,
        "PRODUCT: behind symmetric NATs {answered} of {SYM_REQUESTS} requests reached the host's \
         service — {}. vox up's transcript below names the reason ({outcomes:?}).\nup:\n{}",
        seen.join("; "),
        up.transcript()
    );
}
