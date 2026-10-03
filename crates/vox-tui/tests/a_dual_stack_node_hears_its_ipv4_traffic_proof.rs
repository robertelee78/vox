//! **A node listening dual-stack on `[::]` hears its IPv4 traffic, or says it cannot** (V210-147),
//! driven through the shipped binary.
//!
//! On macOS a UDP socket bound to `[::]:0` with IPv6-only off is often given a port another program
//! already holds on IPv4 — measured with plain sockets, 529 of 3000 such binds against 3000 held
//! `127.0.0.1` ports — and an explicit `[::]:P` is even allowed over a `0.0.0.0:P` holder. IPv4
//! datagrams to that port then go to the other program, and the node, saying nothing, hears IPv6
//! only: a host that dialled such an anchor over IPv4 reached another node and was told
//! "signature verification failed" (V210-143).
//!
//! **Whether the node hears IPv4 is asked of the node itself, in QUIC:** a 1200-byte long-header
//! packet of an unknown version, sent over IPv4 to `127.0.0.1:P`, must be answered with a Version
//! Negotiation packet (RFC 9000 §6), which only the QUIC endpoint on that port sends.
//!
//! `a_node_on_an_ephemeral_dual_stack_port_hears_ipv4_even_when_ports_are_held`: this test holds
//! [`HELD`] IPv4 ports on `127.0.0.1`, about half the ephemeral range, standing for the programs on
//! a busy machine, then starts `vox node --listen [::]:0` [`STARTS`] times. Each start's node must
//! answer over IPv4 on its port, and that port must not be one this test holds. Without the check,
//! about one start in two collides.
//!
//! `a_node_told_to_listen_on_a_port_held_on_ipv4_refuses_and_says_why`: this test holds
//! `0.0.0.0:P` and starts `vox node --listen [::]:P`. The node must not run, and must say that IPv4
//! traffic to P reaches another program.
//!
//! The pinned-identity mismatch naming who answered is proved by
//! `a_dial_that_reaches_another_node_says_who_answered_proof` (V210-143).
//!
//! Every red says PRODUCT, quoting the node, or CANNOT MEASURE, naming the staging not achieved.
//!
//! **Mutations that must turn it red:** the self-test removed (`hears_ipv4` always true): the
//! first test, at a start that collides, and the second, which then runs. And no rebind (an
//! ephemeral port that fails is refused, not bound again): the first test, whose node does not
//! start.
//!
//! `#[ignore]`d: production Argon2id per start. Run it in release.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/world.rs"]
mod world;

use std::collections::BTreeSet;
use std::net::{Ipv4Addr, UdpSocket};
use std::time::{Duration, Instant};

use world::{args, mkdir, tempdir, VoxProc};

/// How many IPv4 ports the first test holds: about half the ephemeral range (49152–65535).
const HELD: usize = 8000;
/// How many times the first test starts a node on `[::]:0`.
const STARTS: usize = 10;

/// Whether the QUIC endpoint on `127.0.0.1:port` answers over IPv4: a Version Negotiation packet
/// in reply to a 1200-byte long-header packet of an unknown version.
fn answers_quic_over_ipv4(port: u16) -> bool {
    let Ok(s) = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)) else {
        return false;
    };
    let mut pkt = vec![0u8; 1200];
    pkt[0] = 0xc0; // long header
    pkt[1..5].copy_from_slice(&0x1a2a_3a4au32.to_be_bytes()); // a reserved, unknown version
    pkt[5] = 8; // destination connection id length
    pkt[6..14].copy_from_slice(b"voxprobe");
    pkt[14] = 8; // source connection id length
    pkt[15..23].copy_from_slice(b"v210-147");
    let _ = s.set_read_timeout(Some(Duration::from_millis(500)));
    for _ in 0..4 {
        if s.send_to(&pkt, (Ipv4Addr::LOCALHOST, port)).is_err() {
            return false;
        }
        let mut buf = [0u8; 1500];
        if let Ok((n, _)) = s.recv_from(&mut buf) {
            // Version Negotiation: long header, version 0.
            if n >= 5 && buf[0] & 0x80 != 0 && buf[1..5] == [0, 0, 0, 0] {
                return true;
            }
        }
    }
    false
}

/// The UDP port a `vox node`'s `--anchor` spec names.
fn spec_port(spec: &str) -> Option<u16> {
    spec.rsplit('/').next()?.trim().parse().ok()
}

fn start_node(dir: &std::path::Path, listen: &str) -> VoxProc {
    VoxProc::spawn("node", dir, &args(&["node", "--listen", listen]))
}

#[test]
#[ignore = "production Argon2id per start; run in release"]
fn a_node_on_an_ephemeral_dual_stack_port_hears_ipv4_even_when_ports_are_held() {
    watchdog::arm();
    let mut held = Vec::with_capacity(HELD);
    for _ in 0..HELD {
        match UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)) {
            Ok(s) => held.push(s),
            Err(e) => panic!(
                "CANNOT MEASURE (APPARATUS): this test could hold only {} of {HELD} IPv4 ports \
                 ({e}); raise the open-file limit",
                held.len()
            ),
        }
    }
    let ports: BTreeSet<u16> = held
        .iter()
        .filter_map(|s| s.local_addr().ok().map(|a| a.port()))
        .collect();
    let tmp = tempdir();
    let dir = tmp.path().join("node");
    mkdir(&dir.join("cfg"));
    let mut reds = Vec::new();
    for n in 1..=STARTS {
        let mut node = start_node(&dir, "[::]:0");
        let spec = node.expect_line("the node's --anchor spec", |l| {
            !l.starts_with("! ")
                && l.trim_start().contains('@')
                && l.trim_start().starts_with(|c: char| c.is_alphanumeric())
        });
        let Some(port) = spec_port(&spec) else {
            panic!("PRODUCT: start {n}: the node's spec names no port: {spec:?}");
        };
        let collided = ports.contains(&port);
        let answers = answers_quic_over_ipv4(port);
        println!(
            "[proof] start {n}: the node took [::]:{port}; held on IPv4 by this test: {collided}; \
             answers QUIC over IPv4: {answers}"
        );
        if collided || !answers {
            reds.push(format!(
                "start {n}: the node on [::]:{port} {}; it said:\n{}",
                if collided {
                    "took a port this test holds on IPv4, so its IPv4 traffic reaches the test"
                } else {
                    "does not answer QUIC over IPv4"
                },
                node.transcript()
            ));
        }
        drop(node);
    }
    drop(held);
    assert!(
        reds.is_empty(),
        "PRODUCT: a node listening on [::]:0 must hear its IPv4 traffic, whatever ports other \
         programs hold; {} of {STARTS} start(s) did not:\n{}",
        reds.len(),
        reds.join("\n")
    );
}

#[test]
#[ignore = "production Argon2id; run in release"]
fn a_node_told_to_listen_on_a_port_held_on_ipv4_refuses_and_says_why() {
    watchdog::arm();
    let holder = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
        .expect("APPARATUS: hold an IPv4 port on 0.0.0.0");
    let port = holder
        .local_addr()
        .expect("APPARATUS: the held port")
        .port();
    let tmp = tempdir();
    let dir = tmp.path().join("node");
    mkdir(&dir.join("cfg"));
    let mut node = start_node(&dir, &format!("[::]:{port}"));
    let deadline = Instant::now() + Duration::from_secs(60);
    let exited = loop {
        match node.child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(100)),
            _ => break None,
        }
    };
    let said = node.transcript();
    println!(
        "[proof] told to listen on [::]:{port} while this test holds 0.0.0.0:{port}: exited \
         {exited:?}; it said: {said}"
    );
    assert!(
        exited.is_some_and(|s| !s.success())
            && said.contains(&format!(
                "IPv4 traffic to port {port} reaches another program"
            )),
        "PRODUCT: a node told to listen on [::]:{port}, a port another program holds on IPv4, must \
         refuse to run and say that IPv4 traffic to it reaches another program; exited \
         {exited:?}, it said:\n{said}"
    );
    drop(holder);
}
