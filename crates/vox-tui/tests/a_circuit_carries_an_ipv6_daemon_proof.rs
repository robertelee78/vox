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
//! direct dial and no hole punch connects them. The gate asserts the product itself says the path
//! is relayed, so a split that stopped splitting cannot pass it.
//!
//! What must hold: the guest joins the host's room, and bytes cross a `vox forward` both ways.
//!
//! `#[ignore]`d: production Argon2id and a real PoW. Run it in release.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/world.rs"]
mod world;

#[path = "support/relay.rs"]
mod relay;

use std::time::Duration;

use relay::{RelayWorld, Split};
use world::round_trip;

#[test]
#[ignore = "production Argon2id + a real PoW, three real `vox` processes; run in release"]
fn a_guest_on_an_ipv6_socket_reaches_its_host_through_a_relay_circuit() {
    watchdog::arm();
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

/// **The control**: the same anchor, verbs and service with the split removed — host and guest
/// both on `127.0.0.1`. The pair goes direct: the anchor carries no circuit and the guest never
/// reports `still relayed`. Without this, the relayed proofs on this harness could be relayed for
/// some reason other than the split.
#[test]
#[ignore = "production Argon2id + a real PoW, three real `vox` processes; run in release"]
fn without_the_split_the_same_pair_goes_direct() {
    watchdog::arm();
    let mut w = RelayWorld::new(Split::None);
    let (ok, took, out, err) = w.join_guest();
    assert!(
        ok,
        "the control guest could not join ({took:?}).\n{out}\n{err}"
    );
    let at = w.forward();
    let back = round_trip(at, b"direct", Duration::from_secs(120)).expect("echo in the control");
    assert_eq!(back, b"direct");
    let circuits = w.anchor_circuits(Duration::from_secs(10));
    let fwd = w.fwd.as_mut().unwrap().transcript();
    eprintln!("[test] control: the anchor reports {circuits} circuit(s) carried after the echo");
    assert_eq!(
        circuits, 0,
        "the control is relayed too, so the split is not what forces the relay"
    );
    assert!(
        !fwd.contains("still relayed"),
        "the control guest reports a relayed path:\n{fwd}"
    );
}
