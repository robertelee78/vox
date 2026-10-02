//! The precondition of every proof on `relay.rs`'s `Split::Families`: on this machine, a
//! datagram socket on `127.0.0.1` and one on `[::1]` cannot reach each other. That is what makes
//! the anchor's circuit the only path between host and guest, so where it does not hold, a
//! relayed path is not forced by the split and the proof cannot measure what it claims.
//!
//! It replaces the separate "without the split the pair goes direct" controls (gate plan
//! v0.2.10, DELETE #8 and #9): the split itself is checked, before any `vox` runs, instead of
//! a second world of daemons standing in for it.
//!
//! Included with `#[path]` by each proof that needs it.

use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6, UdpSocket};
use std::time::Duration;

/// CANNOT MEASURE unless neither family's loopback socket can deliver a datagram to the
/// other's, in either direction and in either address form (`::1`, `127.0.0.1`, and the
/// IPv4-mapped `::ffff:127.0.0.1` quinn dials from an IPv6 socket).
pub fn assert_the_families_are_split() {
    let v4 = UdpSocket::bind("127.0.0.1:0")
        .unwrap_or_else(|e| panic!("APPARATUS: could not bind a UDP socket on 127.0.0.1: {e}"));
    let v6 = UdpSocket::bind("[::1]:0")
        .unwrap_or_else(|e| panic!("APPARATUS: could not bind a UDP socket on [::1]: {e}"));
    for s in [&v4, &v6] {
        s.set_read_timeout(Some(Duration::from_millis(300)))
            .expect("APPARATUS: set a read timeout");
    }
    let (at4, at6) = (v4.local_addr().unwrap(), v6.local_addr().unwrap());
    let mapped = SocketAddr::V6(SocketAddrV6::new(
        Ipv6Addr::from(0xffff_7f00_0001u128),
        at4.port(),
        0,
        0,
    ));
    let mut crossed = Vec::new();
    for (from, to, to_s) in [(&v4, at6, &v6), (&v6, at4, &v4), (&v6, mapped, &v4)] {
        if from.send_to(b"split?", to).is_ok() {
            let mut buf = [0u8; 16];
            if to_s.recv_from(&mut buf).is_ok() {
                crossed.push(format!("{} -> {to}", from.local_addr().unwrap()));
            }
        }
    }
    assert!(
        crossed.is_empty(),
        "CANNOT MEASURE: the address-family split does not split on this machine: a datagram \
         crossed {crossed:?}, so host and guest could reach each other directly and a relayed \
         path would not be forced by the split"
    );
    eprintln!("[split] 127.0.0.1 and [::1] cannot reach each other: the circuit is the only path");
}
