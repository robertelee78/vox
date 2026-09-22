//! ADR-012 rung 4 — what a circuit's synthetic address must and must not reveal.
//!
//! quinn addresses every path by `SocketAddr`, so a relayed connection needs one. That
//! address is an internal routing handle, but it is not a secret held carefully: it is the
//! `remote_address()` of a connection, it is compared, logged, and has in the past been
//! copied into published records. So its properties are part of the threat model, not an
//! implementation detail.
//!
//! Three properties, one test each.

use std::net::{IpAddr, SocketAddr};

use vox_core::identity::composite::{RootSigner, SoftwareRootSigner};
use vox_core::transport::quic::VoxEndpoint;

fn signer(a: u8) -> SoftwareRootSigner {
    SoftwareRootSigner::from_component_seeds(&[a; 32], &[a ^ 0x5A; 32]).unwrap()
}

fn endpoint(a: u8) -> VoxEndpoint {
    VoxEndpoint::bind(&signer(a), "127.0.0.1:0".parse().unwrap()).unwrap()
}

/// **Unlinkable to the peer it stands for.**
///
/// A fingerprint is published deliberately — it is what `vox trust add` takes. If a
/// circuit's address were a function of it, anyone holding a fingerprint could compute the
/// address and test whether it appears among a node's endpoints, reading that node's relay
/// topology out of public data. So two nodes attaching a circuit to the *same* peer must
/// arrive at different addresses, and so must one node twice.
#[tokio::test]
async fn a_circuit_address_is_not_a_function_of_the_peer() {
    let peer = RootSigner::public_key(&signer(9)).fingerprint();

    let one = endpoint(1);
    let two = endpoint(2);
    let a = one.attach_circuit(&peer).unwrap().addr();
    let b = two.attach_circuit(&peer).unwrap().addr();
    assert_ne!(
        a, b,
        "two nodes derived the same circuit address for one peer, so the address is a \
         function of the peer's identity — anybody holding that fingerprint can compute it"
    );

    // And not stable within one node either: a fresh circuit is a fresh address, so an
    // address that leaked once does not identify the circuit that replaces it.
    let again = one.attach_circuit(&peer).unwrap().addr();
    assert_ne!(
        a, again,
        "re-attaching reused the address, so a leaked address keeps identifying the peer"
    );
}

/// **Contained, and in the socket's own address family.**
///
/// The range is IPv4 whatever the socket is, because quinn refuses an IPv6 destination on
/// an IPv4 socket and maps an IPv4 one on an IPv6 socket — so IPv4 is the only family that
/// works on both, and endpoints here bind IPv4. Containment is all the range provides;
/// identification is the table's job, which is what makes it safe that real networks use
/// this range privately.
#[tokio::test]
async fn a_circuit_address_is_contained_and_dialable_by_this_socket() {
    let peer = RootSigner::public_key(&signer(8)).fingerprint();
    let ep = endpoint(3);
    let addr = ep.attach_circuit(&peer).unwrap().addr();

    assert!(
        vox_core::transport::mux::in_circuit_range(addr),
        "a circuit address must stay inside the range circuits are allocated from: {addr}"
    );
    match addr.ip() {
        IpAddr::V4(v4) => {
            assert!(
                !v4.is_loopback() && !v4.is_multicast() && !v4.is_broadcast(),
                "a circuit address must not name a real local destination: {v4}"
            );
        }
        IpAddr::V6(v6) => panic!(
            "a circuit address is IPv6 ({v6}); quinn refuses an IPv6 destination on the \
             IPv4 socket these endpoints bind, so no datagram would ever reach the circuit"
        ),
    }
}

/// **Known, not guessed.**
///
/// Whether an address is a circuit is a fact the mux records. Asking its shape instead
/// answers wrongly in both directions: an address inside the subnet with nothing attached
/// is not a circuit, and code that guessed would treat it as one — which is what fed the
/// connection manager's relay-first/upgrade-later rule a false premise.
#[tokio::test]
async fn only_an_attached_address_is_a_circuit() {
    let peer = RootSigner::public_key(&signer(7)).fingerprint();
    let ep = endpoint(4);

    let port = ep.attach_circuit(&peer).unwrap();
    let live = port.addr();
    assert!(
        ep.is_circuit(live),
        "an attached circuit must be recognised"
    );
    assert_eq!(ep.circuit_addr_of(&peer), Some(live));

    // An address in the range that nothing is attached to. Same shape, not a circuit —
    // and on a host whose VPN happens to use this range, this is what a *real* interface
    // address looks like to code that only inspects the range.
    let mut o = match live.ip() {
        IpAddr::V4(v4) => v4.octets(),
        IpAddr::V6(v6) => unreachable!("circuit addresses are IPv4: {v6}"),
    };
    o[3] ^= 0xFF;
    let unattached = SocketAddr::new(IpAddr::V4(o.into()), live.port());
    assert_ne!(
        unattached, live,
        "the probe must differ from the live circuit"
    );
    assert!(
        vox_core::transport::mux::in_circuit_range(unattached),
        "the probe must be in the range, or it tests nothing"
    );
    assert!(
        !ep.is_circuit(unattached),
        "an address in the subnet with no circuit attached was reported as a circuit — \
         the answer is being guessed from the address instead of read from the table"
    );

    // Dropping the port detaches it, and the address stops being a circuit.
    drop(port);
    assert!(!ep.is_circuit(live), "a detached circuit is not a circuit");
    assert_eq!(ep.circuit_addr_of(&peer), None);
}
