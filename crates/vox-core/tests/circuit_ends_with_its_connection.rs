//! **A relay circuit ends when the connection it carries does** (PRD-001 R41's stuck relay
//! path).
//!
//! The R41 throughput gate kept finding its anchor still carrying a circuit minutes after
//! the forward it measured had gone direct. Instrumented, both ends held only direct
//! connections; the circuit belonged to a connection that had lost to a direct one — the
//! host dialled the guest while the guest's board address was still the one-shot
//! `vox connect`'s, so the relay rung won — and had been **closed** at both ends. Its circuit
//! stayed up anyway: the relay forwards the inner connection's packets without reading
//! them, so it cannot see a CONNECTION_CLOSE go by, and the ends' circuit drivers ran until
//! their flow ended or `CIRCUIT_IDLE_TIMEOUT` (five minutes) passed. So a relay slot, and an
//! anchor's "circuit carried", outlived every connection that used it.
//!
//! The scene: A and B behind symmetric NATs, C their relay; A reaches B, and the only
//! path is a circuit through C. A then closes that connection. C must stop carrying the
//! circuit within [`WITHIN`].
//!
//! Mutation-checked: with the initiator's driver no longer ended by its connection's close,
//! C still carries the circuit when the bound runs out.

#[path = "support/watchdog.rs"]
mod watchdog;

#[path = "support/vnet.rs"]
mod vnet;

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use vnet::{NatKind, VirtualNet};
use vox_core::hash::Digest32;
use vox_core::identity::composite::SoftwareRootSigner;
use vox_core::nat::multiaddr::{EndpointList, Multiaddr};
use vox_core::node::net::PeerPolicy;
use vox_core::node::network::NodeNet;
use vox_core::transport::quic::{Admission, VoxEndpoint};
use vox_core::wire::WireError;

const NOW: u64 = 1_800_000_000;

/// How soon after the inner connection closes the relay must let the circuit go: the
/// one-second linger that lets the close cross the circuit, plus room.
const WITHIN: Duration = Duration::from_secs(5);

fn signer(seed: u8) -> SoftwareRootSigner {
    SoftwareRootSigner::from_component_seeds(&[seed; 32], &[seed ^ 0xFF; 32]).unwrap()
}

fn run_node(net: Arc<NodeNet>) {
    let accept = Arc::clone(&net);
    tokio::spawn(async move {
        while let Ok(Some(conn)) = accept
            .manager()
            .accept(Admission::AcceptAnyAuthenticated)
            .await
        {
            serve(Arc::clone(&accept), conn);
        }
    });
}

fn serve(net: Arc<NodeNet>, conn: Arc<vox_core::transport::quic::VoxConnection>) {
    // Circuits are served inside `accept_stream`, as the node actor serves them.
    tokio::spawn(async move { while net.accept_stream(&conn).await.is_ok() {} });
}

fn members(net: &NodeNet, ids: &[Digest32]) {
    let mut policy = PeerPolicy::new();
    policy.add_members(ids.iter().copied());
    net.policy().replace(policy);
}

#[test]
fn a_circuit_ends_when_the_connection_it_carries_closes() {
    watchdog::arm();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let net = VirtualNet::new();
        let c_addr: SocketAddr = "198.51.100.1:443".parse().unwrap();
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        let a_sock = net.behind_nat(
            "10.0.1.2:5000".parse().unwrap(),
            NatKind::Symmetric,
            ip("203.0.113.1"),
        );
        let b_sock = net.behind_nat(
            "10.0.2.2:5000".parse().unwrap(),
            NatKind::Symmetric,
            ip("203.0.113.2"),
        );
        let c_sock = net.public(c_addr);
        let clock: vox_core::time::Clock = Arc::new(|| NOW);
        let node = |seed: u8, sock| {
            Arc::new(NodeNet::new(
                Arc::new(VoxEndpoint::bind_abstract(&signer(seed), sock).unwrap()),
                Arc::clone(&clock),
            ))
        };
        let (a, b, c) = (node(0x61, a_sock), node(0x62, b_sock), node(0x63, c_sock));
        let (a_id, b_id, c_id) = (a.local_id(), b.local_id(), c.local_id());
        members(&a, &[b_id, c_id]);
        members(&b, &[a_id, c_id]);
        members(&c, &[a_id, b_id]);
        for n in [&a, &b, &c] {
            run_node(Arc::clone(n));
        }
        let to_c = EndpointList::new(vec![Multiaddr::from(c_addr)]).unwrap();
        serve(
            Arc::clone(&a),
            a.manager().connect(c_id, &to_c).await.unwrap(),
        );
        serve(
            Arc::clone(&b),
            b.manager().connect(c_id, &to_c).await.unwrap(),
        );
        for _ in 0..100 {
            if c.manager().peers().len() == 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(c.manager().peers().len(), 2, "the relay holds both peers");

        // Step 1: the only path from A to B is a circuit through C.
        let conn = tokio::time::timeout(
            Duration::from_secs(60),
            a.reach(b_id, &EndpointList::default()),
        )
        .await
        .expect("reach did not hang")
        .expect("A reaches B through the relay");
        assert_eq!(
            a.manager().endpoint().circuit_addr_of(&b_id),
            Some(conn.quinn().remote_address()),
            "A's connection to B must run over a circuit, or this measures nothing"
        );
        let before = c.relaying();
        eprintln!("[test] step 1: the relay carries {before} circuit(s)");
        assert_eq!(before, 1, "the relay carries the circuit");

        // Step 2: A closes that connection, as it does a connection that lost to a direct
        // one. Nothing else touches the circuit.
        conn.close(WireError::AuthenticatorInvalid);
        let closed = Instant::now();
        let mut after = c.relaying();
        while after != 0 && closed.elapsed() < WITHIN {
            tokio::time::sleep(Duration::from_millis(50)).await;
            after = c.relaying();
        }
        eprintln!(
            "[test] step 2: {:?} after the connection closed, the relay carries {after} circuit(s)",
            closed.elapsed()
        );
        assert_eq!(
            after, 0,
            "a circuit must end when the connection it carried closes — the relay still \
             carried {after} after {WITHIN:?}"
        );
    });
}
