//! The prefer-direct reachability ladder (ADR-012 §"Reachability strategy").
//!
//! Given a peer's advertised [`EndpointList`] (recovered from an authenticated
//! [`crate::nat::record::RendezvousRecord`]), connect over the M9 QUIC transport
//! preferring direct connections, in order:
//!
//! 1. **IPv6 direct**, then **IPv4 direct** — raced Happy-Eyeballs-style
//!    (RFC 8305): the first candidate is tried immediately, each subsequent
//!    candidate is launched after a short staggered delay, and the first QUIC
//!    connection that authenticates as the expected peer wins; the rest are
//!    cancelled. IPv6 candidates are ordered first ([`EndpointList::direct_candidates`]).
//! 2. **Hole-punch** (coordinated via [`crate::nat::holepunch`]) and **relay**
//!    (the relay-hint rung) are the fallbacks for peers with no reachable direct
//!    endpoint. Relay *data-plane* forwarding is ADR-013/M11; this module exposes
//!    the relay hints ([`EndpointList::relay_hints`]) and the direct/hole-punch
//!    rungs.
//!
//! Every attempt authenticates the peer cryptographically (M9 pins the expected
//! composite identity; a wrong identity aborts the handshake). Exhausting the
//! ladder returns [`Error::Unreachable`] — the honest ADR-012 limit, never a false
//! success.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::task::JoinSet;

use crate::error::{Error, Result};
use crate::hash::Digest32;
use crate::nat::multiaddr::EndpointList;
use crate::transport::quic::{VoxConnection, VoxEndpoint};

/// The Happy-Eyeballs "Connection Attempt Delay" (RFC 8305 §5): how long to wait
/// before launching the next candidate in parallel with those already in flight.
/// 250 ms is the RFC's recommended default (bounds simultaneous attempts while
/// still racing).
pub const CONNECTION_ATTEMPT_DELAY: Duration = Duration::from_millis(250);

/// Per-candidate hard timeout: an individual QUIC attempt that neither connects nor
/// fails within this window is abandoned (its slot frees for the next candidate).
pub const PER_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(10);

/// The ordered direct-connection candidates for a peer (IPv6 first, then IPv4),
/// taken from its advertised endpoints. This is the input to [`connect_direct`].
#[must_use]
pub fn direct_candidates(endpoints: &EndpointList) -> Vec<SocketAddr> {
    endpoints.direct_candidates()
}

/// Connect to `expected_peer` over QUIC by racing its direct candidates
/// Happy-Eyeballs-style (RFC 8305).
///
/// Returns the first [`VoxConnection`] that completes the M9 handshake authenticated
/// as `expected_peer`; remaining in-flight attempts are cancelled. Returns
/// [`Error::Unreachable`] if `candidates` is empty or every candidate fails.
///
/// `endpoint` is shared (`Arc`) so each raced attempt can run concurrently on the
/// same local QUIC endpoint. `now_secs` is the caller-supplied wall clock recorded
/// in the session-establishment entry (ADR-011).
pub async fn connect_direct(
    endpoint: Arc<VoxEndpoint>,
    candidates: &[SocketAddr],
    expected_peer: Digest32,
    now_secs: u64,
) -> Result<VoxConnection> {
    if candidates.is_empty() {
        return Err(Error::Unreachable("no direct candidates"));
    }

    let mut set: JoinSet<Result<VoxConnection>> = JoinSet::new();
    let mut next = 0usize;

    // Launch the first candidate immediately.
    spawn_attempt(
        &mut set,
        &endpoint,
        candidates[next],
        expected_peer,
        now_secs,
    );
    next += 1;

    loop {
        if next < candidates.len() {
            // Race a staggered launch of the next candidate against completion of
            // any in-flight attempt (RFC 8305 staggered start).
            tokio::select! {
                () = tokio::time::sleep(CONNECTION_ATTEMPT_DELAY) => {
                    spawn_attempt(&mut set, &endpoint, candidates[next], expected_peer, now_secs);
                    next += 1;
                }
                joined = set.join_next() => {
                    if let Some(conn) = take_success(joined) {
                        return Ok(conn); // JoinSet drop cancels the rest
                    }
                }
            }
        } else {
            // All candidates launched: drain remaining attempts.
            match set.join_next().await {
                Some(joined) => {
                    if let Some(conn) = take_success(Some(joined)) {
                        return Ok(conn);
                    }
                }
                None => return Err(Error::Unreachable("all direct candidates failed")),
            }
        }
    }
}

/// Spawn one staggered QUIC connection attempt onto `set`.
fn spawn_attempt(
    set: &mut JoinSet<Result<VoxConnection>>,
    endpoint: &Arc<VoxEndpoint>,
    addr: SocketAddr,
    expected_peer: Digest32,
    now_secs: u64,
) {
    let ep = Arc::clone(endpoint);
    set.spawn(async move {
        match tokio::time::timeout(
            PER_ATTEMPT_TIMEOUT,
            ep.connect(addr, expected_peer, now_secs),
        )
        .await
        {
            Ok(res) => res,
            Err(_) => Err(Error::Unreachable("direct attempt timed out")),
        }
    });
}

/// Interpret a `JoinSet::join_next` result: `Some(connection)` on a successful,
/// authenticated attempt; `None` if the attempt failed, timed out, or its task
/// panicked/was cancelled (the caller keeps draining the set).
fn take_success(
    joined: Option<std::result::Result<Result<VoxConnection>, tokio::task::JoinError>>,
) -> Option<VoxConnection> {
    match joined {
        Some(Ok(Ok(conn))) => Some(conn),
        // Connect error, timeout, or a join error (panic/cancel): not a success.
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::composite::SoftwareRootSigner;
    use crate::nat::multiaddr::Multiaddr;
    use std::net::{Ipv4Addr, SocketAddrV4};
    use tokio::runtime::Runtime;

    fn rt() -> Runtime {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    fn signer(a: u8, b: u8) -> SoftwareRootSigner {
        SoftwareRootSigner::from_component_seeds(&[a; 32], &[b; 32]).unwrap()
    }

    fn loopback(port: u16) -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port))
    }

    #[test]
    fn direct_candidates_order_v6_first() {
        let list = EndpointList::new(vec![
            Multiaddr::Ip4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 1)),
            Multiaddr::Ip6(std::net::SocketAddrV6::new(
                std::net::Ipv6Addr::LOCALHOST,
                2,
                0,
                0,
            )),
            Multiaddr::Relay([0u8; 32]),
        ])
        .unwrap();
        let cand = direct_candidates(&list);
        assert_eq!(cand.len(), 2, "relay excluded from direct candidates");
        assert!(cand[0].is_ipv6());
    }

    #[test]
    fn empty_candidates_is_unreachable() {
        let rt = rt();
        rt.block_on(async {
            let server = signer(9, 9);
            let ep = Arc::new(VoxEndpoint::bind(&server, loopback(0)).unwrap());
            let res = connect_direct(ep, &[], [0u8; 32], 1000).await;
            assert!(matches!(res, Err(Error::Unreachable(_))));
        });
    }

    #[test]
    fn races_past_a_dead_candidate_to_the_live_one() {
        let rt = rt();
        rt.block_on(async {
            // Real server endpoint with an accept loop.
            let server_signer = signer(1, 2);
            let server = Arc::new(VoxEndpoint::bind(&server_signer, loopback(0)).unwrap());
            let server_addr = server.local_addr().unwrap();
            let server_id = server.local_id();
            let accept_server = Arc::clone(&server);
            tokio::spawn(async move {
                // Accept a couple of connections (the live candidate).
                for _ in 0..2 {
                    if (accept_server.accept(1000).await).is_err() {
                        break;
                    }
                }
            });

            // A dead candidate: an address with no listener. Bind+drop to obtain a
            // free port that will refuse/blackhole.
            let dead = {
                let s = tokio::net::UdpSocket::bind(loopback(0)).await.unwrap();
                let a = s.local_addr().unwrap();
                drop(s);
                a
            };

            let client_signer = signer(3, 4);
            let client = Arc::new(VoxEndpoint::bind(&client_signer, loopback(0)).unwrap());
            // Dead candidate first, live second: Happy-Eyeballs must still succeed.
            let candidates = vec![dead, server_addr];
            let conn = tokio::time::timeout(
                Duration::from_secs(15),
                connect_direct(client, &candidates, server_id, 1000),
            )
            .await
            .expect("did not hang")
            .expect("connects to the live candidate");
            assert_eq!(conn.peer_id(), server_id);
        });
    }

    #[test]
    fn all_dead_candidates_is_unreachable() {
        let rt = rt();
        rt.block_on(async {
            let dead1 = {
                let s = tokio::net::UdpSocket::bind(loopback(0)).await.unwrap();
                let a = s.local_addr().unwrap();
                drop(s);
                a
            };
            let client_signer = signer(3, 4);
            let client = Arc::new(VoxEndpoint::bind(&client_signer, loopback(0)).unwrap());
            // One unreachable candidate; pin a random expected peer it can never be.
            let res = tokio::time::timeout(
                Duration::from_secs(15),
                connect_direct(client, &[dead1], [7u8; 32], 1000),
            )
            .await
            .expect("did not hang");
            assert!(matches!(res, Err(Error::Unreachable(_))));
        });
    }
}
