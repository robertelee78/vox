//! ADR-012 M15.1b — a better path displacing a worse one must not cut what the worse one
//! is carrying.
//!
//! One connection per peer is a *preference*: when a direct path appears behind a relayed
//! one, the direct one replaces it and the relayed one is retired. Retirement is not a
//! close — anything still riding the old path has to finish on it, and what rides these
//! paths is a tunnel, so "finish" can mean hours of an `ssh` session or a file transfer,
//! not the tail of one request.
//!
//! So a retired connection is closed when the grace has passed **and** nothing is still
//! carried on it. The strong count of the `Arc` is that signal: a tunnel task holds one for
//! as long as it splices.

use std::sync::Arc;
use std::time::Duration;

use vox_core::hash::Digest32;
use vox_core::identity::composite::SoftwareRootSigner;
use vox_core::node::net::ConnectionManager;
use vox_core::transport::quic::VoxEndpoint;

fn signer(a: u8) -> SoftwareRootSigner {
    SoftwareRootSigner::from_component_seeds(&[a; 32], &[a ^ 0x3C; 32]).unwrap()
}

/// A manager whose clock we drive, so the grace can be stepped over without waiting.
fn manager(a: u8, now: Arc<std::sync::atomic::AtomicU64>) -> ConnectionManager {
    let ep = Arc::new(VoxEndpoint::bind(&signer(a), "127.0.0.1:0".parse().unwrap()).unwrap());
    let clock = {
        let now = Arc::clone(&now);
        Arc::new(move || now.load(std::sync::atomic::Ordering::SeqCst)) as vox_core::time::Clock
    };
    ConnectionManager::with_retire_grace(ep, clock, 60)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_retired_connection_stays_open_while_it_is_still_carrying() {
    use std::sync::atomic::{AtomicU64, Ordering};
    let now = Arc::new(AtomicU64::new(1_000));
    let a = manager(1, Arc::clone(&now));

    // A real connection between two endpoints, adopted so the manager owns it the way it
    // owns a dialled one.
    let b_ep = VoxEndpoint::bind(&signer(2), "127.0.0.1:0".parse().unwrap()).unwrap();
    let b_addr = b_ep.local_addr().unwrap();
    let b_id = b_ep.local_id();
    let accepting = tokio::spawn(async move { b_ep.accept(1_000).await });
    let dialled = a.endpoint().connect(b_addr, b_id, 1_000).await.unwrap();
    let _server = accepting.await.unwrap().unwrap();
    let held = a.adopt(dialled);

    // Displace it: a second connection to the same peer on a path the manager prefers, or
    // failing that, retire it directly the way `file` does. Either way it lands in the
    // retiring list, which is what this test is about.
    let second_ep = VoxEndpoint::bind(&signer(3), "127.0.0.1:0".parse().unwrap()).unwrap();
    let _ = second_ep;
    a.retire_for_test(&held);
    assert_eq!(a.retiring_count(), 1, "the connection is retired");

    // The grace passes. Something is still carrying on it — this test holds the `Arc`, as a
    // splicing tunnel task would — so it must not be closed.
    now.store(1_000 + 61, Ordering::SeqCst);
    assert_eq!(
        a.retire_expired(),
        0,
        "a carried connection was closed on the timer"
    );
    assert_eq!(a.retiring_count(), 1);
    assert!(
        held.quinn().close_reason().is_none(),
        "the connection carrying traffic was closed when the grace expired — a live ssh \
         session or file transfer dies here, mid-stream, because a better path appeared"
    );

    // Once nothing is carried, it goes on the next sweep.
    drop(held);
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(
        a.retire_expired(),
        1,
        "an uncarried, expired connection must be closed"
    );
    assert_eq!(a.retiring_count(), 0);
}

/// The grace still applies: a connection nothing is carrying is closed when it expires,
/// not kept for ever.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_uncarried_retired_connection_still_closes_on_time() {
    use std::sync::atomic::{AtomicU64, Ordering};
    let now = Arc::new(AtomicU64::new(2_000));
    let a = manager(4, Arc::clone(&now));

    let b_ep = VoxEndpoint::bind(&signer(5), "127.0.0.1:0".parse().unwrap()).unwrap();
    let b_addr = b_ep.local_addr().unwrap();
    let b_id: Digest32 = b_ep.local_id();
    let accepting = tokio::spawn(async move { b_ep.accept(2_000).await });
    let dialled = a.endpoint().connect(b_addr, b_id, 2_000).await.unwrap();
    let _server = accepting.await.unwrap().unwrap();
    let held = a.adopt(dialled);
    a.retire_for_test(&held);
    drop(held);

    now.store(2_000 + 59, Ordering::SeqCst);
    assert_eq!(a.retire_expired(), 0, "closed before its grace elapsed");
    now.store(2_000 + 61, Ordering::SeqCst);
    assert_eq!(a.retire_expired(), 1, "not closed after its grace elapsed");
}
