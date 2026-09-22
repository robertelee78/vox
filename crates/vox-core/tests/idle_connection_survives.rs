//! A Vox connection must survive going quiet.
//!
//! Vox carries tunnels: an `ssh` session between keystrokes, a port-forward waiting on the
//! far end, a room nobody is talking in. quinn's default `max_idle_timeout` is 30 seconds
//! and its default `keep_alive_interval` is `None` — so on defaults a connection dies after
//! half a minute of silence and nothing keeps it warm. For a person that is their session
//! dropping while they read.
//!
//! This holds a real connection between two real endpoints silent for longer than that
//! default and then uses it. It takes ~40 seconds of wall clock, which is the point: the
//! property is about time passing and cannot be asserted any faster.

use std::sync::Arc;
use std::time::{Duration, Instant};

use vox_core::identity::composite::SoftwareRootSigner;
use vox_core::transport::quic::VoxEndpoint;
use vox_core::transport::streams::{accept_typed, open_typed, StreamKind};

const NOW: u64 = 1_800_000_000;

/// Longer than quinn's 30s default idle timeout, with margin.
const SILENCE: Duration = Duration::from_secs(40);

fn signer(a: u8) -> SoftwareRootSigner {
    SoftwareRootSigner::from_component_seeds(&[a; 32], &[a ^ 0x77; 32]).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "spends 40s of wall clock waiting for an idle timeout that must not fire"]
async fn a_connection_idle_past_quinns_default_timeout_still_carries_bytes() {
    let server = VoxEndpoint::bind(&signer(0x41), "127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = server.local_addr().unwrap();
    let id = server.local_id();

    let accepted = tokio::spawn(async move {
        let conn = server.accept(NOW).await.unwrap().unwrap();
        // Answer one stream, whenever it comes — after the silence, in this test.
        let (kind, mut send, mut recv) = accept_typed(&conn).await.unwrap();
        assert_eq!(kind, StreamKind::Sync);
        let mut buf = [0u8; 5];
        tokio::io::AsyncReadExt::read_exact(&mut recv, &mut buf)
            .await
            .unwrap();
        tokio::io::AsyncWriteExt::write_all(&mut send, &buf)
            .await
            .unwrap();
        send.finish().unwrap();
        // Hold the connection so it is not closed by being dropped.
        tokio::time::sleep(Duration::from_secs(5)).await;
    });

    let client = VoxEndpoint::bind(&signer(0x42), "127.0.0.1:0".parse().unwrap()).unwrap();
    let conn = Arc::new(client.connect(addr, id, NOW).await.unwrap());

    // Say nothing at all for longer than quinn's default idle timeout.
    let quiet_from = Instant::now();
    tokio::time::sleep(SILENCE).await;
    assert!(
        quiet_from.elapsed() >= Duration::from_secs(31),
        "the test did not actually stay silent past the 30s default"
    );

    assert!(
        conn.quinn().close_reason().is_none(),
        "the connection was closed after {:?} of silence: {:?} — on quinn's defaults the \
         idle timeout is 30s and no keep-alive is sent, so a tunnel dies whenever nobody \
         types for half a minute",
        quiet_from.elapsed(),
        conn.quinn().close_reason()
    );

    // And it still works, which is the property a person cares about.
    let (mut send, mut recv) = open_typed(&conn, StreamKind::Sync).await.unwrap();
    tokio::io::AsyncWriteExt::write_all(&mut send, b"awake")
        .await
        .unwrap();
    send.finish().unwrap();
    let mut back = [0u8; 5];
    tokio::time::timeout(
        Duration::from_secs(10),
        tokio::io::AsyncReadExt::read_exact(&mut recv, &mut back),
    )
    .await
    .expect("the idle connection still carries a new stream")
    .unwrap();
    assert_eq!(&back, b"awake");

    accepted.abort();
}
