//! One stream, no bytes, and the node must keep working.
//!
//! The actor is a single task on purpose: it is the only writer of channel state, which is
//! what makes that state safe without locks (ADR-016). The consequence is that anything it
//! awaits inline stops **everything** — commands, the tick, and, once the network queue
//! fills, accepting connections at all.
//!
//! Three inbound stream kinds were handled inline, and every read underneath them was
//! unbounded. So a peer needed one stream and zero bytes to stop a node permanently: open a
//! `Sync` stream, send nothing, and the read never returns. The connection's own liveness is
//! no defence — Vox keeps connections alive with a QUIC keep-alive, so quinn PINGs the
//! connection for ever while the stream stays silent.
//!
//! No credential beyond a valid identity is needed, which makes it a denial of service any
//! member can perform, and an anchor — always on, always addressable — is the worst target.
//!
//! This opens the stream and says nothing, then asks the node to do ordinary work.

#[path = "support/watchdog.rs"]
mod watchdog;

use std::sync::Arc;
use std::time::{Duration, Instant};

use vox_core::identity::composite::SoftwareRootSigner;
use vox_core::transport::quic::VoxEndpoint;
use vox_core::transport::streams::{open_typed, StreamKind};

const NOW: u64 = 1_800_000_000;

fn signer(a: u8) -> SoftwareRootSigner {
    SoftwareRootSigner::from_component_seeds(&[a; 32], &[a ^ 0x2E; 32]).unwrap()
}

/// Two assertions, and the second is the one that matters.
///
/// A mock loop that reads inline would only measure `framing::FRAME_PATIENCE` — it would go
/// green the moment reads were bounded, while a real node was still frozen for thirty seconds
/// per stream. So the first test keeps that mock, because a bound is worth having and worth
/// guarding; and the second drives a **real node** and asserts it answers a command
/// immediately, which is only true once the read is off the actor's task entirely.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_peer_that_opens_a_stream_and_says_nothing_does_not_stop_the_loop() {
    watchdog::arm();
    let server = VoxEndpoint::bind(&signer(0x51), "127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = server.local_addr().unwrap();
    let id = server.local_id();

    // How many frames the loop has managed to read. The wedge shows up as this never
    // advancing past the silent stream.
    let served = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    {
        let served = Arc::clone(&served);
        tokio::spawn(async move {
            while let Ok(Some(conn)) = server.accept(NOW).await {
                let served = Arc::clone(&served);
                tokio::spawn(async move {
                    // Inline, one at a time — the actor's shape.
                    while let Ok((_kind, _send, mut recv)) =
                        vox_core::transport::streams::accept_typed(&conn).await
                    {
                        let _ = vox_core::transport::framing::read_frame(&mut recv, 4096).await;
                        served.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    }
                });
            }
        });
    }

    let client = VoxEndpoint::bind(&signer(0x52), "127.0.0.1:0".parse().unwrap()).unwrap();
    let conn = Arc::new(client.connect(addr, id, NOW).await.unwrap());

    // The attack: open a stream, write nothing, keep it open.
    let (_silent_send, _silent_recv) = open_typed(&conn, StreamKind::Sync).await.unwrap();

    // Now ordinary work. A second stream that DOES send a frame must be served.
    tokio::time::sleep(Duration::from_millis(200)).await;
    let (mut send, _recv) = open_typed(&conn, StreamKind::Sync).await.unwrap();
    vox_core::transport::framing::write_frame(&mut send, b"ordinary work")
        .await
        .unwrap();

    let started = Instant::now();
    let progressed = tokio::time::timeout(Duration::from_secs(45), async {
        loop {
            // Two frames read means the silent stream did not block the second.
            if served.load(std::sync::atomic::Ordering::SeqCst) >= 2 {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;

    assert!(
        progressed.is_ok(),
        "the loop served no further frame for {:?} after a peer opened a stream and said \
         nothing — one stream and zero bytes stop the node, from any peer holding a valid \
         identity, and the QUIC keep-alive means it never times out on its own",
        started.elapsed()
    );
}

// A second test drove a real node and asserted it answers commands while a peer holds a
// silent sync stream. It was DELETED rather than kept, because it passed against the unfixed
// code: an unknown peer may only open `Rendezvous` and `Coord` streams (`node::net`'s
// stream-kind gate), so its `Sync` stream was refused before it ever reached the actor, and
// the test was measuring a refusal rather than a wedge.
//
// The severity claimed next was WRONG, and is corrected here rather than quietly dropped.
// It read: "Reproducing the wedge needs an attacker that is already an admitted member of a
// room the victim holds, which is the honest severity: an insider denial of service, not an
// anonymous one." An audit found otherwise. A stranger reaches `PendingJoiner` by itself —
// connect, open `Rendezvous`, publish a self-signed pre-join naming any channelID the board
// serves — and `PendingJoiner` may open `Join`. A channelID is the public `.vox` name, so
// the wedge was reachable by anyone who had ever been handed an address.
//
// That is now both fixed and proved, in `a_vox_name_is_not_a_licence_to_wedge.rs`. The
// lesson this note carried is still the right one, and it is the reason the claim above went
// unchallenged for as long as it did: a stream kind refused at the gate makes a test go green
// for the wrong reason, so the escalation itself must be asserted, not assumed.
