//! ADR-017 **M17.11 proof** — a stream parked open across a withdrawal of trust is
//! refused, and the service behind it is never touched.
//!
//! The attack needs no timing skill, only patience. A host decides who may reach its
//! services, and that decision is read when a tunnel is served. If the host reads it
//! when the *stream opens* rather than when the *request arrives*, a peer can:
//!
//! 1. open a tunnel stream while it is still trusted,
//! 2. say nothing — QUIC is happy to hold an idle stream open,
//! 3. wait for the operator to remove it from the ring,
//! 4. and only then send its request, to be judged by a decision taken before the
//!    removal.
//!
//! Everything here is real: a real QUIC connection between two real endpoints, the real
//! `session::accept` server, the real length-delimited tunnel wire, and a real TCP
//! service on the host's loopback. The client is hostile by construction — it writes the
//! request frame itself so it can choose *when* — which is the only way to produce a
//! parked stream, since no honest client (`vox up`, `vox connect`) ever delays.
//!
//! What it asserts:
//!
//! - the parked request is **Denied**, and
//! - the echo service **never accepted a connection** — the refusal happens before
//!   anything is dialled, so the withdrawal is not merely reported but enforced.
//!
//! The second test covers the other half of the milestone: a session that is **already
//! carrying bytes** when reach is withdrawn. An `ssh` login opened an hour ago is exactly
//! what an operator means to cut, and the serving task cannot ask the actor, so it watches
//! the same live set the dial gate read. The stream is **reset**, not finished, with
//! `REACH_WITHDRAWN_CODE` — a clean close would be indistinguishable from the carried
//! service hanging up — and the dialer surfaces `Error::TunnelRevoked` rather than a
//! generic splice failure.
//!
//! Mutation checks (each one turns a test here red):
//!
//! - make `ChannelServices::reachers` a plain `Arc<BTreeSet<_>>` snapshotted per accept →
//!   the parked request is **Accepted** and the echo logs a connection;
//! - drop the `changed()` arm from `splice_until_withdrawn` → the live session keeps
//!   flowing after the withdrawal;
//! - `finish()` instead of `reset()` → the dialer reports a plain EOF and cannot tell a
//!   withdrawal from the service closing normally.

#[path = "support/watchdog.rs"]
mod watchdog;

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;

use vox_core::governance::capability::CapabilitySet;
use vox_core::governance::evaluator::Evaluator;
use vox_core::governance::genesis::{ChannelPolicy, DeniabilityMode, Genesis, HistoryMode};
use vox_core::identity::composite::{RootSigner, SoftwareRootSigner};
use vox_core::transport::quic::VoxEndpoint;
use vox_core::transport::streams::{accept_typed, open_typed, StreamKind};
use vox_core::tunnel::session::{self, HostService, TunnelRequest};

const NOW: u64 = 1_800_000_000;

fn signer(a: u8) -> SoftwareRootSigner {
    SoftwareRootSigner::from_component_seeds(&[a; 32], &[a ^ 0xFF; 32]).unwrap()
}

fn policy() -> ChannelPolicy {
    ChannelPolicy {
        history_mode: HistoryMode::ForwardOnly,
        deniability_mode: DeniabilityMode::Attributable,
        ttl: 0,
        min_suite: vox_core::suite::SuiteFloor::DAY_ONE.id(),
    }
}

/// Run the proof once against a given reacher set, returning
/// `(status_byte, echo_connections)`.
async fn park_across_withdrawal() -> (u8, usize) {
    // ---- a real service on the host's loopback that counts who reaches it ----
    let hits = Arc::new(AtomicUsize::new(0));
    let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo.local_addr().unwrap();
    {
        let hits = Arc::clone(&hits);
        tokio::spawn(async move {
            while let Ok((mut s, _)) = echo.accept().await {
                hits.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    let (mut r, mut w) = s.split();
                    let _ = tokio::io::copy(&mut r, &mut w).await;
                });
            }
        });
    }

    let host_signer = signer(0x11);
    let client_signer = signer(0x1b);
    let client_fp = RootSigner::public_key(&client_signer).fingerprint();

    // A room with no service grant of any kind: since M17.7 the genesis does not decide
    // reach, the host's ring does. The evaluator is here because a tunnel is still served
    // under a channel, not because it authorizes anybody.
    let genesis = Genesis::create_with_nonce_and_grant(
        &host_signer,
        NOW,
        policy(),
        CapabilitySet::new(),
        [0x11; 16],
    )
    .unwrap();
    let channel_id = genesis.channel_id();
    let authors: std::collections::BTreeMap<_, _> =
        [(client_fp, RootSigner::public_key(&client_signer))]
            .into_iter()
            .collect();
    let evaluator = Arc::new(
        Evaluator::build_with_members(
            &genesis,
            &[],
            NOW,
            |id| authors.get(id).cloned(),
            [client_fp].into_iter().collect(),
        )
        .unwrap(),
    );

    // The live reacher set the actor owns (`node::tunnel::Reachers`). The client starts in
    // it: at the moment it opens its stream it is trusted and a current author, which is
    // exactly the state the attack begins from.
    let reachers: vox_core::node::tunnel::Reachers = Arc::new(tokio::sync::watch::Sender::new(
        [client_fp].into_iter().collect::<BTreeSet<_>>(),
    ));

    // ---- the host: the real server, taking its snapshot when the stream opens ----
    let host_ep = VoxEndpoint::bind(&host_signer, "127.0.0.1:0".parse().unwrap()).unwrap();
    let host_addr = host_ep.local_addr().unwrap();
    let host_id = host_ep.local_id();
    let served = Arc::new(tokio::sync::Notify::new());
    {
        let evaluator = Arc::clone(&evaluator);
        let reachers = Arc::clone(&reachers);
        let served = Arc::clone(&served);
        tokio::spawn(async move {
            while let Ok(Some(conn)) = host_ep.accept(NOW).await {
                let peer = conn.peer_id();
                let evaluator = Arc::clone(&evaluator);
                let reachers = Arc::clone(&reachers);
                let served = Arc::clone(&served);
                tokio::spawn(async move {
                    while let Ok((kind, send, recv)) = accept_typed(&conn).await {
                        if kind != StreamKind::Tunnel {
                            continue;
                        }
                        let evaluator = Arc::clone(&evaluator);
                        let reachers = Arc::clone(&reachers);
                        // The snapshot is taken HERE — when the stream opens, before a
                        // single byte of the request has been read. That is the actor's
                        // real shape (`Inbound::Tunnel` → `host_snapshot`), and it is why
                        // the set it carries has to be live rather than a copy.
                        served.notify_one();
                        tokio::spawn(async move {
                            let _ = session::accept(send, recv, &peer, |cid, _tag| {
                                (*cid == channel_id).then_some(HostService {
                                    evaluator,
                                    endpoint: echo_addr,
                                    reachers,
                                })
                            })
                            .await;
                        });
                    }
                });
            }
        });
    }

    // ---- the hostile client: open, park, wait out the withdrawal, then ask ----
    let client_ep = VoxEndpoint::bind(&client_signer, "127.0.0.1:0".parse().unwrap()).unwrap();
    let conn = client_ep.connect(host_addr, host_id, NOW).await.unwrap();
    let (mut send, mut recv) = open_typed(&conn, StreamKind::Tunnel).await.unwrap();

    // Wait until the host has actually taken its snapshot for this stream. Without this
    // the test could pass by losing the race rather than by the fix working.
    tokio::time::timeout(Duration::from_secs(10), served.notified())
        .await
        .expect("the host served the parked stream");

    // The operator removes the client from the ring. This is the write
    // `NodeActor::refresh_reachers` performs — in place, into the set the serving task is
    // already holding, which is the whole of the fix.
    reachers.send_modify(|set| {
        set.remove(&client_fp);
    });

    // Only now does the request go out.
    let req = TunnelRequest {
        channel_id,
        service_tag: "22".to_owned(),
    };
    let body = req.to_bytes();
    let len = u32::try_from(body.len()).unwrap();
    send.write_all(&len.to_be_bytes()).await.unwrap();
    send.write_all(&body).await.unwrap();
    send.flush().await.unwrap();

    // Read the host's status frame off the wire ourselves.
    let mut len_buf = [0u8; 4];
    tokio::io::AsyncReadExt::read_exact(&mut recv, &mut len_buf)
        .await
        .expect("the host answered the parked request");
    let n = u32::from_be_bytes(len_buf) as usize;
    assert_eq!(n, 1, "a status frame is one byte");
    let mut status = [0u8; 1];
    tokio::io::AsyncReadExt::read_exact(&mut recv, &mut status)
        .await
        .unwrap();

    // Give a wrongly-accepted dial time to reach the echo, so the second assertion can
    // fail honestly rather than by being asked too early.
    tokio::time::sleep(Duration::from_millis(300)).await;
    (status[0], hits.load(Ordering::SeqCst))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn m17_11_a_parked_stream_is_refused_after_trust_is_withdrawn() {
    watchdog::arm();
    let (status, echo_hits) = park_across_withdrawal().await;
    assert_eq!(
        status, 0,
        "the parked request was ACCEPTED against a decision taken before the withdrawal — \
         a peer that simply waits defeats removal from the ring"
    );
    assert_eq!(
        echo_hits, 0,
        "the service was dialled for a peer the host had already removed: the refusal has \
         to happen before anything is connected, not after"
    );
}

/// A real spliced session, cut by a withdrawal while bytes are in flight.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn m17_11_a_live_session_is_cut_when_reach_is_withdrawn() {
    watchdog::arm();

    // An echo the test can keep a conversation going with, so the session is genuinely
    // live — not merely open — at the moment reach is withdrawn.
    let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = echo.accept().await {
            tokio::spawn(async move {
                let (mut r, mut w) = s.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });

    let host_signer = signer(0x21);
    let client_signer = signer(0x2b);
    let client_fp = RootSigner::public_key(&client_signer).fingerprint();
    let genesis = Genesis::create_with_nonce_and_grant(
        &host_signer,
        NOW,
        policy(),
        CapabilitySet::new(),
        [0x21; 16],
    )
    .unwrap();
    let channel_id = genesis.channel_id();
    let authors: std::collections::BTreeMap<_, _> =
        [(client_fp, RootSigner::public_key(&client_signer))]
            .into_iter()
            .collect();
    let evaluator = Arc::new(
        Evaluator::build_with_members(
            &genesis,
            &[],
            NOW,
            |id| authors.get(id).cloned(),
            [client_fp].into_iter().collect(),
        )
        .unwrap(),
    );
    let reachers: vox_core::node::tunnel::Reachers = Arc::new(tokio::sync::watch::Sender::new(
        [client_fp].into_iter().collect::<BTreeSet<_>>(),
    ));

    let host_ep = VoxEndpoint::bind(&host_signer, "127.0.0.1:0".parse().unwrap()).unwrap();
    let host_addr = host_ep.local_addr().unwrap();
    let host_id = host_ep.local_id();
    {
        let reachers = Arc::clone(&reachers);
        tokio::spawn(async move {
            while let Ok(Some(conn)) = host_ep.accept(NOW).await {
                let peer = conn.peer_id();
                let evaluator = Arc::clone(&evaluator);
                let reachers = Arc::clone(&reachers);
                tokio::spawn(async move {
                    while let Ok((kind, send, recv)) = accept_typed(&conn).await {
                        if kind != StreamKind::Tunnel {
                            continue;
                        }
                        let evaluator = Arc::clone(&evaluator);
                        let reachers = Arc::clone(&reachers);
                        tokio::spawn(async move {
                            let _ = session::accept(send, recv, &peer, |cid, _tag| {
                                (*cid == channel_id).then_some(HostService {
                                    evaluator,
                                    endpoint: echo_addr,
                                    reachers,
                                })
                            })
                            .await;
                        });
                    }
                });
            }
        });
    }

    // The dialer: a real local TCP socket spliced to a real tunnel, exactly as `vox up`
    // hands one over. `session::dial` owns the splice, so its return value is what a
    // client program would be told.
    let local = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local_addr = local.local_addr().unwrap();
    let mut app = tokio::net::TcpStream::connect(local_addr).await.unwrap();
    let (spliced, _) = local.accept().await.unwrap();

    let client_ep = VoxEndpoint::bind(&client_signer, "127.0.0.1:0".parse().unwrap()).unwrap();
    let conn = client_ep.connect(host_addr, host_id, NOW).await.unwrap();
    let (send, recv) = open_typed(&conn, StreamKind::Tunnel).await.unwrap();
    let dialing =
        tokio::spawn(async move { session::dial(send, recv, &channel_id, "22", spliced).await });

    // Prove the session is alive: a round trip through the real echo, end to end.
    app.write_all(b"alive before the withdrawal").await.unwrap();
    let mut back = [0u8; 27];
    tokio::time::timeout(
        Duration::from_secs(10),
        tokio::io::AsyncReadExt::read_exact(&mut app, &mut back),
    )
    .await
    .expect("the tunnel carried bytes before the withdrawal")
    .unwrap();
    assert_eq!(&back, b"alive before the withdrawal");

    // Now the operator removes the client from the ring — the write the actor performs.
    reachers.send_modify(|set| {
        set.remove(&client_fp);
    });

    let outcome = tokio::time::timeout(Duration::from_secs(15), dialing)
        .await
        .expect("the live session ended on the withdrawal rather than flowing on")
        .unwrap();
    assert!(
        matches!(outcome, Err(vox_core::error::Error::TunnelRevoked(_))),
        "a live session survived the withdrawal, or ended without saying why: {outcome:?} \
         — the dialer must be able to tell a decision from a dropped connection"
    );
}

/// **A recompute is not a withdrawal.** The regression guard for the mid-session reset.
///
/// The actor re-derives every room's reacher set on **every accept**. It used to write them
/// with `watch::Sender::send_replace`, which notifies unconditionally — so each new tunnel
/// stream woke every serving task in every room, and a serving task answers a wake by
/// re-evaluating whether to tear down the live session it is carrying. That surfaced as
/// `Connection reset by peer` in the middle of a transfer with nobody having withdrawn
/// anything: reproduced on `edfdcc5` by a second session, reading the echo back.
///
/// The discriminating observable is **the wake itself, not the survival**, and getting that
/// right took a deleted draft. Under the old code a spurious wake happens and the task
/// usually re-checks membership successfully, so a test that merely keeps a session alive
/// across recomputes passes on the broken code too — it would have been a green test proving
/// nothing, which is the failure mode this repository has been bitten by all day.
///
/// So this asserts what the writer does, through the one function that writes these sets:
/// an unchanged recompute must not notify anybody. Mutation: put `send_replace` back inside
/// `publish_reachers` and the third assertion fails.
#[tokio::test]
async fn m17_11_an_unchanged_recompute_does_not_wake_the_serving_tasks() {
    let fp: vox_core::hash::Digest32 = [0x7A; 32];
    let other: vox_core::hash::Digest32 = [0x7B; 32];
    let handle = vox_core::node::tunnel::empty_reachers();
    let mut rx = handle.subscribe();

    // (1) The first real change notifies — without this the rest proves nothing, because a
    // writer that never notifies would also pass assertion (3) and would break withdrawal.
    let changed = vox_core::node::tunnel::publish_reachers(
        &handle,
        [fp].into_iter().collect::<BTreeSet<_>>(),
    );
    assert!(changed, "adding a reacher must count as a change");
    assert!(
        rx.has_changed().unwrap(),
        "a real change did not wake the serving tasks, so a withdrawal would not reach a \
         live session either"
    );
    let _ = rx.borrow_and_update();

    // (2) Recomputing the *same* set, as every accept does, must change nothing...
    let changed = vox_core::node::tunnel::publish_reachers(
        &handle,
        [fp].into_iter().collect::<BTreeSet<_>>(),
    );
    assert!(
        !changed,
        "an identical recompute reported itself as a change"
    );

    // (3) ...and must not wake anybody. This is the bug: a wake here makes every serving
    // task re-decide whether to cut the session it is carrying, on every accept.
    assert!(
        !rx.has_changed().unwrap(),
        "an unchanged recompute woke the serving tasks — every new tunnel stream then makes \
         every live session re-decide whether to tear itself down, and a person sees \
         `Connection reset by peer` mid-transfer with nothing having been withdrawn"
    );

    // (4) And a genuine withdrawal still gets through, which is what M17.11 is for.
    let changed = vox_core::node::tunnel::publish_reachers(
        &handle,
        [other].into_iter().collect::<BTreeSet<_>>(),
    );
    assert!(
        changed && rx.has_changed().unwrap(),
        "a withdrawal must still wake them"
    );
}
