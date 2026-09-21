//! ADR-020 **M19.1 gate** — several clients attach to one node, and none of them
//! can stall it.
//!
//! Agent comms puts more than one local client on a single harness node (ADR-020
//! §2: one node per `(host, harness)`, many agent sessions). Before M19.1 the
//! actor emitted every event with `event_tx.send(..).await` on a bounded `mpsc`,
//! and the actor is a single `select!` loop — so **one client that stopped
//! draining blocked the actor after exactly `EVENT_QUEUE` events**, taking sync
//! and every command down with it. Measured before the change: the producer
//! blocked at exactly 256.
//!
//! What this gate proves, with a wedged client attached the whole time:
//!
//! 1. the node keeps answering commands — far past the buffer depth;
//! 2. a second client that does keep draining still receives everything;
//! 3. the wedged client is **told** it lagged rather than silently skipped, and
//!    then recovers — which is safe only because an event is a wake and the
//!    ADR-008 log is the durable record (ADR-020 §7).
//!
//! Mutation-checked, both run and observed to fail:
//!
//! - swallow the lag report (recurse past `RecvError::Lagged` instead of
//!   surfacing it) — the gate fails with "lag was silently swallowed", having
//!   received `message 145` where a report was due;
//! - raise `EVENT_QUEUE` to 100 000 so the wedged client never falls behind — the
//!   gate fails the same way, at `message 0`, which proves it exercises the real
//!   buffer rather than passing by luck.
//!
//! Property (1) is **not** mutation-checked by restoring the old emission,
//! because the old code cannot express this test at all: every `NodeHandle` clone
//! shared one `Arc<Mutex<mpsc::Receiver>>`, so two clients could not each receive
//! every event. The stall itself was measured directly in the M19.1 spike — a
//! bounded `mpsc(256)` with a consumer that stopped reading blocked its producer
//! after exactly 256 sends. The watchdog below is armed because that failure mode
//! is a hang, and a hung test is silent (ADR-018 §6).
//!
//! Production Argon2id is paid once at setup; the 400 appends afterwards are
//! cheap. `#[ignore]`d in the debug suite, like every other real-parameter gate.

#[path = "support/watchdog.rs"]
mod watchdog;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use vox_core::node::actor::{Clock, EventStreamItem, Node, NodeHandle};
use vox_core::node::api::{NodeCommand, NodeEvent, Secret};
use vox_core::node::paths::Paths;

/// Comfortably more than `EVENT_QUEUE` (256), so the wedged subscriber must lag.
const MESSAGES: usize = 400;

fn secret(s: &str) -> Secret {
    Secret::new(s.as_bytes().to_vec())
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap()
}

fn spawn(rt: &tokio::runtime::Runtime, paths: &Paths) -> NodeHandle {
    let clock: Clock = Arc::new(|| 1_800_000_000);
    rt.block_on(async {
        Node::spawn_with(
            paths.clone(),
            clock,
            vox_core::atrest::sek::Argon2Profile::default(),
        )
    })
    .unwrap()
}

#[test]
#[ignore = "production Argon2id at setup (≈2 s release / ≈30 s debug); CI runs it in release"]
fn m19_one_wedged_client_cannot_stall_the_node() {
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();
    let paths = Paths::resolve("m19", Some(tmp.path()), Some(&tmp.path().join("cfg"))).unwrap();

    let rt = runtime();
    let h = spawn(&rt, &paths);

    rt.block_on(async {
        assert!(h
            .apply(NodeCommand::CreateIdentity {
                passphrase: secret("identity passphrase"),
            })
            .await
            .is_done());
        assert!(h
            .apply(NodeCommand::CreateChannel {
                local_name: "fan-out gate".into(),
                passphrase: secret("channel passphrase"),
            })
            .await
            .is_done());
        let cid = h.view().channels[0].channel_id;

        // Client A subscribes and then NEVER reads. Before M19.1 this alone was
        // enough to stall the whole node once it fell `EVENT_QUEUE` behind.
        let mut wedged = h.subscribe();

        // Client B subscribes and drains continuously in its own task, counting
        // the messages it sees and reporting when the last one arrives.
        let mut keeping_up = h.subscribe();
        let seen = Arc::new(AtomicUsize::new(0));
        let seen_in_task = Arc::clone(&seen);
        let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();
        let reader = tokio::spawn(async move {
            let mut done_tx = Some(done_tx);
            let mut lagged = 0u64;
            while let Some(item) = keeping_up.next().await {
                match item {
                    EventStreamItem::Event(NodeEvent::NewEntry { row, .. }) => {
                        seen_in_task.fetch_add(1, Ordering::Relaxed);
                        if row.text == format!("message {}", MESSAGES - 1) {
                            if let Some(tx) = done_tx.take() {
                                let _ = tx.send(());
                            }
                        }
                    }
                    EventStreamItem::Lagged(n) => lagged += n,
                    EventStreamItem::Event(_) => {}
                }
            }
            lagged
        });

        // ---- the property: the node keeps working with a wedged client attached.
        for i in 0..MESSAGES {
            let outcome = h
                .apply(NodeCommand::SendText {
                    channel_id: cid,
                    text: format!("message {i}"),
                })
                .await;
            assert!(
                outcome.is_done(),
                "the node stopped answering at message {i} — a wedged subscriber stalled it"
            );
        }

        // Commands still work *after* the burst, not merely during it.
        assert!(h
            .apply(NodeCommand::SendText {
                channel_id: cid,
                text: "after the burst".into(),
            })
            .await
            .is_done());

        // (2) the client that kept draining saw the whole burst through to the end.
        tokio::time::timeout(Duration::from_secs(10), done_rx)
            .await
            .expect("the draining client never saw the last message")
            .expect("reader task dropped the signal");
        assert!(
            seen.load(Ordering::Relaxed) >= MESSAGES,
            "the draining client saw only {} of {MESSAGES} messages",
            seen.load(Ordering::Relaxed)
        );

        // (3) the wedged client is TOLD it lagged, and then recovers.
        let first = tokio::time::timeout(Duration::from_secs(5), wedged.next())
            .await
            .expect("wedged client blocked")
            .expect("stream closed");
        let missed = match first {
            EventStreamItem::Lagged(n) => n,
            other => panic!("expected a lag report, got {other:?} — lag was silently swallowed"),
        };
        assert!(missed > 0, "lag report claimed nothing was missed");

        // It resumes at the oldest retained event rather than being stuck.
        let resumed = tokio::time::timeout(Duration::from_secs(5), wedged.next())
            .await
            .expect("wedged client did not resume")
            .expect("stream closed after lag");
        assert!(
            matches!(resumed, EventStreamItem::Event(_)),
            "expected an event after the lag report, got {resumed:?}"
        );

        // And the log — the durable record the lagging client re-reads from — has
        // every message, which is what makes dropping events safe at all.
        let detail = h
            .view()
            .channels
            .into_iter()
            .find(|c| c.channel_id == cid)
            .expect("channel present");
        assert!(
            detail.entries > MESSAGES as u64,
            "the log holds {} entries, fewer than the {} appended",
            detail.entries,
            MESSAGES + 1
        );

        reader.abort();
    });
}
