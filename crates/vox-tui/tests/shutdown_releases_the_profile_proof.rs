//! V29-16 (#51) — **a node that answers `Shutdown` has let go of its profile.**
//!
//! A process that runs a node and then hands its profile to another `vox` — a one-shot verb
//! finishing, or a test harness handing a joined profile to `vox daemon` — relies on `Done` meaning
//! the store is closed. It did not: `Shutdown` was answered before cleanup, and even after cleanup
//! the store stayed open for milliseconds, held by work that outlives the actor (a sync session on
//! a blocking thread, an aborted join exchange). The next `vox` on that profile was told "another
//! vox already has this profile open". `vox daemon` retries that, which hid it; a one-shot verb
//! does not retry, so this uses one.
//!
//! A `vox daemon` or `vox node` stopped with SIGTERM cannot show this: its profile is released
//! when the process exits, which the OS does whatever the node was doing. The window is only
//! visible while the process that ran the node is still alive, so bob's node runs in-process here
//! and the second opener is the shipped binary.
//!
//! Each round: bob's node opens and unlocks the profile, alice posts so bob has sync work when it
//! is told to stop, bob is shut down, and **the instant `Shutdown` answers `Done`** `vox trust list`
//! opens the same profile. Every handoff must open it.
//!
//! What this measures, and what it does not: answering `Shutdown` before cleanup (the original
//! defect) fails 50 of 51 handoffs. Removing only the bounded wait for the store's last reference
//! stays green, because these rounds do not reliably leave work running past the actor; that wait
//! is not proved here.

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::process::{Command, Stdio};
use std::time::Duration;

use vox_core::node::actor::{Node, NodeHandle};
use vox_core::node::api::{NodeCommand, NodeEvent, Secret};
use vox_core::node::paths::Paths;

const VOX: &str = env!("CARGO_BIN_EXE_vox");
const IDENTITY: &str = "identity passphrase";
const ROOM_PASS: &str = "channel passphrase";
/// Rounds of shut-down-then-open. The window this closes lost 3 of 4 handoffs before the fix.
const ROUNDS: usize = 50;

fn secret(s: &str) -> Secret {
    Secret::new(s.as_bytes().to_vec())
}

async fn wait_for<T>(h: &NodeHandle, mut f: impl FnMut(NodeEvent) -> Option<T>) -> T {
    tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            match h.next_event().await {
                Some(e) => {
                    if let Some(v) = f(e) {
                        return v;
                    }
                }
                None => panic!("event stream ended"),
            }
        }
    })
    .await
    .expect("timed out waiting for an event")
}

/// Open bob's profile with the shipped binary, a verb that does not retry a busy profile.
fn vox_opens(data: &std::path::Path, cfg: &std::path::Path) -> Result<(), String> {
    let out = Command::new(VOX)
        .args(["trust", "list"])
        .env("VOX_DATA_DIR", data)
        .env("VOX_CONFIG_DIR", cfg)
        .env("VOX_IDENTITY_PASSPHRASE", IDENTITY)
        .env_remove("VOX_ROOM")
        .stdin(Stdio::null())
        .output()
        .expect("spawn vox");
    if out.status.success() {
        Ok(())
    } else {
        Err(format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )
        .trim()
        .to_owned())
    }
}

#[test]
#[ignore = "two networked nodes, 50 shutdowns, production Argon2id; CI runs it in release"]
fn a_profile_is_free_the_moment_shutdown_answers_done() {
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap();
    let (a_data, a_cfg) = (tmp.path().join("a/data"), tmp.path().join("a/cfg"));
    let (b_data, b_cfg) = (tmp.path().join("b/data"), tmp.path().join("b/cfg"));
    let a_paths = Paths::resolve("default", Some(&a_data), Some(&a_cfg)).unwrap();
    let b_paths = Paths::resolve("default", Some(&b_data), Some(&b_cfg)).unwrap();

    // ---- alice stays up for the whole proof; bob joins and trusts once ----
    let (alice, cid) = rt.block_on(async {
        let alice = Node::spawn_networked(a_paths.clone(), "127.0.0.1:0".parse().unwrap()).unwrap();
        let bob = Node::spawn_networked(b_paths.clone(), "127.0.0.1:0".parse().unwrap()).unwrap();
        for n in [&alice, &bob] {
            assert!(n
                .apply(NodeCommand::CreateIdentity {
                    passphrase: secret(IDENTITY)
                })
                .await
                .is_done());
        }
        let (a_fp, b_fp) = (
            alice.view().identity.unwrap().fingerprint,
            bob.view().identity.unwrap().fingerprint,
        );
        assert!(alice
            .apply(NodeCommand::CreateChannel {
                local_name: "r".into(),
                passphrase: secret(ROOM_PASS)
            })
            .await
            .is_done());
        let cid = alice.view().channels[0].channel_id;
        assert!(alice
            .apply(NodeCommand::Invite { channel_id: cid })
            .await
            .is_done());
        let url = wait_for(&alice, |e| match e {
            NodeEvent::InviteLink { channel_id, url } if channel_id == cid => Some(url),
            _ => None,
        })
        .await;
        assert!(bob
            .apply(NodeCommand::JoinChannel {
                link: url,
                local_name: "r".into(),
                passphrase: secret(ROOM_PASS)
            })
            .await
            .is_done());
        for (n, peer, name) in [(&alice, b_fp, "bob"), (&bob, a_fp, "alice")] {
            assert!(n
                .apply(NodeCommand::Trust {
                    fingerprint: peer,
                    petname: name.into()
                })
                .await
                .is_done());
        }
        wait_for(&bob, |e| match e {
            NodeEvent::SenderKeyReceived {
                channel_id, peer, ..
            } if channel_id == cid && peer == a_fp => Some(()),
            _ => None,
        })
        .await;
        assert!(bob.apply(NodeCommand::Shutdown).await.is_done());
        (alice, cid)
    });

    // ---- the rounds: every `Done`, the join's included, is followed at once by the binary ----
    let mut opened = 0usize;
    let mut refused: Vec<String> = Vec::new();
    match vox_opens(&b_data, &b_cfg) {
        Ok(()) => opened += 1,
        Err(said) => refused.push(format!("after the join: {said}")),
    }
    for round in 0..ROUNDS {
        rt.block_on(async {
            // Bob's own reopen waits for the profile: it is the setup for the next handoff, not
            // the claim, and the claim's verdict must come from the binary above.
            let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
            let bob = loop {
                match Node::spawn_networked(b_paths.clone(), "127.0.0.1:0".parse().unwrap()) {
                    Ok(bob) => break bob,
                    Err(vox_core::error::Error::ProfileBusy)
                        if tokio::time::Instant::now() < deadline =>
                    {
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                    Err(e) => panic!("round {round}: bob's node could not open its profile: {e}"),
                }
            };
            assert!(
                bob.apply(NodeCommand::Unlock {
                    passphrase: secret(IDENTITY)
                })
                .await
                .is_done(),
                "round {round}: bob unlocks"
            );
            // A sync with alice in flight when bob is told to stop: that is the work that
            // outlived the actor.
            assert!(alice
                .apply(NodeCommand::SendText {
                    channel_id: cid,
                    text: format!("round {round}")
                })
                .await
                .is_done());
            tokio::time::sleep(Duration::from_millis((round as u64 * 37) % 400)).await;
            assert!(
                bob.apply(NodeCommand::Shutdown).await.is_done(),
                "round {round}: bob's Shutdown answers Done"
            );
        });
        // The instant `Done` came back: nothing in between.
        match vox_opens(&b_data, &b_cfg) {
            Ok(()) => opened += 1,
            Err(said) => refused.push(format!("round {round}: {said}")),
        }
    }
    eprintln!("[V29-16] `vox trust list` opened the profile the moment Shutdown answered Done: {opened} of {}", ROUNDS + 1);
    assert!(
        refused.is_empty(),
        "{} of {} handoffs found the profile still held after Shutdown answered Done:\n{}",
        refused.len(),
        ROUNDS + 1,
        refused.join("\n")
    );
}
