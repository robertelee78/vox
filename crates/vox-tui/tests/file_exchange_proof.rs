//! ADR-020 §11 / M19.8 — **a file crossing between two agents**, driven as real
//! binaries against two real nodes.
//!
//! The decision this proves is the decider's, and it replaced a draft of §11 that
//! would have carried file bytes through the log as chunked payloads:
//!
//! > "nc over vox over room bound service is the answer for files."
//!
//! So the bytes ride a room-bound service — the ADR-013/017 machinery that already
//! carries arbitrary TCP between members, encrypted and through NAT on both sides —
//! and the log carries only a **signed announcement** naming the file, its size and
//! its SHA-256. No new struct tag, no codec, no wire change.
//!
//! What it proves:
//!
//! 1. **A file crosses.** `vox room send` offers it and announces it; `vox room
//!    get` on a *different node with a different identity* collects it, and the
//!    bytes are identical.
//! 2. **The announcement is durable and the bytes are live.** The offer is
//!    discoverable from the log by name.
//! 3. **A transfer that does not match what was announced is refused, and the
//!    partial file is removed.** This is the property the hash exists for, and it
//!    has nothing to do with secrecy: `cat | nc` **truncates silently** — the
//!    connection drops, the receiver gets a partial file, and `nc` exits 0. A
//!    receiver that kept those bytes would reproduce that failure with extra steps.
//! 4. **Asking for something nobody offered says so**, rather than hanging or
//!    producing an empty file.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::process::{Child, Command, Stdio};

use vox_core::node::actor::{Node, NodeHandle};
use vox_core::node::api::{NodeCommand, NodeEvent, Secret};
use vox_core::node::paths::Paths;

const VOX: &str = env!("CARGO_BIN_EXE_vox");
const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

fn secret(s: &str) -> Secret {
    Secret::new(s.as_bytes().to_vec())
}

/// A long-running child, killed however the test ends.
struct Running(Child);

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct Agent {
    data: std::path::PathBuf,
    cfg: std::path::PathBuf,
    paths: Paths,
    node: NodeHandle,
}

impl Agent {
    fn vox(&self, args: &[&str]) -> (bool, String, String) {
        let out = Command::new(VOX)
            .args(args)
            .env("VOX_DATA_DIR", &self.data)
            .env("VOX_CONFIG_DIR", &self.cfg)
            .env_remove("VOX_ROOM")
            .stdin(Stdio::null())
            .output()
            .expect("spawn vox");
        (
            out.status.success(),
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    }

    fn spawn(&self, args: &[&str]) -> Running {
        Running(
            Command::new(VOX)
                .args(args)
                .env("VOX_DATA_DIR", &self.data)
                .env("VOX_CONFIG_DIR", &self.cfg)
                .env_remove("VOX_ROOM")
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("spawn vox"),
        )
    }
}

async fn agent(tmp: &tempfile::TempDir, name: &str) -> Agent {
    let data = tmp.path().join(name).join("data");
    let cfg = tmp.path().join(name).join("cfg");
    let paths = Paths::resolve("default", Some(&data), Some(&cfg)).unwrap();
    let node = Node::spawn_networked(paths.clone(), "127.0.0.1:0".parse().unwrap()).unwrap();
    assert!(node
        .apply(NodeCommand::CreateIdentity {
            passphrase: secret("identity passphrase"),
        })
        .await
        .is_done());
    Agent {
        data,
        cfg,
        paths,
        node,
    }
}

async fn wait_for<T>(h: &NodeHandle, mut f: impl FnMut(NodeEvent) -> Option<T>) -> T {
    tokio::time::timeout(TIMEOUT, async {
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

fn until(who: &Agent, what: &str, args: &[&str], ok: impl Fn(&str) -> bool) -> String {
    let deadline = std::time::Instant::now() + TIMEOUT;
    let mut last = String::new();
    while std::time::Instant::now() < deadline {
        let (_, out, err) = who.vox(args);
        last = format!("stdout={out:?} stderr={err:?}");
        if ok(&out) {
            return out;
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
    panic!("timed out waiting for {what}; last saw {last}");
}

#[test]
#[ignore = "two networked nodes and real child processes; CI runs it in release"]
fn a_file_crosses_between_two_agents_and_a_mismatch_is_refused() {
    watchdog::arm();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap();
    let tmp = tempfile::tempdir().unwrap();

    // Big enough to cross several 64 KiB reads, so a truncation is possible at all.
    let payload: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
    let source = tmp.path().join("artifact.bin");
    std::fs::write(&source, &payload).unwrap();

    let (alice, bob, room, _a_sock, _b_sock) = rt.block_on(async {
        let alice = agent(&tmp, "alice").await;
        let bob = agent(&tmp, "bob").await;
        let alice_fp = alice.node.view().identity.unwrap().fingerprint;
        let bob_fp = bob.node.view().identity.unwrap().fingerprint;

        assert!(alice
            .node
            .apply(NodeCommand::CreateChannel {
                local_name: "mission".into(),
                passphrase: secret("channel passphrase"),
            })
            .await
            .is_done());
        let cid = alice.node.view().channels[0].channel_id;
        assert!(alice
            .node
            .apply(NodeCommand::Invite { channel_id: cid })
            .await
            .is_done());
        let url = wait_for(&alice.node, |e| match e {
            NodeEvent::InviteLink { channel_id, url } if channel_id == cid => Some(url),
            _ => None,
        })
        .await;
        assert!(bob
            .node
            .apply(NodeCommand::JoinChannel {
                link: url,
                local_name: "mission".into(),
                passphrase: secret("channel passphrase"),
            })
            .await
            .is_done());

        // Joining grants nothing: each admits the other before either can read what
        // the other writes, which is also what makes the announcement's audience and
        // the transfer's audience the same set.
        for (who, peer, name) in [(&alice, bob_fp, "bob"), (&bob, alice_fp, "alice")] {
            assert!(who
                .node
                .apply(NodeCommand::Trust {
                    fingerprint: peer,
                    petname: name.into(),
                })
                .await
                .is_done());
        }
        for (who, peer) in [(&alice, bob_fp), (&bob, alice_fp)] {
            wait_for(&who.node, |e| match e {
                NodeEvent::SenderKeyReceived {
                    channel_id,
                    peer: p,
                    ..
                } if channel_id == cid && p == peer => Some(()),
                _ => None,
            })
            .await;
        }

        let a_sock = vox_core::node::ipc::bind(alice.node.clone(), &alice.paths).expect("alice");
        let b_sock = vox_core::node::ipc::bind(bob.node.clone(), &bob.paths).expect("bob");
        let room = vox_core::node::link::b32_encode(&cid);
        (alice, bob, room, a_sock, b_sock)
    });

    // ---- (4) nothing offered yet: asking says so ----
    let (ok, _, err) = bob.vox(&["room", "get", &room, "artifact.bin"]);
    assert!(!ok, "collecting something nobody offered must fail");
    assert!(
        err.contains("no offer in this room matches"),
        "it must say why: {err:?}"
    );

    // ---- (1) and (2) alice offers; the announcement reaches bob; bob collects ----
    let _offer = alice.spawn(&["room", "send", &room, source.to_str().unwrap()]);
    until(
        &bob,
        "the announcement to reach bob",
        &["room", "read", &room],
        |o| o.contains("artifact.bin"),
    );

    let dest = tmp.path().join("collected.bin");
    let (ok, out, err) = bob.vox(&[
        "room",
        "get",
        &room,
        "artifact.bin",
        "--out",
        dest.to_str().unwrap(),
    ]);
    assert!(
        ok,
        "bob could not collect the file: stdout={out:?} stderr={err:?}"
    );
    assert!(out.contains("verified"), "{out:?}");
    let got = std::fs::read(&dest).expect("the collected file");
    assert_eq!(
        got.len(),
        payload.len(),
        "the collected file is a different length"
    );
    assert!(
        got == payload,
        "the collected bytes differ from what was sent"
    );

    // ---- (3) a real truncation is refused, and the partial file is removed ----
    //
    // Not a hand-written announcement claiming the wrong hash — an actual short
    // transfer, which is the failure this exists to catch. `cat | nc` truncates
    // silently: the connection drops, the receiver gets a partial file, and `nc`
    // exits 0. Here the offered file is shortened on disk **after** it was
    // announced, so the sender serves fewer bytes than it signed for, exactly as a
    // dropped connection would.
    let flaky = tmp.path().join("flaky.bin");
    std::fs::write(&flaky, &payload).unwrap();
    let _flaky_offer = alice.spawn(&["room", "send", &room, flaky.to_str().unwrap()]);
    until(
        &bob,
        "the second announcement to reach bob",
        &["room", "read", &room],
        |o| o.contains("flaky.bin"),
    );

    // The offer re-opens the path for each collector, so shortening it now means the
    // next transfer is short — while the announced size and hash still describe the
    // whole file.
    std::fs::write(&flaky, &payload[..100_000]).unwrap();

    let bad = tmp.path().join("truncated.bin");
    let (ok, out, err) = bob.vox(&[
        "room",
        "get",
        &room,
        "flaky.bin",
        "--out",
        bad.to_str().unwrap(),
    ]);
    assert!(
        !ok,
        "a short transfer must be refused, not accepted silently: stdout={out:?}"
    );
    assert!(
        err.contains("does not match what was announced"),
        "it must say why: {err:?}"
    );
    assert!(
        !bad.exists(),
        "the partial file must be removed, not left looking complete"
    );
}
