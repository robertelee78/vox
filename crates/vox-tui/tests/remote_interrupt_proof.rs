//! ADR-021 F15 / ADR-020 §6 — **an urgent message from ANOTHER node interrupts its
//! addressee**, through a real `vox daemon`.
//!
//! `interrupt_proof` calls the daemon's wake decision directly, so it never runs the
//! loop that feeds it — and that loop woke sessions only on `NodeEvent::NewEntry`, which
//! the node emits for its own appends and never for an entry synced from a peer. So an
//! urgent message from another agent on another machine — the case the interrupt path
//! exists for — could not interrupt anybody, and no gate could see it.
//!
//! This drives the real thing: bob's profile is joined and trusted in-process, then
//! served by the shipped `vox daemon`; a stand-in Claude Code session is registered with
//! it exactly as the drain hook registers one; alice, on another node, posts to bob. It
//! asserts all three cases, **each for a message that arrived by sync**:
//!
//! 1. addressed to bob and urgent — bob's session is woken;
//! 2. urgent but addressed to someone else — nothing;
//! 3. addressed to bob but not urgent — nothing.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::io::{Read as _, Write as _};
use std::os::unix::net::UnixListener;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use vox_core::node::actor::{Node, NodeHandle};
use vox_core::node::api::{NodeCommand, NodeEvent, Secret};
use vox_core::node::paths::Paths;

const VOX: &str = env!("CARGO_BIN_EXE_vox");
const IDENTITY: &str = "identity passphrase";
const ROOM_PASS: &str = "channel passphrase";

fn secret(s: &str) -> Secret {
    Secret::new(s.as_bytes().to_vec())
}

struct Proc(std::process::Child);
impl Drop for Proc {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// A stand-in harness session: every connection's bytes, as they are written.
fn listen(path: &std::path::Path) -> mpsc::Receiver<String> {
    let listener = UnixListener::bind(path).expect("bind the stand-in session socket");
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut buf = String::new();
            let _ = stream.read_to_string(&mut buf);
            if tx.send(buf).is_err() {
                return;
            }
        }
    });
    rx
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

fn vox(data: &std::path::Path, cfg: &std::path::Path, args: &[&str]) -> (bool, String, String) {
    let out = Command::new(VOX)
        .args(args)
        .env("VOX_DATA_DIR", data)
        .env("VOX_CONFIG_DIR", cfg)
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

#[test]
#[ignore = "two networked nodes, a real vox daemon, production Argon2id; CI runs it in release"]
fn an_urgent_message_from_another_node_interrupts_its_addressee() {
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

    // ---- alice (stays in-process) and bob (in-process only to join and trust) ----
    let (alice, cid, _a_sock, a_fp, b_fp) = rt.block_on(async {
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
                local_name: "mission".into(),
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
                local_name: "mission".into(),
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
        for (n, peer) in [(&alice, b_fp), (&bob, a_fp)] {
            wait_for(n, |e| match e {
                NodeEvent::SenderKeyReceived {
                    channel_id,
                    peer: p,
                    ..
                } if channel_id == cid && p == peer => Some(()),
                _ => None,
            })
            .await;
        }
        let _ = bob.apply(NodeCommand::Shutdown).await;
        let sock = vox_core::node::ipc::bind(alice.clone(), &a_paths).expect("alice socket");
        (alice, cid, sock, a_fp, b_fp)
    });
    let room = vox_core::node::link::b32_encode(&cid);
    // PRD-001 R15: `to` carries fingerprints on the wire.
    let (bob_fp, alice_fp) = (
        vox_core::node::link::b32_encode(&b_fp),
        vox_core::node::link::b32_encode(&a_fp),
    );

    // ---- bob is now the real `vox daemon`, holding the room ----
    let err_path = tmp.path().join("daemon.err");
    let mut daemon = Command::new(VOX)
        .args(["daemon", "--listen", "127.0.0.1:0"])
        .env("VOX_DATA_DIR", &b_data)
        .env("VOX_CONFIG_DIR", &b_cfg)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::from(std::fs::File::create(&err_path).unwrap()))
        .spawn()
        .expect("spawn vox daemon");
    let mut pipe = daemon.stdin.take().unwrap();
    pipe.write_all(format!("{IDENTITY}\n{} {ROOM_PASS}\n", &room[..12]).as_bytes())
        .unwrap();
    drop(pipe);
    let _daemon = Proc(daemon);

    // A session registered with bob's daemon exactly as the drain hook registers one.
    let sock = tmp.path().join("session.sock");
    let inbox = listen(&sock);
    std::fs::create_dir_all(b_paths.session_dir()).unwrap();
    std::fs::write(
        b_paths.session_file("session-bob"),
        serde_json::to_vec(&serde_json::json!({
            "session": "session-bob", "harness": "claude", "room": room, "name": "bob",
            "endpoint": sock.to_string_lossy(), "token": "a-token",
        }))
        .unwrap(),
    )
    .unwrap();

    // Bob's daemon must be in sync with alice before the cases mean anything.
    rt.block_on(post(&alice, cid, "SYNC-MARKER"));
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        let (_, out, _) = vox(&b_data, &b_cfg, &["room", "read", &room]);
        if out.contains("SYNC-MARKER") {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "bob's daemon never synced with alice; daemon stderr:\n{}",
            std::fs::read_to_string(&err_path).unwrap_or_default()
        );
        std::thread::sleep(Duration::from_millis(250));
    }

    // ---- (2) urgent, addressed to someone else: nothing ----
    rt.block_on(post(
        &alice,
        cid,
        &format!(r#"{{"v":1,"type":"ask","to":["{alice_fp}"],"urgent":true,"body":"alice: OTHER-ADDRESSEE"}}"#),
    ));
    // ---- (3) addressed to bob, not urgent: nothing ----
    rt.block_on(post(
        &alice,
        cid,
        &format!(r#"{{"v":1,"type":"ask","to":["{bob_fp}"],"body":"bob: NOT-URGENT"}}"#),
    ));
    // ---- (1) addressed to bob and urgent: woken ----
    rt.block_on(post(
        &alice,
        cid,
        r#"{"v":1,"type":"ask","to":["bob"],"urgent":true,"body":"bob: BY-PETNAME-ONLY"}"#,
    ));
    // ---- (1) addressed to bob's FINGERPRINT and urgent: woken ----
    rt.block_on(post(
        &alice,
        cid,
        &format!(r#"{{"v":1,"type":"ask","to":["{bob_fp}"],"urgent":true,"body":"bob: WAKE-UP-FROM-ALICE"}}"#),
    ));
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let (_, out, _) = vox(&b_data, &b_cfg, &["room", "read", &room]);
        if out.contains("WAKE-UP-FROM-ALICE") {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the urgent message never reached bob's node"
        );
        std::thread::sleep(Duration::from_millis(250));
    }
    let mut woken = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        if let Ok(frames) = inbox.recv_timeout(Duration::from_millis(500)) {
            eprintln!("[receipt] bob's session received: {frames}");
            woken.push(frames);
        }
    }
    let all = woken.join("\n");
    assert!(
        all.contains("WAKE-UP-FROM-ALICE"),
        "an urgent message addressed to bob, from another node, must interrupt bob's session; \
         received {woken:?}; daemon stderr:\n{}",
        std::fs::read_to_string(&err_path).unwrap_or_default()
    );
    assert!(
        !all.contains("OTHER-ADDRESSEE"),
        "a message addressed to another agent must not interrupt bob"
    );
    assert!(
        !all.contains("BY-PETNAME-ONLY"),
        "a petname in `to` addresses nobody: addressing is by fingerprint (PRD-001 R15)"
    );
    assert!(
        !all.contains("NOT-URGENT"),
        "an addressed message that is not urgent must wait for the next turn"
    );
    assert_eq!(
        woken
            .iter()
            .filter(|f| f.contains("WAKE-UP-FROM-ALICE"))
            .count(),
        1,
        "one urgent message wakes the session once: {woken:?}"
    );

    // ---- (4) through the CLI: `--to` takes a fingerprint PREFIX and writes it in full ----
    let out = Command::new(VOX)
        .args([
            "room",
            "post",
            &room,
            "--type",
            "ask",
            "--urgent",
            "--to",
            &bob_fp[..10],
            "-",
        ])
        .env("VOX_DATA_DIR", &a_data)
        .env("VOX_CONFIG_DIR", &a_cfg)
        .env("VOX_SESSION", "alice-cli")
        .env_remove("CLAUDE_CODE_SESSION_ID")
        .env_remove("CODEX_THREAD_ID")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .and_then(|mut c| {
            c.stdin.take().unwrap().write_all(b"bob: VIA-THE-CLI")?;
            c.wait_with_output()
        })
        .expect("vox room post");
    assert!(
        out.status.success(),
        "vox room post --to <prefix>: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut via_cli = false;
    while Instant::now() < deadline && !via_cli {
        if let Ok(frames) = inbox.recv_timeout(Duration::from_millis(500)) {
            eprintln!("[receipt] bob's session received: {frames}");
            via_cli = frames.contains("VIA-THE-CLI");
        }
    }
    assert!(
        via_cli,
        "`vox room post --to <fingerprint prefix> --urgent` must wake the addressee"
    );
    drop(alice);
}

async fn post(node: &NodeHandle, cid: [u8; 32], text: &str) {
    assert!(
        node.apply(NodeCommand::SendText {
            channel_id: cid,
            text: text.to_owned()
        })
        .await
        .is_done(),
        "alice could not post"
    );
}
