//! ADR-020 §6, second half / M19.6 — **an interrupt fires only when a message is
//! addressed *and* urgent.**
//!
//! The queue half is the drain hook and it is the default on purpose. This is the
//! other half: reaching a session that is already running, or starting a turn for
//! one sitting idle. The property worth proving is not that an interrupt can be
//! delivered — that is easy — but that it is **withheld** in the two neighbouring
//! cases. An interrupt that fires on everything is a queue with worse manners, and
//! it would make an agent's context unusable exactly as the decider described: "a
//! wall of shit that I would not be able to keep up with."
//!
//! So this asserts all three cases:
//!
//! 1. addressed **and** urgent → the session is woken;
//! 2. urgent but **not addressed** → nothing is delivered;
//! 3. addressed but **not urgent** → nothing is delivered; it waits for the turn.
//!
//! ## What is real here and what stands in
//!
//! Real: the node, the room, the log, the envelope parsing, the registration file
//! the drain hook writes, the daemon's decision, and a **real Unix socket
//! receiving real NDJSON frames**.
//!
//! Standing in: the listener on the far end of that socket is this test rather than
//! a live Claude Code session. The frame format is not guessed — it was verified
//! against a **live session**, by writing exactly these two frames to a real
//! `CLAUDE_CODE_MESSAGING_SOCKET` and observing the message arrive. What this test
//! cannot show is that a harness *acts* on it, and that is said here rather than
//! implied.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::io::Read as _;
use std::os::unix::net::UnixListener;
use std::sync::mpsc;

use vox_core::node::api::{NodeCommand, Secret};
use vox_core::node::paths::Paths;

fn secret(s: &str) -> Secret {
    Secret::new(s.as_bytes().to_vec())
}

/// A stand-in harness: accepts one connection and reports what was written.
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

#[test]
#[ignore = "production Argon2id at setup and a real socket; CI runs it in release"]
fn an_interrupt_fires_only_when_a_message_is_addressed_and_urgent() {
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();
    let data = tmp.path().join("data");
    let cfg = tmp.path().join("cfg");
    let paths = Paths::resolve("default", Some(&data), Some(&cfg)).unwrap();

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let node = rt
        .block_on(async {
            vox_core::node::actor::Node::spawn_with(
                paths.clone(),
                std::sync::Arc::new(|| {
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map_or(0, |d| d.as_secs())
                }),
                vox_core::atrest::sek::Argon2Profile::default(),
            )
        })
        .unwrap();
    let cid = rt.block_on(async {
        assert!(node
            .apply(NodeCommand::CreateIdentity {
                passphrase: secret("identity passphrase"),
            })
            .await
            .is_done());
        assert!(node
            .apply(NodeCommand::CreateChannel {
                local_name: "mission".into(),
                passphrase: secret("channel passphrase"),
            })
            .await
            .is_done());
        node.view().channels[0].channel_id
    });
    let room = vox_core::node::link::b32_encode(&cid);

    // A session that has registered a wake channel, exactly as the drain hook
    // writes it — same struct, same file, same directory.
    let sock = tmp.path().join("session.sock");
    let inbox = listen(&sock);
    std::fs::create_dir_all(paths.session_dir()).unwrap();
    let registration = serde_json::json!({
        "session": "session-1",
        "harness": "claude",
        "room": room,
        "name": "alice",
        "endpoint": sock.to_string_lossy(),
        "token": "a-token",
    });
    std::fs::write(
        paths.session_file("session-1"),
        serde_json::to_vec(&registration).unwrap(),
    )
    .unwrap();

    // The daemon's decision, exercised directly against the registration it reads.
    let deliver = |envelope: &str| -> Option<String> {
        let parsed = vox_agentcomms::envelope::Envelope::parse(envelope).expect("an envelope");
        let sessions = vox_tui::wake::registered(&paths);
        assert_eq!(sessions.len(), 1, "exactly one session is registered");
        let session = &sessions[0];
        if !parsed.may_interrupt(&session.name) {
            return None;
        }
        rt.block_on(async {
            vox_tui::wake::wake(session, parsed.body.trim())
                .await
                .expect("delivery");
        });
        inbox.recv_timeout(std::time::Duration::from_secs(10)).ok()
    };

    // ---- (2) urgent, but addressed to somebody else ----
    let other = r#"{"v":1,"type":"ask","to":["bob"],"urgent":true,"body":"bob, the build is red"}"#;
    assert!(
        deliver(other).is_none(),
        "a message addressed to another agent must not interrupt this one"
    );

    // ---- (3) addressed, but not urgent ----
    let calm = r#"{"v":1,"type":"ask","to":["alice"],"body":"alice, when you get a moment"}"#;
    assert!(
        deliver(calm).is_none(),
        "an addressed message that is not urgent must wait for the next turn"
    );

    // ---- (1) addressed and urgent: this one wakes ----
    let urgent =
        r#"{"v":1,"type":"ask","to":["alice"],"urgent":true,"body":"alice, main is broken"}"#;
    let got = deliver(urgent).expect("an addressed, urgent message must interrupt");

    // The wire is what a live Claude Code session accepts: an auth frame, then a
    // user message, one JSON object per line.
    let mut lines = got.lines();
    let auth: serde_json::Value =
        serde_json::from_str(lines.next().expect("an auth frame")).expect("auth is JSON");
    assert_eq!(auth["type"], "auth", "the first frame must authenticate");
    assert_eq!(
        auth["token"], "a-token",
        "it must carry the session's token"
    );
    let message: serde_json::Value =
        serde_json::from_str(lines.next().expect("a message frame")).expect("message is JSON");
    assert_eq!(message["type"], "user");
    assert_eq!(message["message"]["role"], "user");
    assert!(
        message["message"]["content"]
            .as_str()
            .is_some_and(|c| c.contains("main is broken")),
        "the message must carry what was said: {message}"
    );
}
