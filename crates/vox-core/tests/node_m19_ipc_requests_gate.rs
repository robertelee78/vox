//! ADR-020 §7/§8 **gate** — an out-of-process client posts and reads through the
//! control socket.
//!
//! M19.1b carried events only, so an agent session attached to a harness node
//! could watch a room and say nothing. This is the other half: the narrow request
//! set an app legitimately needs — post, read from a cursor, roster, rooms — and
//! nothing more.
//!
//! What it proves:
//!
//! 1. a client posts a message and the **node's own view** shows it, so the post
//!    really went through the log rather than being echoed back;
//! 2. **reading from a cursor returns only what follows it**, which is what makes
//!    an agent's "what did I miss" cheap and what the drain hook will call;
//! 3. an **unknown cursor is an error, not silence** — returning "from the start"
//!    would silently re-deliver a whole room to an agent that asked for the tail;
//! 4. roster and rooms answer;
//! 5. a **failed request leaves the connection usable** — asking about a room
//!    that is not open is an answer, not a disconnection;
//! 6. the surface is **narrow by construction**: there is no request that creates
//!    an identity, unlocks, revokes, or edits the trust keyring.
//!
//! Point 6 is the one worth stating plainly: the `0600` file mode is the actual
//! boundary and the uid behind it can already read the vault. The narrow request
//! set is accident prevention against model-authored code, not a security claim.

#![cfg(unix)]

#[path = "support/watchdog.rs"]
mod watchdog;

use std::sync::Arc;

use vox_core::node::actor::{Clock, Node, NodeHandle};
use vox_core::node::api::{NodeCommand, Secret};
use vox_core::node::ipc::{self, Frame, Request};
use vox_core::node::paths::Paths;

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

fn spawn_node(rt: &tokio::runtime::Runtime, paths: &Paths) -> NodeHandle {
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
#[ignore = "production Argon2id at setup; CI runs it in release"]
fn m19_a_client_posts_and_reads_through_the_socket() {
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();
    let paths = Paths::resolve("m19req", Some(tmp.path()), Some(&tmp.path().join("cfg"))).unwrap();
    let rt = runtime();
    let h = spawn_node(&rt, &paths);

    rt.block_on(async {
        assert!(h
            .apply(NodeCommand::CreateIdentity {
                passphrase: secret("identity passphrase"),
            })
            .await
            .is_done());
        assert!(h
            .apply(NodeCommand::CreateChannel {
                local_name: "agents".into(),
                passphrase: secret("channel passphrase"),
            })
            .await
            .is_done());
        let cid = h.view().channels[0].channel_id;

        let _server = ipc::bind(h.clone(), &paths).expect("bind");
        let mut client = ipc::IpcClient::open(&paths.socket_file())
            .await
            .expect("open");

        // (4) rooms answers, and names the room this node holds.
        let Frame::Rooms { rooms } = client.request(&Request::Rooms).await.expect("rooms") else {
            panic!("expected Rooms");
        };
        assert!(
            rooms
                .iter()
                .any(|(id, name, _)| *id == cid && name == "agents"),
            "rooms did not list the room: {rooms:?}"
        );

        // (1) post, and see it in the NODE's view — not echoed back to us.
        for i in 0..3 {
            let reply = client
                .request(&Request::Post {
                    channel_id: cid,
                    text: format!("posted {i}"),
                })
                .await
                .expect("post");
            assert_eq!(reply, Frame::Ok, "post {i} refused: {reply:?}");
        }
        let in_the_node = h
            .view()
            .open_channels
            .iter()
            .find(|d| d.channel_id == cid)
            .map(|d| {
                d.timeline
                    .iter()
                    .map(|r| r.text.clone())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        for i in 0..3 {
            assert!(
                in_the_node.contains(&format!("posted {i}")),
                "the node's own view is missing {i}: {in_the_node:?}"
            );
        }

        // (2) read everything, then read from a cursor and get only what follows.
        let Frame::Rows { rows } = client
            .request(&Request::Read {
                channel_id: cid,
                since: None,
                limit: 0,
            })
            .await
            .expect("read")
        else {
            panic!("expected Rows");
        };
        assert!(rows.len() >= 3, "read returned {} rows", rows.len());
        let texts: Vec<String> = rows.iter().map(|r| r.text.clone()).collect();
        let first = rows[0].entry_hash;

        let Frame::Rows { rows: tail } = client
            .request(&Request::Read {
                channel_id: cid,
                since: Some(first),
                limit: 0,
            })
            .await
            .expect("read since")
        else {
            panic!("expected Rows");
        };
        assert_eq!(
            tail.len(),
            rows.len() - 1,
            "a cursor must return only what follows it"
        );
        assert_eq!(tail[0].text, texts[1]);
        assert!(
            !tail.iter().any(|r| r.entry_hash == first),
            "the cursor entry itself must not be returned again"
        );

        // limit caps the rows.
        let Frame::Rows { rows: capped } = client
            .request(&Request::Read {
                channel_id: cid,
                since: None,
                limit: 2,
            })
            .await
            .expect("read limit")
        else {
            panic!("expected Rows");
        };
        assert_eq!(capped.len(), 2);

        // (3) an unknown cursor is an ERROR, not "from the start".
        let reply = client
            .request(&Request::Read {
                channel_id: cid,
                since: Some([0x5A; 32]),
                limit: 0,
            })
            .await
            .expect("read bad cursor");
        assert!(
            matches!(reply, Frame::Error { .. }),
            "an unknown cursor must be refused, not silently restarted: {reply:?}"
        );

        // (4) roster answers.
        let Frame::Members { members } = client
            .request(&Request::Roster { channel_id: cid })
            .await
            .expect("roster")
        else {
            panic!("expected Members");
        };
        assert!(!members.is_empty(), "roster was empty");

        // (5) a failure leaves the connection usable — ask about a room that does
        // not exist, then ask a good question on the same connection.
        let reply = client
            .request(&Request::Roster {
                channel_id: [0xEE; 32],
            })
            .await
            .expect("roster for an unknown room");
        assert!(matches!(reply, Frame::Error { .. }), "{reply:?}");

        let still_works = client.request(&Request::Rooms).await.expect("still usable");
        assert!(
            matches!(still_works, Frame::Rooms { .. }),
            "an error ended the connection: {still_works:?}"
        );
    });
}

/// The request surface is narrow by construction (ADR-020 §7).
///
/// Not a restatement of the enum: this asserts that the *wire* refuses a request
/// this build does not define, which is what stops a future client inventing one
/// and finding it half-handled.
#[test]
fn an_undefined_request_is_refused_on_the_wire() {
    use vox_core::cbor::Encoder;
    // Tag 99 is not a request this build defines.
    let mut e = Encoder::new();
    e.array(1).uint(99);
    assert!(Request::from_bytes(&e.finish()).is_err());

    // A defined tag with the wrong arity is refused too, rather than being read
    // with whatever fields happen to be present.
    let mut e = Encoder::new();
    e.array(2).uint(1).uint(0);
    assert!(Request::from_bytes(&e.finish()).is_err());
}
