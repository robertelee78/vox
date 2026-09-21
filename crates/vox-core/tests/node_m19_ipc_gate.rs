//! ADR-020 §7 **M19.1b gate** — two separate *processes* attach to one node.
//!
//! M19.1a proved the in-process fan-out. This proves the same property across a
//! process boundary, which is the one agent comms actually needs: several agent
//! sessions, each its own process, attached to one harness node.
//!
//! Proven here, with real `fork`/`exec`'d children rather than tasks:
//!
//! 1. the control socket is `0600` — measured, because `bind` yields `0755` from
//!    the umask and only an explicit `chmod` fixes it;
//! 2. two independent client **processes** each receive every event;
//! 3. **killing one mid-stream disturbs neither the node nor the other** — the
//!    survivor still receives every remaining message and the node still answers
//!    commands afterwards.
//!
//! The children are this same test binary re-invoked with `VOX_IPC_CHILD_SOCK`
//! set, which is how a test gets a genuinely separate process without shipping a
//! helper binary. Each child writes `<tag>.ready` once subscribed and `<tag>.done`
//! with what it saw, so the parent synchronises on files instead of parsing
//! stdout.
//!
//! Mutation-checked, both run and observed to fail:
//!
//! - drop the explicit `chmod` after `bind` — fails with "control socket mode is
//!   0755, not 0600", which is also the measurement that makes the chmod
//!   load-bearing rather than decorative;
//! - serve clients sequentially in the accept loop instead of giving each its own
//!   task — fails with "timed out waiting for child B to subscribe", because the
//!   first client then holds the accept loop and the second never gets served.
//!
//! Production Argon2id is paid once at setup. `#[ignore]`d in the debug suite.

#![cfg(unix)]

#[path = "support/watchdog.rs"]
mod watchdog;

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use vox_core::node::actor::{Clock, Node, NodeHandle};
use vox_core::node::api::{NodeCommand, NodeEvent, Secret};
use vox_core::node::ipc::{self, Frame};
use vox_core::node::paths::Paths;

/// Messages sent while both children are attached.
const BEFORE_KILL: usize = 20;
/// Messages sent after one child has been killed.
const AFTER_KILL: usize = 20;
const SENTINEL: &str = "SENTINEL-last";

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

fn wait_for(path: &Path, what: &str) {
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        if path.is_file() {
            return;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    panic!("timed out waiting for {what}: {}", path.display());
}

/// The child half. Only does anything when the parent set the env var, so it is
/// inert in an ordinary test run.
#[test]
#[ignore = "child half of m19_two_processes_attach_to_one_node; driven by the parent"]
fn ipc_client_child() {
    let Ok(sock) = std::env::var("VOX_IPC_CHILD_SOCK") else {
        return;
    };
    let tag = PathBuf::from(std::env::var("VOX_IPC_CHILD_TAG").expect("child tag"));

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let mut client = ipc::IpcClient::connect(Path::new(&sock))
            .await
            .expect("child connects");
        // Subscribed: tell the parent it is safe to start sending.
        std::fs::write(tag.with_extension("ready"), b"1").unwrap();

        let mut texts: Vec<String> = Vec::new();
        while let Ok(Some(frame)) = client.next().await {
            match frame {
                Frame::Event(NodeEvent::NewEntry { row, .. }) => {
                    let done = row.text == SENTINEL;
                    texts.push(row.text);
                    if done {
                        break;
                    }
                }
                Frame::Lagged { missed } => texts.push(format!("LAGGED:{missed}")),
                _ => {}
            }
        }
        std::fs::write(tag.with_extension("done"), texts.join("\n")).unwrap();
    });
}

fn spawn_child(sock: &Path, tag: &Path) -> std::process::Child {
    std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "ipc_client_child", "--ignored", "--nocapture"])
        .env("VOX_IPC_CHILD_SOCK", sock)
        .env("VOX_IPC_CHILD_TAG", tag)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn child process")
}

#[test]
#[ignore = "production Argon2id at setup + two child processes; CI runs it in release"]
fn m19_two_processes_attach_to_one_node() {
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();
    let paths = Paths::resolve("m19ipc", Some(tmp.path()), Some(&tmp.path().join("cfg"))).unwrap();

    let rt = runtime();
    let h = spawn_node(&rt, &paths);

    let cid = rt.block_on(async {
        assert!(h
            .apply(NodeCommand::CreateIdentity {
                passphrase: secret("identity passphrase"),
            })
            .await
            .is_done());
        assert!(h
            .apply(NodeCommand::CreateChannel {
                local_name: "ipc gate".into(),
                passphrase: secret("channel passphrase"),
            })
            .await
            .is_done());
        h.view().channels[0].channel_id
    });

    // Bind the control socket. The node itself knows nothing about IPC — the
    // caller that spawned it binds the socket and holds the server.
    let _server = rt
        .block_on(async { ipc::bind(h.clone(), &paths) })
        .expect("bind control socket");
    let sock = paths.socket_file();

    // (1) the socket is 0600, not whatever the umask would have given.
    let mode = std::fs::metadata(&sock).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "control socket mode is {mode:04o}, not 0600");

    // Two genuinely separate client processes.
    let tag_a = tmp.path().join("child-a");
    let tag_b = tmp.path().join("child-b");
    let mut child_a = spawn_child(&sock, &tag_a);
    let mut child_b = spawn_child(&sock, &tag_b);
    wait_for(&tag_a.with_extension("ready"), "child A to subscribe");
    wait_for(&tag_b.with_extension("ready"), "child B to subscribe");

    rt.block_on(async {
        for i in 0..BEFORE_KILL {
            assert!(h
                .apply(NodeCommand::SendText {
                    channel_id: cid,
                    text: format!("before {i}"),
                })
                .await
                .is_done());
        }
    });

    // (3) kill one client outright, mid-stream.
    child_a.kill().expect("kill child A");
    child_a.wait().expect("reap child A");

    rt.block_on(async {
        for i in 0..AFTER_KILL {
            assert!(
                h.apply(NodeCommand::SendText {
                    channel_id: cid,
                    text: format!("after {i}"),
                })
                .await
                .is_done(),
                "the node stopped answering after a client was killed"
            );
        }
        assert!(
            h.apply(NodeCommand::SendText {
                channel_id: cid,
                text: SENTINEL.into(),
            })
            .await
            .is_done(),
            "the node stopped answering before the sentinel"
        );
    });

    // (2) + (3): the survivor saw everything, including messages sent after its
    // peer was killed.
    wait_for(&tag_b.with_extension("done"), "child B to finish");
    let seen = std::fs::read_to_string(tag_b.with_extension("done")).unwrap();
    let lines: Vec<&str> = seen.lines().collect();
    assert!(
        !lines.iter().any(|l| l.starts_with("LAGGED:")),
        "the survivor lagged, so this run does not prove delivery: {lines:?}"
    );
    for i in 0..BEFORE_KILL {
        let want = format!("before {i}");
        assert!(
            lines.contains(&want.as_str()),
            "survivor missed {want:?}; saw {lines:?}"
        );
    }
    for i in 0..AFTER_KILL {
        let want = format!("after {i}");
        assert!(
            lines.contains(&want.as_str()),
            "survivor missed {want:?} sent AFTER its peer was killed; saw {lines:?}"
        );
    }
    assert_eq!(lines.last(), Some(&SENTINEL));

    // The killed child never reported, which is the point: it died, and nothing
    // else noticed.
    assert!(
        !tag_a.with_extension("done").is_file(),
        "child A was killed, so it must not have completed"
    );

    // And the node is still fully alive afterwards.
    let still = rt.block_on(async {
        h.apply(NodeCommand::SendText {
            channel_id: cid,
            text: "after everything".into(),
        })
        .await
    });
    assert!(still.is_done(), "the node did not survive the whole gate");

    let _ = child_b.kill();
    let _ = child_b.wait();
}
