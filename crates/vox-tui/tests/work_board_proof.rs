//! ADR-020 §5 / M19.9 — **two agents splitting work**, driven as real binaries
//! against two real nodes.
//!
//! The decider's requirement is agents that "communicate **and split work loads**".
//! Communication was reachable from M19.4; splitting work was not. The whole claim
//! model has lived in `vox-agentcomms` since M19.3 — `ClaimOp`, the resolution
//! rules, the deterministic tie-break — and until M19.9 **nothing in the shipped
//! binary called any of it**. `resolve` was exercised only by its own gate, which
//! is precisely the kind of green that proves nothing about the product.
//!
//! So this drives the product. Two nodes, two identities, one room, and the `vox`
//! binary run as a separate process against each — because a claim is only useful
//! if a *different agent* is bound by it, and a single-node test cannot show that.
//!
//! What it proves:
//!
//! 1. **Exactly one agent holds a contested resource.** Both claim it; the first
//!    wins; the winner is told it holds it.
//! 2. **The loser is told it lost, and fails.** Not a silent no-op — a non-zero
//!    exit and a message naming the holder. An agent that cannot tell "I got it"
//!    from "I did not" will start work someone else is already doing, which is the
//!    exact failure claims exist to prevent.
//! 3. **The board agrees from both sides**, and each agent can see which claims are
//!    its own — which is why `Frame::Hello` carries the client's fingerprint.
//! 4. **A release frees it**, and only the owner's release counts.
//! 5. **A lapsed `--ttl` frees it with nobody acting** — the property that stops a
//!    dead agent holding a resource forever.
//!
//! Real wall-clock time is used rather than a fixed test clock, because `--ttl`
//! expiry is compared against the *client's* clock and a node pinned to a fixed
//! instant would make every claim appear to be from the future.
//!
//! ## One thing this deliberately does NOT assert
//!
//! That a release leaves a resource **unowned** when another agent has already
//! posted a losing claim for it. It may not, and that is not a defect:
//! `created_secs` has one-second resolution, so a losing claim and the release that
//! follows it can carry the same timestamp, and §5's tie-break then orders them by
//! entry hash. Every node computes the *same* answer — that is what the tie-break
//! is for — but the answer is not causal within a second. The earlier claim may
//! sort after the release and acquire the resource.
//!
//! This was found by running this proof, which first asserted the causal outcome
//! and failed: bob was correctly told he had lost, and his board then showed him
//! holding it once alice released. Neither statement was wrong — "you did not get
//! it" was true when it was said — so what is asserted below is the property the
//! model actually guarantees: **after a release, the previous owner no longer
//! holds it, and a fresh claim succeeds.**

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::process::{Command, Stdio};

use vox_core::node::actor::{Node, NodeHandle};
use vox_core::node::api::{NodeCommand, NodeEvent, Secret};
use vox_core::node::paths::Paths;

const VOX: &str = env!("CARGO_BIN_EXE_vox");
const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

fn secret(s: &str) -> Secret {
    Secret::new(s.as_bytes().to_vec())
}

/// One agent's view of the machine: a profile directory pair and a node.
struct Agent {
    /// The one session this agent speaks as.
    session: String,
    data: std::path::PathBuf,
    cfg: std::path::PathBuf,
    paths: Paths,
    node: NodeHandle,
}

impl Agent {
    /// Run `vox …` as this agent, against this agent's node.
    fn vox(&self, args: &[&str]) -> (bool, String, String) {
        let out = Command::new(VOX)
            .args(args)
            .env("VOX_DATA_DIR", &self.data)
            .env("VOX_CONFIG_DIR", &self.cfg)
            .env_remove("VOX_ROOM")
            // Ownership is per session (ADR-021 §4): each agent here is one session,
            // named after it, and a session inherited from the test's own harness must
            // never leak in.
            .env_remove("CLAUDE_CODE_SESSION_ID")
            .env_remove("CODEX_THREAD_ID")
            .env("VOX_SESSION", &self.session)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .expect("spawn vox");
        (
            out.status.success(),
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    }

    fn fingerprint(&self) -> [u8; 32] {
        self.node.view().identity.expect("identity").fingerprint
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
    assert!(
        !node.view().listening.is_empty(),
        "{name} listens once unlocked"
    );
    Agent {
        session: name.to_owned(),
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

/// Poll a command until its output satisfies `ok`, or fail with what it last said.
///
/// A claim posted on one node reaches the other through the log, so "has it arrived
/// yet" is a real question with no synchronous answer.
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
#[ignore = "two networked nodes with production Argon2id; CI runs it in release"]
fn two_agents_split_work_and_only_one_holds_a_contested_resource() {
    watchdog::arm();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap();
    let tmp = tempfile::tempdir().unwrap();

    // The bind guards must outlive the test: dropping one stops accepting and
    // unlinks the socket path, and every `vox room` call would then be told there
    // is no node running.
    let (alice, bob, room, _alice_sock, _bob_sock, alice_short) = rt.block_on(async {
        let alice = agent(&tmp, "alice").await;
        let bob = agent(&tmp, "bob").await;
        let alice_fp = alice.fingerprint();
        let bob_fp = bob.fingerprint();

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

        // Joining grants nothing (M17.6): each must admit the other to the ring
        // before either can read what the other writes. That is the whole point of
        // §3, and it means a work board is only shared between agents an operator
        // deliberately introduced.
        assert!(alice
            .node
            .apply(NodeCommand::Trust {
                fingerprint: bob_fp,
                petname: "bob".into(),
            })
            .await
            .is_done());
        assert!(bob
            .node
            .apply(NodeCommand::Trust {
                fingerprint: alice_fp,
                petname: "alice".into(),
            })
            .await
            .is_done());

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

        let alice_sock =
            vox_core::node::ipc::bind(alice.node.clone(), &alice.paths).expect("alice socket");
        let bob_sock = vox_core::node::ipc::bind(bob.node.clone(), &bob.paths).expect("bob socket");
        let room = vox_core::node::link::b32_encode(&cid);
        let alice_short: String = vox_core::node::link::b32_encode(&alice_fp)
            .chars()
            .take(12)
            .collect();
        (alice, bob, room, alice_sock, bob_sock, alice_short)
    });

    // ---- (1) and (2): both claim the same thing; exactly one wins ----
    let (ok, out, err) = alice.vox(&["room", "claim", &room, "port-the-codec"]);
    assert!(ok, "alice's claim failed: {err}");
    assert!(
        out.contains("you hold port-the-codec"),
        "a winning claim must say so: {out:?}"
    );

    // Bob must see alice's claim before his own can lose to it.
    until(
        &bob,
        "alice's claim to reach bob",
        &["room", "board", &room],
        |o| o.contains("port-the-codec"),
    );

    let (ok, out, err) = bob.vox(&["room", "claim", &room, "port-the-codec"]);
    assert!(
        !ok,
        "a losing claim must fail, not succeed quietly: stdout={out:?}"
    );
    assert!(
        err.contains("is held by"),
        "the loser must be told who holds it: {err:?}"
    );

    // ---- (3) the board agrees from both sides, and each knows its own ----
    let alice_board = alice.vox(&["room", "board", &room]).1;
    assert!(
        alice_board.contains("port-the-codec") && alice_board.contains("(you)"),
        "alice must see the resource as hers: {alice_board:?}"
    );
    let bob_board = bob.vox(&["room", "board", &room]).1;
    assert!(
        bob_board.contains("port-the-codec") && !bob_board.contains("(you)"),
        "bob must see it held by someone who is not him: {bob_board:?}"
    );

    // ---- (4) a release frees it, and the new claim succeeds ----
    let (ok, _, err) = alice.vox(&["room", "release", &room, "port-the-codec"]);
    assert!(ok, "alice could not release: {err}");
    // What a release guarantees is that **the releaser stops holding it** — not
    // that the resource is unowned, because bob's earlier losing claim may sort
    // after the release and acquire it. See the header.
    until(
        &bob,
        "alice to stop holding the resource",
        &["room", "board", &room],
        |o| {
            !o.lines()
                .any(|l| l.starts_with("port-the-codec") && l.contains(&alice_short))
        },
    );
    let (ok, out, err) = bob.vox(&["room", "claim", &room, "port-the-codec"]);
    assert!(ok, "bob should hold it once alice released: {err}");
    assert!(out.contains("you hold port-the-codec"), "{out:?}");

    // ---- (5) a lapsed ttl frees it with nobody acting ----
    let (ok, out, err) = alice.vox(&["room", "claim", &room, "flaky-test", "--ttl", "2"]);
    assert!(ok, "alice's ttl claim failed: {err}");
    assert!(out.contains("you hold flaky-test"), "{out:?}");
    until(
        &bob,
        "the ttl claim to reach bob",
        &["room", "board", &room],
        |o| o.contains("flaky-test"),
    );

    // Nobody releases it. It lapses.
    std::thread::sleep(std::time::Duration::from_secs(3));
    let (ok, out, err) = bob.vox(&["room", "claim", &room, "flaky-test"]);
    assert!(
        ok,
        "a lapsed claim must free the resource with nobody acting: stdout={out:?} stderr={err:?}"
    );
    assert!(out.contains("you hold flaky-test"), "{out:?}");
}
