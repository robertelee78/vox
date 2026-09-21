//! ADR-020 M19.7 — **the rehearsal**: two agent sessions and a human operator in
//! one room, with real models reading what each other wrote.
//!
//! ADR-020 marks this **REQUIRED** before agent comms may be described as working,
//! and the reason is M17's lesson: every CLI-composition defect that rehearsal
//! found was invisible to every library gate. A gate proves a function; a rehearsal
//! proves the product.
//!
//! What it drives, end to end, with nothing mocked:
//!
//! - two nodes with two identities, mutually admitted to each other's trust
//!   keyrings, sharing one room;
//! - two **separate agent sessions**, each a real `opencode` turn against a real
//!   model, each with its own session id and therefore its own cursor;
//! - the **operator** speaking into the same room as plain text through
//!   `vox room post`, exactly as a person would;
//! - a typed `assign` envelope from the operator and a typed `result` envelope
//!   back from the agent that did the work.
//!
//! What it asserts:
//!
//! 1. an agent's model **reads an assignment it was never prompted with**, and
//!    names the work in its own answer;
//! 2. the **second** agent's model reads the *result* the first one posted — so a
//!    message written by one session reaches a different session on a different
//!    identity, which is the whole feature;
//! 3. **cursors are per session**: the second agent sees the backlog the first has
//!    already consumed, because it has not read it;
//! 4. the operator's plain prose and the agents' typed envelopes coexist in one
//!    room, which is the shared-room case rather than the pure-agent one.
//!
//! ## Stated rather than implied
//!
//! This runs **two sessions on one host**, not on two machines. The overlay's
//! cross-machine path — NAT traversal, anchors, circuits — is proved by M17's own
//! rehearsal and by `service_rehearsal_proof`; what is new here is the composition
//! of agent sessions, cursors, envelopes and the operator, and that composition is
//! host-independent. The two-machine claim is not made here and should not be read
//! into it.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::path::Path;
use std::process::Command;

use vox_core::node::actor::{Node, NodeHandle};
use vox_core::node::api::{NodeCommand, NodeEvent, Secret};
use vox_core::node::paths::Paths;

const VOX: &str = env!("CARGO_BIN_EXE_vox");
const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

fn secret(s: &str) -> Secret {
    Secret::new(s.as_bytes().to_vec())
}

fn model() -> String {
    std::env::var("VOX_PROOF_OPENCODE_MODEL")
        .unwrap_or_else(|_| "opencode/claude-haiku-4-5".to_owned())
}

fn allow_unproven(name: &str) -> bool {
    std::env::var("VOX_PROOF_ALLOW_UNPROVEN")
        .unwrap_or_default()
        .split(',')
        .any(|s| s.trim().eq_ignore_ascii_case(name))
}

fn which(bin: &str) -> Option<std::path::PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|d| d.join(bin))
        .find(|p| p.is_file())
}

fn auth_present() -> bool {
    std::env::var_os("XDG_DATA_HOME")
        .map(std::path::PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| Path::new(&h).join(".local/share")))
        .is_some_and(|b| b.join("opencode/auth.json").is_file())
}

struct Agent {
    data: std::path::PathBuf,
    cfg: std::path::PathBuf,
    paths: Paths,
    node: NodeHandle,
    /// This agent's own project directory, where its OpenCode plugin lives.
    project: std::path::PathBuf,
}

impl Agent {
    fn vox(&self, args: &[&str]) -> (bool, String, String) {
        let out = Command::new(VOX)
            .args(args)
            .env("VOX_DATA_DIR", &self.data)
            .env("VOX_CONFIG_DIR", &self.cfg)
            .env_remove("VOX_ROOM")
            .stdin(std::process::Stdio::null())
            .output()
            .expect("spawn vox");
        (
            out.status.success(),
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    }

    /// One real model turn for this agent, with its room wired in.
    fn turn(&self, oc_cfg: &Path, room: &str, prompt: &str) -> String {
        let mut cmd = Command::new("opencode");
        // A spawned OpenCode that inherits cargo's environment loads the plugin and
        // never fires its message hook. Measured; see `opencode_plugin_proof`.
        cmd.env_clear();
        for key in ["PATH", "HOME", "SHELL", "LANG", "TMPDIR", "USER"] {
            if let Some(v) = std::env::var_os(key) {
                cmd.env(key, v);
            }
        }
        let out = cmd
            .current_dir(&self.project)
            .args(["run", "-m", &model(), prompt])
            .env("XDG_CONFIG_HOME", oc_cfg)
            .env("VOX_DATA_DIR", &self.data)
            .env("VOX_CONFIG_DIR", &self.cfg)
            .env("VOX_ROOM", room)
            .env("VOX_BIN", VOX)
            .output()
            .expect("run opencode");
        format!(
            "{}\n--- stderr ---\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )
    }
}

async fn agent(tmp: &tempfile::TempDir, name: &str, fixture: &Path) -> Agent {
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
    // Each session gets its own project directory, which is also what gives it its
    // own OpenCode session and therefore its own cursor.
    let project = fixture.join(name);
    std::fs::create_dir_all(project.join(".opencode/plugin")).unwrap();
    std::fs::write(
        project.join(".opencode/plugin/vox.js"),
        vox_tui::agent_hook::OPENCODE_PLUGIN,
    )
    .unwrap();
    Agent {
        data,
        cfg,
        paths,
        node,
        project,
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

fn until(who: &Agent, what: &str, args: &[&str], ok: impl Fn(&str) -> bool) {
    let deadline = std::time::Instant::now() + TIMEOUT;
    let mut last = String::new();
    while std::time::Instant::now() < deadline {
        let (_, out, err) = who.vox(args);
        last = format!("stdout={out:?} stderr={err:?}");
        if ok(&out) {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
    panic!("timed out waiting for {what}; last saw {last}");
}

#[test]
#[ignore = "two nodes, two live model turns; CI runs it in release"]
fn two_agent_sessions_and_an_operator_share_one_room() {
    watchdog::arm();
    if which("opencode").is_none() || !auth_present() {
        assert!(
            allow_unproven("opencode"),
            "UNPROVEN: the rehearsal needs a real harness and a usable credential. Set \
             VOX_PROOF_ALLOW_UNPROVEN=opencode to accept that gap deliberately."
        );
        return;
    }

    // A persistent fixture: OpenCode installs a `node_modules` tree into both the
    // project and the config directory on first use, and until it has, the plugin
    // loads while its hook never fires.
    let fixture = std::env::temp_dir().join("vox-agent-rehearsal");
    let oc_cfg = fixture.join("config");
    std::fs::create_dir_all(oc_cfg.join("opencode")).unwrap();

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap();
    let tmp = tempfile::tempdir().unwrap();

    let (alice, bob, room, _a, _b) = rt.block_on(async {
        let alice = agent(&tmp, "alice", &fixture).await;
        let bob = agent(&tmp, "bob", &fixture).await;
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
        let a = vox_core::node::ipc::bind(alice.node.clone(), &alice.paths).expect("alice");
        let b = vox_core::node::ipc::bind(bob.node.clone(), &bob.paths).expect("bob");
        (alice, bob, vox_core::node::link::b32_encode(&cid), a, b)
    });

    // Warm both projects: the first turn in a fresh directory installs and does not
    // fire the hook.
    for who in [&alice, &bob] {
        let _ = who.turn(&oc_cfg, &room, "Reply with exactly: READY");
    }

    // ---- the operator speaks, as a person, in plain prose ----
    let assignment = r#"{"v":1,"type":"assign","to":["alice"],"body":"port the wire codec to the new envelope format","data":{"resource":"port-the-codec"}}"#;
    let (ok, _, err) = alice.vox(&["room", "post", &room, assignment]);
    assert!(ok, "the operator could not post the assignment: {err}");
    until(
        &bob,
        "the assignment to reach bob",
        &["room", "read", &room],
        |o| o.contains("port the wire codec"),
    );

    // ---- (1) alice's model reads work it was never prompted with ----
    let answer = alice.turn(
        &oc_cfg,
        &room,
        "What task have you been assigned? Answer with just the task.",
    );
    assert!(
        answer.contains("codec") || answer.contains("wire"),
        "alice's model did not read its assignment: {answer:?}"
    );

    // ---- alice reports a result, as an agent would ----
    let result = r#"{"v":1,"type":"result","re":"port-the-codec","body":"done: the codec now speaks the envelope format. verification token QUORUM-8812"}"#;
    let (ok, _, err) = alice.vox(&["room", "post", &room, result]);
    assert!(ok, "alice could not post her result: {err}");
    until(
        &bob,
        "the result to reach bob",
        &["room", "read", &room],
        |o| o.contains("QUORUM-8812"),
    );

    // ---- (2) and (3) bob's model reads what alice wrote, from its own cursor ----
    let seen = bob.turn(
        &oc_cfg,
        &room,
        "What verification token was reported in your room? Answer with just the token.",
    );
    assert!(
        seen.contains("QUORUM-8812"),
        "a message written by one agent session did not reach the other: {seen:?}"
    );

    // ---- (4) the operator asks a question in prose, and it lands ----
    let (ok, _, err) = bob.vox(&[
        "room",
        "post",
        &room,
        "hey, is the codec work finished? the release is waiting on it",
    ]);
    assert!(ok, "the operator could not ask a question: {err}");
    until(
        &alice,
        "the question to reach alice",
        &["room", "read", &room],
        |o| o.contains("release is waiting"),
    );
    let heard = alice.turn(
        &oc_cfg,
        &room,
        "Did anyone ask you a question just now? Answer yes or no and quote it.",
    );
    assert!(
        heard.contains("release is waiting") || heard.to_lowercase().contains("codec"),
        "plain prose from the operator did not reach an agent's context: {heard:?}"
    );
}
