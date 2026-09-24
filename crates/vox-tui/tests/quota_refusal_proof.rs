//! ADR-021 F14 — **a rate limit says it is a rate limit**, through the shipped `vox`
//! binary.
//!
//! ADR-008's per-author quota admits at most 1,000 entries per identity per rolling
//! hour (`log/quota.rs`), and refusing the next one is correct. What was wrong is how
//! the refusal reached the person: `append_text` discarded `Quota(RateExceeded)` and
//! the post failed as `vox: Failed(Internal)` — indistinguishable from a bug, with no
//! word that it was a limit or that it clears by itself. An agent that hits it cannot
//! tell whether to wait, retry or report a defect.
//!
//! What this drives: one real node alone in a room (no peer is needed — the quota is
//! this identity's own), posting through the control socket until the quota refuses
//! it, and then the **shipped `vox room post`**, as an agent's shell would run it.
//!
//! What it asserts:
//!
//! 1. the refusal arrives where ADR-008 puts it — at the quota, about the 1,000th
//!    entry, not earlier and not never;
//! 2. `vox room post` exits non-zero and says **rate limited**, names the cap, says the
//!    window is a rolling hour and **when posting works again**;
//! 3. it does **not** say `Failed(Internal)`;
//! 4. the time it gives is in the future and no more than an hour away — the window's
//!    own bound — so it is a real answer rather than a placeholder.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::process::{Command, Stdio};

use vox_core::node::actor::Node;
use vox_core::node::api::{NodeCommand, Secret};
use vox_core::node::ipc::{Frame, IpcClient, Request};
use vox_core::node::paths::Paths;

const VOX: &str = env!("CARGO_BIN_EXE_vox");

fn secret(s: &str) -> Secret {
    Secret::new(s.as_bytes().to_vec())
}

#[test]
#[ignore = "one node with production Argon2id and 1,000+ posts; CI runs it in release"]
fn a_rate_limited_post_says_so_and_says_when_it_clears() {
    watchdog::arm();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let data = tmp.path().join("data");
    let cfg = tmp.path().join("cfg");
    let paths = Paths::resolve("default", Some(&data), Some(&cfg)).unwrap();

    let (_sock, cid) = rt.block_on(async {
        let node = Node::spawn_networked(paths.clone(), "127.0.0.1:0".parse().unwrap()).unwrap();
        assert!(node
            .apply(NodeCommand::CreateIdentity {
                passphrase: secret("identity passphrase"),
            })
            .await
            .is_done());
        assert!(node
            .apply(NodeCommand::CreateChannel {
                local_name: "alone".into(),
                passphrase: secret("channel passphrase"),
            })
            .await
            .is_done());
        let cid = node.view().channels[0].channel_id;
        let sock = vox_core::node::ipc::bind(node.clone(), &paths).expect("socket");
        (sock, cid)
    });
    let room = vox_core::node::link::b32_encode(&cid);

    // ---- (1) post until the quota refuses ----
    let sock = paths.socket_file();
    let (accepted, first_refusal) = rt.block_on(async move {
        let mut c = IpcClient::open(&sock).await.expect("socket");
        let mut accepted = 0u32;
        for i in 0..1_100u32 {
            match c
                .request(&Request::Post {
                    channel_id: cid,
                    text: format!("message {i}"),
                })
                .await
            {
                Ok(Frame::Ok) => accepted += 1,
                Ok(Frame::Error { reason }) => return (accepted, reason),
                other => panic!("post {i}: {other:?}"),
            }
        }
        (accepted, String::new())
    });
    eprintln!("[receipt] {accepted} posts accepted; first refusal: {first_refusal:?}");
    assert!(
        !first_refusal.is_empty(),
        "1,100 posts in a minute were all accepted — the quota never refused, so this \
         proved nothing"
    );
    assert!(
        (990..=1_000).contains(&accepted),
        "the refusal should come at ADR-008's 1,000-per-hour cap (less the room's own \
         set-up entries), not after {accepted}"
    );

    // ---- (2)–(4) the shipped binary says what it is ----
    let out = Command::new(VOX)
        .args(["room", "post", &room, "one more"])
        .env("VOX_DATA_DIR", &data)
        .env("VOX_CONFIG_DIR", &cfg)
        .env_remove("VOX_ROOM")
        .stdin(Stdio::null())
        .output()
        .expect("spawn vox");
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    eprintln!(
        "[receipt] vox room post {room} \"one more\" -> exit {:?}\n  stderr: {}",
        out.status.code(),
        stderr.trim()
    );
    assert!(!out.status.success(), "a refused post must not succeed");
    assert!(
        !stderr.contains("Failed(Internal)"),
        "a rate limit was reported as an internal fault: {stderr}"
    );
    assert!(
        stderr.contains("rate limited") && stderr.contains("1000 entries in the last hour"),
        "the refusal must say it is a rate limit and name the cap: {stderr}"
    );
    assert!(
        stderr.contains("posting works again in"),
        "the refusal must say when it clears: {stderr}"
    );
    let clears: u64 = stderr
        .split("at unix time ")
        .nth(1)
        .and_then(|t| t.split(|c: char| !c.is_ascii_digit()).next())
        .and_then(|t| t.parse().ok())
        .unwrap_or_else(|| panic!("no clear time in: {stderr}"));
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    assert!(
        clears > now && clears <= now + 3_600,
        "the clear time {clears} must be in the next hour (now {now})"
    );
}
