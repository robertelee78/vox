//! PRD-001 R18 — `vox share`: a file offered to a room over a room-bound HTTP service,
//! announced with its name, size and SHA-256, pulled with curl through `vox up` or with
//! `vox room get`. Proved with the shipped binary against real nodes.
//!
//! alice shares; bob, whom she trusts, pulls it twice — once with `curl` through his own
//! `vox up`, once with `vox room get`, which lands it in his downloads directory. mallory
//! is in the same room and is not trusted: she can neither read the announcement nor open
//! the service, and her attempts are not fetches. After two fetches (`--count 2`) the share
//! stops by itself. A folder is shared as one tar, and arrives as a valid one.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::io::BufRead as _;
use std::net::SocketAddr;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use sha2::{Digest as _, Sha256};
use vox_core::hash::Digest32;
use vox_core::node::actor::{Node, NodeHandle};
use vox_core::node::api::{NodeCommand, NodeEvent, Secret};
use vox_core::node::link::b32_encode;
use vox_core::node::paths::Paths;

const VOX: &str = env!("CARGO_BIN_EXE_vox");
const TIMEOUT: Duration = Duration::from_secs(60);

fn secret(s: &str) -> Secret {
    Secret::new(s.as_bytes().to_vec())
}

struct Member {
    data: std::path::PathBuf,
    cfg: std::path::PathBuf,
    paths: Paths,
    node: NodeHandle,
}

impl Member {
    fn command(&self, args: &[&str]) -> Command {
        let mut c = Command::new(VOX);
        c.args(args)
            .env("VOX_DATA_DIR", &self.data)
            .env("VOX_CONFIG_DIR", &self.cfg)
            .env_remove("VOX_ROOM")
            .env_remove("VOX_ANCHORS");
        c
    }

    fn fp(&self) -> Digest32 {
        self.node.view().identity.unwrap().fingerprint
    }

    /// Wait until `vox room read` shows `what`: the announcement has synced here.
    fn sees(&self, room: &str, what: &str) {
        let until = Instant::now() + TIMEOUT;
        while Instant::now() < until {
            if self.run(&["room", "read", room]).1.contains(what) {
                return;
            }
            std::thread::sleep(Duration::from_millis(250));
        }
        panic!("the announcement of {what} never reached this member");
    }

    fn run(&self, args: &[&str]) -> (bool, String) {
        let out = self.command(args).stdin(Stdio::null()).output().unwrap();
        (
            out.status.success(),
            format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            ),
        )
    }
}

/// A long-running child, killed by PID however the test ends, its output kept.
struct Proc {
    child: Child,
    said: Arc<Mutex<String>>,
}

impl Proc {
    fn spawn(mut cmd: Command) -> Self {
        let mut child = cmd
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let said = Arc::new(Mutex::new(String::new()));
        for pipe in [
            child
                .stdout
                .take()
                .map(|p| Box::new(p) as Box<dyn std::io::Read + Send>),
            child
                .stderr
                .take()
                .map(|p| Box::new(p) as Box<dyn std::io::Read + Send>),
        ]
        .into_iter()
        .flatten()
        {
            let sink = Arc::clone(&said);
            std::thread::spawn(move || {
                for line in std::io::BufReader::new(pipe).lines() {
                    let Ok(line) = line else { return };
                    let mut s = sink.lock().unwrap();
                    s.push_str(&line);
                    s.push('\n');
                }
            });
        }
        Self { child, said }
    }

    fn said(&self) -> String {
        self.said.lock().unwrap().clone()
    }

    fn wait_line(&self, what: &str, prefix: &str) -> String {
        let until = Instant::now() + TIMEOUT;
        while Instant::now() < until {
            if let Some(l) = self.said().lines().find(|l| l.starts_with(prefix)) {
                return l.to_owned();
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!("timed out waiting for {what}; it said: {}", self.said());
    }
}

impl Drop for Proc {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

async fn member(tmp: &tempfile::TempDir, name: &str) -> Member {
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
    Member {
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

async fn trust(who: &Member, peer: &Member, name: &str) {
    assert!(who
        .node
        .apply(NodeCommand::Trust {
            fingerprint: peer.fp(),
            petname: name.into(),
        })
        .await
        .is_done());
}

/// A `vox up` for `who`, and where it listens.
fn up(who: &Member) -> (Proc, SocketAddr) {
    let p = Proc::spawn(who.command(&["up", "--bind", "127.0.0.1:0"]));
    let line = p.wait_line("vox up's address", "vox up on ");
    let addr = line.split_whitespace().nth(3).unwrap().parse().unwrap();
    (p, addr)
}

/// `curl` through `proxy`: whether it succeeded, and the bytes.
fn curl(proxy: SocketAddr, url: &str) -> (bool, Vec<u8>) {
    let out = Command::new("curl")
        .args([
            "-s",
            "--fail",
            "--max-time",
            "60",
            "--socks5-hostname",
            &proxy.to_string(),
            url,
        ])
        .output()
        .unwrap();
    (out.status.success(), out.stdout)
}

fn sha(b: &[u8]) -> String {
    format!("{:x}", Sha256::digest(b))
}

#[test]
#[ignore = "three real nodes and real child processes; CI runs it in release"]
fn a_share_is_pulled_by_the_trusted_and_by_nobody_else() {
    watchdog::arm();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let payload: Vec<u8> = (0..700_000u32)
        .map(|i| (i.wrapping_mul(97) >> 3) as u8)
        .collect();
    let file = tmp.path().join("report.bin");
    std::fs::write(&file, &payload).unwrap();
    let folder = tmp.path().join("photos");
    std::fs::create_dir_all(folder.join("2026")).unwrap();
    std::fs::write(folder.join("a.txt"), b"first").unwrap();
    std::fs::write(folder.join("2026").join("b.txt"), b"second").unwrap();

    let (alice, bob, mallory, room, _socks) = rt.block_on(async {
        let alice = member(&tmp, "alice").await;
        let bob = member(&tmp, "bob").await;
        let mallory = member(&tmp, "mallory").await;
        assert!(alice
            .node
            .apply(NodeCommand::CreateChannel {
                local_name: "files".into(),
                passphrase: secret("room passphrase"),
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
        for who in [&bob, &mallory] {
            assert!(who
                .node
                .apply(NodeCommand::JoinChannel {
                    link: url.clone(),
                    local_name: "files".into(),
                    passphrase: secret("room passphrase"),
                })
                .await
                .is_done());
        }
        trust(&alice, &bob, "bob").await;
        trust(&bob, &alice, "alice").await;
        // mallory trusts alice — she would like what alice shares — but alice has not
        // trusted her.
        trust(&mallory, &alice, "alice").await;
        wait_for(&bob.node, |e| match e {
            NodeEvent::SenderKeyReceived {
                channel_id, peer, ..
            } if channel_id == cid && peer == alice.fp() => Some(()),
            _ => None,
        })
        .await;
        let socks = [
            vox_core::node::ipc::bind(alice.node.clone(), &alice.paths).unwrap(),
            vox_core::node::ipc::bind(bob.node.clone(), &bob.paths).unwrap(),
            vox_core::node::ipc::bind(mallory.node.clone(), &mallory.paths).unwrap(),
        ];
        (alice, bob, mallory, cid, socks)
    });
    let room_b32 = b32_encode(&room);
    let bob_dl = tmp.path().join("bob-downloads");
    std::fs::write(
        bob.paths.config_file(),
        format!("downloads = {}\n", bob_dl.display()),
    )
    .unwrap();

    let share =
        Proc::spawn(alice.command(&["share", &room_b32, file.to_str().unwrap(), "--count", "2"]));
    let line = share.wait_line("the share's port", "vox: sharing ");
    let port: u16 = line
        .split("on port ")
        .nth(1)
        .and_then(|p| p.trim().parse().ok())
        .unwrap_or_else(|| panic!("no port in {line:?}"));
    let (_bob_up, bob_proxy) = up(&bob);
    let (_mal_up, mal_proxy) = up(&mallory);
    let url = format!("http://alice.files.vox:{port}/report.bin");

    // Fetch 1: bob, with curl through his own `vox up`.
    let (curl_ok, curled) = curl(bob_proxy, &url);
    // mallory: the same URL through her own proxy, and `vox room get`. Neither is a fetch.
    let (mal_curl_ok, mal_curled) = curl(mal_proxy, &url);
    let (mal_get_ok, mal_get_said) = mallory.run(&["room", "get", &room_b32, "report.bin"]);
    let fetches_before_get = share.said().matches("vox: fetched ").count();
    // Fetch 2: bob, with `vox room get`, into his downloads directory, once the
    // announcement has reached him.
    bob.sees(&room_b32, "report.bin");
    let (get_ok, get_said) = bob.run(&["room", "get", &room_b32, "report.bin"]);
    let landed = bob_dl.join("report.bin");
    let got = std::fs::read(&landed).unwrap_or_default();
    // Two fetches: the share stops by itself.
    let mut share = share;
    let until = Instant::now() + Duration::from_secs(20);
    let mut ended = None;
    while Instant::now() < until {
        if let Ok(Some(s)) = share.child.try_wait() {
            ended = Some(s);
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    // A folder, as one tar.
    let folder_share = Proc::spawn(alice.command(&[
        "share",
        &room_b32,
        folder.to_str().unwrap(),
        "--for",
        "120s",
    ]));
    folder_share.wait_line("the folder share", "vox: sharing ");
    bob.sees(&room_b32, "photos.tar");
    let (tar_ok, tar_said) = bob.run(&["room", "get", &room_b32, "photos.tar"]);
    let listing = Command::new("tar")
        .args(["-tf", bob_dl.join("photos.tar").to_str().unwrap()])
        .output()
        .unwrap();
    let listing = String::from_utf8_lossy(&listing.stdout).into_owned();

    eprintln!(
        "curl by bob: ok {curl_ok}, {} bytes, sha {}\nsent {} bytes, sha {}\n\
         mallory curl: ok {mal_curl_ok}, {} bytes; mallory get: ok {mal_get_ok}: {mal_get_said}\
         fetches counted before bob's get: {fetches_before_get}\nbob's get: ok {get_ok}: \
         {get_said}landed {} ({} bytes, sha {})\nshare ended {ended:?}; it said:\n{}\n\
         folder get: ok {tar_ok}: {tar_said}tar lists:\n{listing}",
        curled.len(),
        sha(&curled),
        payload.len(),
        sha(&payload),
        mal_curled.len(),
        landed.display(),
        got.len(),
        sha(&got),
        share.said()
    );
    assert!(
        curl_ok && sha(&curled) == sha(&payload),
        "curl through vox up must get the same bytes"
    );
    assert!(
        !mal_curl_ok && mal_curled.is_empty(),
        "an untrusted member's curl must get nothing"
    );
    assert!(
        !mal_get_ok,
        "an untrusted member's `vox room get` must get nothing"
    );
    assert_eq!(fetches_before_get, 1, "only bob's curl was a fetch");
    assert!(get_ok, "bob's `vox room get` must succeed");
    assert_eq!(
        sha(&got),
        sha(&payload),
        "and land the same bytes in his downloads directory"
    );
    assert!(
        ended.is_some_and(|s| s.success()) && share.said().contains("fetched 2 time(s)"),
        "the share must stop by itself after --count 2"
    );
    assert!(tar_ok, "the folder share must be collectable");
    for entry in [
        "photos/",
        "photos/a.txt",
        "photos/2026/",
        "photos/2026/b.txt",
    ] {
        assert!(
            listing.lines().any(|l| l == entry),
            "the tar must hold {entry}"
        );
    }
    drop((alice, mallory));
}
