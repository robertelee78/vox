//! PRD-001 R20 / ADR-017 decision 7 — **local names**: `ssh nas.family.vox`, where `nas`
//! is the name *this* machine gave that node when it trusted it and `family` is *this*
//! machine's name for the room. Proved with the shipped binary (`vox up`, `vox forward`,
//! `vox trust rename`) against real nodes.
//!
//! The scene, from alice's side:
//!
//! - bob created room *family*; alice and carol joined it. bob and carol each serve "port
//!   22" there — an echo that answers with its owner's name.
//! - alice trusts bob as `nas` and carol as `laptop`.
//! - carol also created room *work*, which alice joined; carol serves 22 there too.
//!
//! What must hold:
//!
//! 1. `nas.family.vox` reaches bob and `laptop.family.vox` reaches carol — the member the
//!    name names, not the room's creator.
//! 2. `laptop.work.vox` reaches carol through the second room, under its own name.
//! 3. An unknown room, an unknown node, and an ambiguous node name are refused, each with
//!    a sentence saying which.
//! 4. A node that is no longer trusted has no name.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::io::{Read as _, Write as _};
use std::net::{SocketAddr, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

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

/// `creator` makes a room; everyone in `joiners` joins it under `local_name`.
async fn room(creator: &Member, joiners: &[&Member], local_name: &str) -> Digest32 {
    assert!(creator
        .node
        .apply(NodeCommand::CreateChannel {
            local_name: local_name.into(),
            passphrase: secret(&format!("{local_name} passphrase")),
        })
        .await
        .is_done());
    let cid = wait_for(&creator.node, |e| match e {
        NodeEvent::ChannelOpened { channel_id } => Some(channel_id),
        _ => None,
    })
    .await;
    assert!(creator
        .node
        .apply(NodeCommand::Invite { channel_id: cid })
        .await
        .is_done());
    let url = wait_for(&creator.node, |e| match e {
        NodeEvent::InviteLink { channel_id, url } if channel_id == cid => Some(url),
        _ => None,
    })
    .await;
    for j in joiners {
        assert!(j
            .node
            .apply(NodeCommand::JoinChannel {
                link: url.clone(),
                local_name: local_name.into(),
                passphrase: secret(&format!("{local_name} passphrase")),
            })
            .await
            .is_done());
    }
    cid
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

/// A TCP service that answers each line with `<owner>:<line>`.
fn echo(owner: &'static str) -> SocketAddr {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let at = l.local_addr().unwrap();
    std::thread::spawn(move || {
        for s in l.incoming() {
            let Ok(mut s) = s else { return };
            std::thread::spawn(move || {
                let mut buf = [0u8; 1024];
                while let Ok(n) = s.read(&mut buf) {
                    if n == 0 {
                        return;
                    }
                    let mut out = format!("{owner}:").into_bytes();
                    out.extend_from_slice(&buf[..n]);
                    if s.write_all(&out).is_err() {
                        return;
                    }
                }
            });
        }
    });
    at
}

/// A CONNECT through the proxy to `host:port`; the stream, or the SOCKS reply code.
fn socks(proxy: SocketAddr, host: &str, port: u16) -> Result<TcpStream, u8> {
    let mut s = TcpStream::connect(proxy).unwrap();
    s.set_read_timeout(Some(
        vox_core::node::up::HOST_PATIENCE + Duration::from_secs(30),
    ))
    .unwrap();
    s.write_all(&[0x05, 0x01, 0x00]).unwrap();
    let mut hello = [0u8; 2];
    s.read_exact(&mut hello).unwrap();
    let mut req = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
    req.extend_from_slice(host.as_bytes());
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req).unwrap();
    let mut head = [0u8; 4];
    s.read_exact(&mut head).unwrap();
    if head[1] != 0 {
        return Err(head[1]);
    }
    let skip = match head[3] {
        0x01 => 6,
        0x04 => 18,
        _ => {
            let mut l = [0u8; 1];
            s.read_exact(&mut l).unwrap();
            usize::from(l[0]) + 2
        }
    };
    let mut rest = vec![0u8; skip];
    s.read_exact(&mut rest).unwrap();
    Ok(s)
}

/// Who answers at `name` through the proxy: the owner's name from the echo.
fn who_answers(proxy: SocketAddr, name: &str) -> Result<String, u8> {
    let mut s = socks(proxy, name, 22)?;
    s.write_all(b"hello\n").unwrap();
    let mut buf = [0u8; 64];
    let n = s.read(&mut buf).unwrap();
    let got = String::from_utf8_lossy(&buf[..n]).into_owned();
    Ok(got.split(':').next().unwrap_or("").to_owned())
}

/// `vox forward <name> 22 0` on alice: whether it bound, and what it said.
fn forward(alice: &Member, name: &str) -> (bool, String) {
    let mut child = alice
        .command(&["forward", name, "22", "0"])
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
        let mut pipe = pipe;
        std::thread::spawn(move || {
            let mut buf = [0u8; 1024];
            while let Ok(n) = pipe.read(&mut buf) {
                if n == 0 {
                    return;
                }
                sink.lock()
                    .unwrap()
                    .push_str(&String::from_utf8_lossy(&buf[..n]));
            }
        });
    }
    let until = Instant::now() + Duration::from_secs(20);
    let mut bound = false;
    while Instant::now() < until {
        if said.lock().unwrap().contains("forwarding") {
            bound = true;
            break;
        }
        if let Ok(Some(_)) = child.try_wait() {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let _ = child.kill();
    let _ = child.wait();
    std::thread::sleep(Duration::from_millis(100));
    let out = said.lock().unwrap().clone();
    (bound, out)
}

struct Proxy(Child);

impl Drop for Proxy {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
#[ignore = "three real nodes and real child processes; CI runs it in release"]
fn a_local_name_reaches_the_node_it_names() {
    watchdog::arm();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let (nas_echo, laptop_echo, laptop_work_echo) =
        (echo("bob"), echo("carol"), echo("carol-work"));
    let (alice, bob, carol) = rt.block_on(async {
        let alice = member(&tmp, "alice").await;
        let bob = member(&tmp, "bob").await;
        let carol = member(&tmp, "carol").await;
        let family = room(&bob, &[&alice, &carol], "family").await;
        let work = room(&carol, &[&alice], "work").await;
        trust(&alice, &bob, "nas").await;
        trust(&alice, &carol, "laptop").await;
        trust(&bob, &alice, "alice").await;
        trust(&carol, &alice, "alice").await;
        for (who, cid, at) in [
            (&bob, family, nas_echo),
            (&carol, family, laptop_echo),
            (&carol, work, laptop_work_echo),
        ] {
            assert!(who
                .node
                .apply(NodeCommand::AddService {
                    channel_id: cid,
                    service_tag: "22".into(),
                    local: at,
                })
                .await
                .is_done());
        }
        (alice, bob, carol)
    });
    let _sock = rt.block_on(async { vox_core::node::ipc::bind(alice.node.clone(), &alice.paths) });

    // `vox up`, no room: the proxy inside alice's node, across every room it holds.
    let mut up = alice
        .command(&["up", "--bind", "127.0.0.1:0"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut out = up.stdout.take().unwrap();
    let mut first = String::new();
    let mut byte = [0u8; 1];
    while !first.ends_with('\n') && out.read(&mut byte).unwrap_or(0) == 1 {
        first.push(byte[0] as char);
    }
    let _up = Proxy(up);
    let proxy: SocketAddr = first
        .split_whitespace()
        .nth(3)
        .unwrap_or_else(|| panic!("vox up said {first:?}"))
        .parse()
        .unwrap();

    // (1) and (2): each name reaches the node it names.
    let reached: Vec<(&str, Result<String, u8>)> = [
        "nas.family.vox",
        "laptop.family.vox",
        "laptop.work.vox",
        "NAS.Family.vox",
    ]
    .into_iter()
    .map(|n| (n, who_answers(proxy, n)))
    .collect();
    // (3): refusals, with reasons, from `vox forward`.
    let unknown_room = forward(&alice, "nas.nowhere.vox");
    let unknown_node = forward(&alice, "ghost.family.vox");
    let not_there = forward(&alice, "nas.work.vox");
    let named = forward(&alice, "laptop.family.vox");
    // Two trusted nodes called `nas` in family: ambiguous.
    let rename = alice
        .command(&["trust", "rename", &b32_encode(&carol.fp()), "nas"])
        .env("VOX_IDENTITY_PASSPHRASE", "identity passphrase")
        .output()
        .unwrap();
    let ambiguous = forward(&alice, "nas.family.vox");
    let ambiguous_socks = who_answers(proxy, "nas.family.vox");
    // (4): untrusting carol takes her name away.
    rt.block_on(async {
        assert!(alice
            .node
            .apply(NodeCommand::Untrust {
                fingerprint: carol.fp(),
            })
            .await
            .is_done());
    });
    let untrusted = forward(&alice, "nas.family.vox");
    let now_bob = who_answers(proxy, "nas.family.vox");
    let untrusted_laptop = who_answers(proxy, "laptop.work.vox");

    eprintln!(
        "reached: {reached:?}\nunknown room: {unknown_room:?}\nunknown node: {unknown_node:?}\n\
         nas in work: {not_there:?}\nforward laptop.family: {:?}\nrename: {}{}\nambiguous: \
         {ambiguous:?} / socks {ambiguous_socks:?}\nafter untrusting carol: forward \
         nas.family {untrusted:?}, socks nas.family {now_bob:?}, laptop.work {untrusted_laptop:?}",
        named.0,
        String::from_utf8_lossy(&rename.stdout),
        String::from_utf8_lossy(&rename.stderr)
    );
    let answered = |n: &str| {
        reached
            .iter()
            .find(|(name, _)| *name == n)
            .map(|(_, r)| r.clone())
            .unwrap()
    };
    assert_eq!(answered("nas.family.vox"), Ok("bob".into()), "nas is bob");
    assert_eq!(
        answered("laptop.family.vox"),
        Ok("carol".into()),
        "laptop is carol — not the room's creator"
    );
    assert_eq!(
        answered("laptop.work.vox"),
        Ok("carol-work".into()),
        "the same node through a second room, under that room's name"
    );
    assert_eq!(
        answered("NAS.Family.vox"),
        Ok("bob".into()),
        "names are case-insensitive"
    );
    assert!(named.0, "vox forward takes a name too: {}", named.1);
    assert!(
        !unknown_room.0
            && unknown_room
                .1
                .contains("no room on this machine is called `nowhere`"),
        "{unknown_room:?}"
    );
    assert!(
        !unknown_node.0
            && unknown_node
                .1
                .contains("no node you trust is called `ghost`"),
        "{unknown_node:?}"
    );
    assert!(
        !not_there.0 && not_there.1.contains("not a member of `work`"),
        "{not_there:?}"
    );
    assert!(rename.status.success(), "the rename must succeed");
    assert!(
        !ambiguous.0 && ambiguous.1.contains("names 2 nodes you trust in `family`"),
        "{ambiguous:?}"
    );
    assert_eq!(
        ambiguous_socks,
        Err(2),
        "the proxy refuses an ambiguous name"
    );
    assert!(
        untrusted.0,
        "with carol untrusted, `nas` is bob's again: {untrusted:?}"
    );
    assert_eq!(now_bob, Ok("bob".into()));
    assert_eq!(
        untrusted_laptop,
        Err(2),
        "carol is no longer trusted, so no name reaches her"
    );
    drop(bob);
}
