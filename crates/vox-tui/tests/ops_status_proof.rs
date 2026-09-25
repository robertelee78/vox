//! PRD-001 R35 and R38 — `vox status` and `vox daemon --metrics`, proved with the shipped
//! binary against real nodes.
//!
//! 1. **A relayed path is named, with its relay.** Two nodes behind symmetric NATs reach
//!    each other only through an anchor; `vox status --json` says `relayed` and names the
//!    anchor.
//! 2. **A served tunnel is listed while it is in use, and not after.**
//! 3. **The metrics endpoint counts traffic**, and a daemon asked to serve it where the
//!    network can reach it refuses to start.
//! 4. **A peer that dies is flagged.** Kill a trusted member's daemon and the status says
//!    it is unreachable.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "../../vox-core/tests/support/vnet.rs"]
mod vnet;

use std::io::{Read as _, Write as _};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::Value;
use vnet::{NatKind, VirtualNet};
use vox_core::hash::Digest32;
use vox_core::identity::composite::RootSigner;
use vox_core::nat::bootstrap::{BootstrapNode, BootstrapSet};
use vox_core::nat::multiaddr::{EndpointList, Multiaddr};
use vox_core::node::actor::{Bind, Node, NodeConfig, NodeHandle};
use vox_core::node::api::{NodeCommand, NodeEvent, Secret};
use vox_core::node::link::b32_encode;
use vox_core::node::paths::Paths;

const VOX: &str = env!("CARGO_BIN_EXE_vox");
const TIMEOUT: Duration = Duration::from_secs(60);

fn secret(s: &str) -> Secret {
    Secret::new(s.as_bytes().to_vec())
}

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap()
}

/// A profile's directories, and how the binary is pointed at them.
#[derive(Clone)]
struct Dirs {
    data: PathBuf,
    cfg: PathBuf,
}

impl Dirs {
    fn new(tmp: &tempfile::TempDir, name: &str) -> Self {
        Self {
            data: tmp.path().join(name).join("data"),
            cfg: tmp.path().join(name).join("cfg"),
        }
    }

    fn paths(&self) -> Paths {
        Paths::resolve("default", Some(&self.data), Some(&self.cfg)).unwrap()
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut c = Command::new(VOX);
        c.args(args)
            .env("VOX_DATA_DIR", &self.data)
            .env("VOX_CONFIG_DIR", &self.cfg)
            .env_remove("VOX_ROOM")
            .env_remove("VOX_ANCHORS")
            .env_remove("VOX_LISTEN");
        c
    }

    /// `vox status --json`, parsed.
    fn status(&self) -> Value {
        let out = self
            .command(&["status", "--json"])
            .stdin(Stdio::null())
            .output()
            .expect("spawn vox status");
        assert!(
            out.status.success(),
            "vox status failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        serde_json::from_slice(&out.stdout).expect("vox status --json prints JSON")
    }

    /// `vox status`, for a person.
    fn status_text(&self) -> String {
        let out = self
            .command(&["status"])
            .stdin(Stdio::null())
            .output()
            .expect("spawn vox status");
        String::from_utf8_lossy(&out.stdout).into_owned()
    }
}

/// A child process, killed by its PID however the test ends.
struct Proc {
    child: Child,
    said: Arc<Mutex<String>>,
}

impl Proc {
    fn spawn(mut cmd: Command, stdin: &str) -> Self {
        let mut child = cmd
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn vox");
        let mut into = child.stdin.take().unwrap();
        into.write_all(stdin.as_bytes()).unwrap();
        drop(into);
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
                let mut buf = [0u8; 4096];
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
        Self { child, said }
    }

    fn said(&self) -> String {
        self.said.lock().unwrap().clone()
    }

    fn wait_said(&self, what: &str, needle: &str) -> String {
        let until = Instant::now() + TIMEOUT;
        while Instant::now() < until {
            let s = self.said();
            if s.contains(needle) {
                return s;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!("timed out waiting for {what}; it said: {}", self.said());
    }

    fn kill(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for Proc {
    fn drop(&mut self) {
        self.kill();
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

async fn create_room(node: &NodeHandle) -> (Digest32, String) {
    assert!(node
        .apply(NodeCommand::CreateChannel {
            local_name: "ops".into(),
            passphrase: secret("room passphrase"),
        })
        .await
        .is_done());
    let cid = node.view().channels[0].channel_id;
    assert!(node
        .apply(NodeCommand::Invite { channel_id: cid })
        .await
        .is_done());
    let url = wait_for(node, |e| match e {
        NodeEvent::InviteLink { channel_id, url } if channel_id == cid => Some(url),
        _ => None,
    })
    .await;
    (cid, url)
}

async fn join(node: &NodeHandle, url: &str) {
    let out = node
        .apply(NodeCommand::JoinChannel {
            link: url.to_owned(),
            local_name: "ops".into(),
            passphrase: secret("room passphrase"),
        })
        .await;
    assert!(out.is_done(), "join: {out:?}");
}

async fn trust(node: &NodeHandle, peer: Digest32) {
    assert!(node
        .apply(NodeCommand::Trust {
            fingerprint: peer,
            petname: "peer".into(),
        })
        .await
        .is_done());
}

async fn networked(dirs: &Dirs) -> NodeHandle {
    let node = Node::spawn_networked(dirs.paths(), "127.0.0.1:0".parse().unwrap()).unwrap();
    assert!(node
        .apply(NodeCommand::CreateIdentity {
            passphrase: secret("identity passphrase"),
        })
        .await
        .is_done());
    node
}

fn fp(node: &NodeHandle) -> Digest32 {
    node.view().identity.unwrap().fingerprint
}

fn peer_in<'a>(status: &'a Value, id: &Digest32) -> Option<&'a Value> {
    let id = b32_encode(id);
    status["peers"]
        .as_array()?
        .iter()
        .find(|p| p["id"].as_str() == Some(id.as_str()))
}

/// **(1) A relayed path is named, with its relay.**
#[test]
#[ignore = "a relayed join on a simulated NAT network and real child processes; CI runs it in release"]
fn status_names_the_relayed_path_and_the_relay() {
    watchdog::arm();
    let rt = rt();
    let tmp = tempfile::tempdir().unwrap();
    let (alice_dirs, _keep, carol_fp, bob_fp) = rt.block_on(async {
        // A clock that does not move, so the hourly-ish retry for a direct path never
        // comes due: the path stays what the network allows, which is a circuit.
        let now = Arc::new(AtomicU64::new(1_800_000_000));
        let clock: vox_core::time::Clock = {
            let now = Arc::clone(&now);
            Arc::new(move || now.load(Ordering::SeqCst))
        };
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        let addr = |s: &str| s.parse::<SocketAddr>().unwrap();
        let net = VirtualNet::new();
        let c_addr = addr("198.51.100.1:443");
        let c_sock = net.public(c_addr);
        let a_sock = net.behind_nat(addr("10.0.1.2:5000"), NatKind::Symmetric, ip("203.0.113.1"));
        let b_sock = net.behind_nat(addr("10.0.2.2:5000"), NatKind::Symmetric, ip("203.0.113.2"));

        let carol_dirs = Dirs::new(&tmp, "anchor");
        let carol_signer =
            vox_core::node::headless::load_or_create_identity(&carol_dirs.paths()).unwrap();
        let carol_fp = RootSigner::public_key(&carol_signer).fingerprint();
        let carol = Node::spawn_config(
            carol_dirs.paths(),
            NodeConfig::new()
                .bind(Bind::Socket(c_sock))
                .headless(carol_signer)
                .clock(Arc::clone(&clock)),
        )
        .unwrap();
        let mut anchors = BootstrapSet::new();
        anchors
            .add(
                BootstrapNode::new(
                    carol_fp,
                    EndpointList::new(vec![Multiaddr::from(c_addr)]).unwrap(),
                )
                .unwrap(),
            )
            .unwrap();
        let spawn = |dirs: &Dirs, sock| {
            let mut cfg = NodeConfig::new()
                .bind(Bind::Socket(sock))
                .anchors(anchors.clone())
                .clock(Arc::clone(&clock));
            cfg.pow_params = Some(vox_core::join::pow::PowParams { n: 48, k: 5 });
            Node::spawn_config(dirs.paths(), cfg).unwrap()
        };
        let alice_dirs = Dirs::new(&tmp, "alice");
        let bob_dirs = Dirs::new(&tmp, "bob");
        let alice = spawn(&alice_dirs, a_sock);
        let bob = spawn(&bob_dirs, b_sock);
        for n in [&alice, &bob] {
            assert!(n
                .apply(NodeCommand::CreateIdentity {
                    passphrase: secret("identity passphrase"),
                })
                .await
                .is_done());
        }
        let bob_fp = fp(&bob);
        let (_, url) = create_room(&alice).await;
        join(&bob, &url).await;
        tokio::time::timeout(TIMEOUT, async {
            while !alice.view().relayed_peers.contains(&bob_fp) {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        .expect("alice must reach bob over the relay, or this proves nothing");
        let sock = vox_core::node::ipc::bind(alice.clone(), &alice_dirs.paths()).unwrap();
        (alice_dirs, (sock, alice, bob, carol, net), carol_fp, bob_fp)
    });

    let status = alice_dirs.status();
    let text = alice_dirs.status_text();
    let bob_row = peer_in(&status, &bob_fp).cloned();
    eprintln!(
        "alice's status for bob: {bob_row:?}\nrelay is {}\nhuman form:\n{text}",
        b32_encode(&carol_fp)
    );
    let bob_row = bob_row.expect("bob must be listed among alice's peers");
    assert_eq!(bob_row["path"], "relayed", "the path to bob is a circuit");
    assert_eq!(
        bob_row["relay"].as_str(),
        Some(b32_encode(&carol_fp).as_str()),
        "and the relay carrying it must be named"
    );
    let carol_short: String = b32_encode(&carol_fp).chars().take(12).collect();
    assert!(
        text.contains(&format!("relayed via {carol_short}")),
        "the human form must say it too"
    );
}

/// A TCP echo server, for a service to carry.
fn echo_server() -> SocketAddr {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let at = l.local_addr().unwrap();
    std::thread::spawn(move || {
        for s in l.incoming() {
            let Ok(mut s) = s else { return };
            std::thread::spawn(move || {
                let mut buf = [0u8; 1024];
                while let Ok(n) = s.read(&mut buf) {
                    if n == 0 || s.write_all(&buf[..n]).is_err() {
                        return;
                    }
                }
            });
        }
    });
    at
}

/// **(2) A served tunnel is listed while it is in use, and not after.**
#[test]
#[ignore = "real nodes and real child processes; CI runs it in release"]
fn a_served_tunnel_is_listed_while_in_use() {
    watchdog::arm();
    let rt = rt();
    let tmp = tempfile::tempdir().unwrap();
    let (alice_dirs, bob_dirs) = (Dirs::new(&tmp, "alice"), Dirs::new(&tmp, "bob"));
    let echo = echo_server();
    let (local, bob_fp, _keep) = rt.block_on(async {
        let alice = networked(&alice_dirs).await;
        let bob = networked(&bob_dirs).await;
        let (cid, url) = create_room(&alice).await;
        join(&bob, &url).await;
        trust(&alice, fp(&bob)).await;
        trust(&bob, fp(&alice)).await;
        assert!(alice
            .apply(NodeCommand::AddService {
                channel_id: cid,
                service_tag: "echo".into(),
                local: echo,
            })
            .await
            .is_done());
        assert!(bob
            .apply(NodeCommand::Forward {
                channel_id: cid,
                host: fp(&alice),
                service_tag: "echo".into(),
                local: "127.0.0.1:0".parse().unwrap(),
            })
            .await
            .is_done());
        let local = bob.view().forwards[0].local;
        let sockets = (
            vox_core::node::ipc::bind(alice.clone(), &alice_dirs.paths()).unwrap(),
            vox_core::node::ipc::bind(bob.clone(), &bob_dirs.paths()).unwrap(),
        );
        (local, fp(&bob), (sockets, alice, bob))
    });

    let before = alice_dirs.status();
    // In use: a line crosses and comes back.
    let mut tcp = std::net::TcpStream::connect(local).unwrap();
    tcp.write_all(b"ping\n").unwrap();
    let mut got = [0u8; 5];
    tcp.read_exact(&mut got).unwrap();
    assert_eq!(&got, b"ping\n");
    let during = alice_dirs.status();
    let bob_view = bob_dirs.status();
    drop(tcp);
    let until = Instant::now() + Duration::from_secs(20);
    let mut after = alice_dirs.status();
    while !after["tunnels_served"].as_array().unwrap().is_empty() && Instant::now() < until {
        std::thread::sleep(Duration::from_millis(200));
        after = alice_dirs.status();
    }
    let count = |v: &Value| v["tunnels_served"].as_array().map_or(0, Vec::len);
    eprintln!(
        "served tunnels at alice: before {} during {} after {}\nduring: {}\nbob dials: {}",
        count(&before),
        count(&during),
        count(&after),
        during["tunnels_served"],
        bob_view["tunnels_dialed"]
    );
    assert_eq!(count(&before), 0, "nothing is served before a connection");
    assert_eq!(
        count(&during),
        1,
        "the tunnel must be listed while it carries bytes"
    );
    assert_eq!(during["tunnels_served"][0]["service"], "echo");
    assert_eq!(
        during["tunnels_served"][0]["client"].as_str(),
        Some(b32_encode(&bob_fp).as_str()),
        "and name who is using it"
    );
    assert_eq!(
        bob_view["tunnels_dialed"].as_array().map_or(0, Vec::len),
        1,
        "the dial side lists its forward"
    );
    assert_eq!(
        count(&after),
        0,
        "and must be gone once the connection closes"
    );
}

fn curl(url: &str) -> String {
    let out = Command::new("curl")
        .args(["-s", "--max-time", "10", url])
        .output()
        .expect("curl");
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn metric(text: &str, name: &str) -> Option<u64> {
    text.lines()
        .find(|l| l.starts_with(name) && !l.starts_with('#'))
        .and_then(|l| l.rsplit(' ').next())
        .and_then(|v| v.parse().ok())
}

/// Alice's profile with one room she holds, her node stopped so a daemon can take the
/// profile, and the port she listened on so the invite's address stays true.
async fn stopped_host(dirs: &Dirs) -> (Digest32, String, SocketAddr) {
    let alice = networked(dirs).await;
    let (cid, url) = create_room(&alice).await;
    let port = alice
        .view()
        .listening
        .iter()
        .filter_map(|m| Multiaddr::parse(m).ok())
        .filter_map(|m| m.socket_addr())
        .find(|a| a.ip().is_loopback())
        .expect("alice listens on loopback");
    let fp = fp(&alice);
    assert!(alice.apply(NodeCommand::Shutdown).await.is_done());
    drop(alice);
    // The store is single-writer and the port is about to be reused: wait until the
    // stopped node has let go of both, rather than guessing how long that takes.
    port_free(port).await;
    let _ = fp;
    (cid, url, port)
}

/// Wait until nothing holds UDP `port`, so a daemon can bind it.
async fn port_free(addr: SocketAddr) {
    let until = Instant::now() + TIMEOUT;
    while Instant::now() < until {
        if std::net::UdpSocket::bind(addr).is_ok() {
            // Let the store's lock go too: it is released with the same node.
            tokio::time::sleep(Duration::from_millis(200)).await;
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("{addr} was never released by the stopped node");
}

/// **(3) The metrics endpoint counts traffic, and refuses the network.**
#[test]
#[ignore = "a real daemon and a real node; CI runs it in release"]
fn metrics_count_traffic_and_refuse_a_non_loopback_bind() {
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();

    let rt = rt();
    let alice_dirs = Dirs::new(&tmp, "alice");
    let bob_dirs = Dirs::new(&tmp, "bob");
    let (cid, url, listen) = rt.block_on(stopped_host(&alice_dirs));

    // Refused: a profile that would otherwise start — it has an identity and the right
    // passphrase — asked to serve metrics on every interface. Without the check it would
    // come up and serve them there.
    let mut refused = Proc::spawn(
        alice_dirs.command(&[
            "daemon",
            "--listen",
            "127.0.0.1:0",
            "--metrics",
            "0.0.0.0:0",
        ]),
        "identity passphrase\nroom passphrase\n",
    );
    let started = Instant::now();
    let mut exit = None;
    while started.elapsed() < Duration::from_secs(10) {
        if let Ok(Some(s)) = refused.child.try_wait() {
            exit = Some(s);
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    eprintln!(
        "non-loopback --metrics: exit {exit:?}, said: {}",
        refused.said()
    );
    assert!(
        exit.is_some_and(|s| !s.success()),
        "a daemon asked to serve metrics on every interface must refuse to start"
    );
    assert!(refused.said().contains("loopback only"), "and say why");
    refused.kill();
    let listen = listen.to_string();
    let daemon = Proc::spawn(
        alice_dirs.command(&["daemon", "--listen", &listen, "--metrics", "127.0.0.1:0"]),
        "identity passphrase\nroom passphrase\n",
    );
    let said = daemon.wait_said("the metrics address", "/metrics");
    let url_metrics = said
        .lines()
        .find_map(|l| l.strip_prefix("vox daemon: metrics "))
        .expect("the daemon prints where metrics are")
        .trim()
        .to_owned();
    let quiet = curl(&url_metrics);
    let before = (
        metric(&quiet, "vox_peers_connected"),
        metric(&quiet, "vox_room_last_sync_seconds"),
    );

    // Traffic: bob joins the daemon's room and they sync.
    let _bob = rt.block_on(async {
        let bob = networked(&bob_dirs).await;
        join(&bob, &url).await;
        bob
    });
    let until = Instant::now() + TIMEOUT;
    let mut busy = curl(&url_metrics);
    while metric(&busy, "vox_room_last_sync_seconds").unwrap_or(0) == 0 && Instant::now() < until {
        std::thread::sleep(Duration::from_millis(250));
        busy = curl(&url_metrics);
    }
    let after = (
        metric(&busy, "vox_peers_connected"),
        metric(&busy, "vox_room_last_sync_seconds"),
    );
    eprintln!(
        "metrics before (peers, room last sync) {before:?}, after {after:?}\nroom {}\n{busy}",
        b32_encode(&cid)
    );
    assert_eq!(metric(&busy, "vox_up"), Some(1));
    assert_eq!(before, (Some(0), Some(0)), "nothing before any traffic");
    assert!(
        after.0.unwrap_or(0) >= 1 && after.1.unwrap_or(0) > 0,
        "after traffic the connection and the room's sync must be counted: {after:?}"
    );
    assert!(
        busy.contains("vox_peer_rtt_milliseconds{peer="),
        "per-peer gauges must be there"
    );
}

/// **(4) A peer that dies is flagged.** bob runs as a real daemon; alice trusts him and
/// is connected to him. Kill bob, and alice's status must say he is unreachable.
#[test]
#[ignore = "a real daemon killed mid-run; waits out QUIC's idle timeout; CI runs it in release"]
fn a_killed_peer_is_flagged_unhealthy() {
    watchdog::arm();
    let rt = rt();
    let tmp = tempfile::tempdir().unwrap();
    let alice_dirs = Dirs::new(&tmp, "alice");
    let bob_dirs = Dirs::new(&tmp, "bob");
    // bob: identity and membership first, then his node stops so a daemon takes over.
    let (alice, bob_fp, bob_listen, _sock) = rt.block_on(async {
        let alice = networked(&alice_dirs).await;
        let bob = networked(&bob_dirs).await;
        let (_, url) = create_room(&alice).await;
        join(&bob, &url).await;
        let bob_fp = fp(&bob);
        trust(&alice, bob_fp).await;
        trust(&bob, fp(&alice)).await;
        let bob_listen = bob
            .view()
            .listening
            .iter()
            .filter_map(|m| Multiaddr::parse(m).ok())
            .filter_map(|m| m.socket_addr())
            .find(|a| a.ip().is_loopback())
            .unwrap();
        assert!(bob.apply(NodeCommand::Shutdown).await.is_done());
        drop(bob);
        port_free(bob_listen).await;
        let sock = vox_core::node::ipc::bind(alice.clone(), &alice_dirs.paths()).unwrap();
        (alice, bob_fp, bob_listen, sock)
    });
    let listen = bob_listen.to_string();
    let mut bob = Proc::spawn(
        bob_dirs.command(&["daemon", "--listen", &listen]),
        "identity passphrase\nroom passphrase\n",
    );
    bob.wait_said("bob's daemon to hold the room", "holding room");
    let connected = |s: &Value| {
        s["rooms"][0]["members"]
            .as_array()
            .unwrap()
            .iter()
            .any(|m| {
                m["id"].as_str() == Some(b32_encode(&bob_fp).as_str()) && m["connected"] == true
            })
    };
    let until = Instant::now() + TIMEOUT;
    let mut s = alice_dirs.status();
    while !connected(&s) && Instant::now() < until {
        std::thread::sleep(Duration::from_millis(250));
        s = alice_dirs.status();
    }
    assert!(connected(&s), "alice must be connected to bob first: {s}");
    // Let the tick file bob as seen.
    std::thread::sleep(Duration::from_millis(1500));
    let healthy = alice_dirs.status();
    let bob_short: String = b32_encode(&bob_fp).chars().take(12).collect();
    let flagged = |s: &Value| {
        s["unhealthy"].as_array().unwrap().iter().any(|l| {
            l.as_str()
                .is_some_and(|l| l.contains(&bob_short) && l.contains("unreachable"))
        })
    };
    assert!(
        !flagged(&healthy),
        "bob must not be flagged while alive: {healthy}"
    );

    let killed = Instant::now();
    bob.kill();
    // QUIC notices a silent peer at its idle timeout (60 s), not before.
    let until = Instant::now() + Duration::from_secs(120);
    let mut s = alice_dirs.status();
    while !flagged(&s) && Instant::now() < until {
        std::thread::sleep(Duration::from_millis(500));
        s = alice_dirs.status();
    }
    eprintln!(
        "{:?} after bob was killed alice's status says: {}\nhuman form:\n{}",
        killed.elapsed(),
        s["unhealthy"],
        alice_dirs.status_text()
    );
    assert!(
        flagged(&s),
        "alice must flag bob as unreachable once he is gone: {s}"
    );
    drop(alice);
}
