//! PRD-001 R37 — a running daemon notifies its operator when `vox status` would flag
//! something, **once** when it starts and **once** when it clears.
//!
//! Two real `vox daemon` processes, alice and bob, trusting each other in one room.
//! alice's daemon runs with `VOX_NOTIFY_COMMAND` pointed at a script that appends each
//! notification to a file, so what is counted is the shipped binary's own decision to
//! notify. Kill bob: exactly one "unreachable" notification. Leave him dead for three
//! minutes: still exactly one. Start him again: exactly one "recovered".

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::io::{Read as _, Write as _};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::Value;
use vox_core::hash::Digest32;
use vox_core::nat::multiaddr::Multiaddr;
use vox_core::node::actor::{Node, NodeHandle};
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

fn loopback(node: &NodeHandle) -> SocketAddr {
    node.view()
        .listening
        .iter()
        .filter_map(|m| Multiaddr::parse(m).ok())
        .filter_map(|m| m.socket_addr())
        .find(|a| a.ip().is_loopback())
        .expect("listens on loopback")
}

/// The notifications the script has recorded, one per line.
fn notes(file: &Path) -> Vec<String> {
    std::fs::read_to_string(file)
        .unwrap_or_default()
        .lines()
        .map(str::to_owned)
        .collect()
}

fn count(lines: &[String], needle: &str, peer: &str) -> usize {
    lines
        .iter()
        .filter(|l| l.contains(needle) && l.contains(peer))
        .count()
}

fn daemon(dirs: &Dirs, listen: SocketAddr, notify: Option<&Path>) -> Proc {
    let listen = listen.to_string();
    let mut cmd = dirs.command(&["daemon", "--listen", &listen]);
    if let Some(script) = notify {
        cmd.env("VOX_NOTIFY_COMMAND", script);
    }
    let p = Proc::spawn(cmd, "identity passphrase\nroom passphrase\n");
    p.wait_said("the daemon to hold the room", "holding room");
    p
}

fn wait_until(what: &str, within: Duration, mut f: impl FnMut() -> bool) {
    let until = Instant::now() + within;
    while Instant::now() < until {
        if f() {
            return;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    panic!("timed out waiting for {what}");
}

#[test]
#[ignore = "two real daemons, one killed for three minutes; CI runs it in release"]
fn a_condition_notifies_once_when_it_starts_and_once_when_it_clears() {
    watchdog::arm();
    let rt = rt();
    let tmp = tempfile::tempdir().unwrap();
    let alice_dirs = Dirs::new(&tmp, "alice");
    let bob_dirs = Dirs::new(&tmp, "bob");
    let file = tmp.path().join("notifications.log");
    let script = tmp.path().join("notify.sh");
    std::fs::write(
        &script,
        format!(
            "#!/bin/sh\nprintf '%s|%s\\n' \"$1\" \"$2\" >> '{}'\n",
            file.display()
        ),
    )
    .unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    let (alice_listen, bob_listen, bob_fp) = rt.block_on(async {
        let alice = networked(&alice_dirs).await;
        let bob = networked(&bob_dirs).await;
        let (_, url) = create_room(&alice).await;
        join(&bob, &url).await;
        trust(&alice, fp(&bob)).await;
        trust(&bob, fp(&alice)).await;
        let (a, b, bob_fp) = (loopback(&alice), loopback(&bob), fp(&bob));
        for n in [&alice, &bob] {
            assert!(n.apply(NodeCommand::Shutdown).await.is_done());
        }
        drop((alice, bob));
        port_free(a).await;
        port_free(b).await;
        (a, b, bob_fp)
    });
    let bob_id = b32_encode(&bob_fp);
    let bob_short: String = bob_id.chars().take(12).collect();

    let _alice = daemon(&alice_dirs, alice_listen, Some(&script));
    let mut bob = daemon(&bob_dirs, bob_listen, None);
    let connected = |s: &Value| {
        s["rooms"][0]["members"].as_array().is_some_and(|ms| {
            ms.iter()
                .any(|m| m["id"].as_str() == Some(bob_id.as_str()) && m["connected"] == true)
        })
    };
    wait_until("alice's daemon to reach bob's", TIMEOUT, || {
        connected(&alice_dirs.status())
    });
    // Two checks' worth, so a notification for a healthy state would have fired by now.
    std::thread::sleep(Duration::from_secs(11));
    let healthy = notes(&file);
    assert_eq!(
        count(&healthy, "unreachable", &bob_short),
        0,
        "nothing about bob while he is up: {healthy:?}"
    );

    // Kill bob. QUIC notices at its idle timeout.
    let killed = Instant::now();
    bob.kill();
    wait_until(
        "the unreachable notification",
        Duration::from_secs(150),
        || count(&notes(&file), "unreachable", &bob_short) >= 1,
    );
    let raised_after = killed.elapsed();
    // Three minutes of the same condition.
    std::thread::sleep(Duration::from_secs(180));
    let held = notes(&file);

    // Bring bob back on the same port.
    rt.block_on(port_free(bob_listen));
    let _bob_again = daemon(&bob_dirs, bob_listen, None);
    let back = Instant::now();
    wait_until(
        "the recovered notification",
        Duration::from_secs(120),
        || count(&notes(&file), "recovered", &bob_short) >= 1,
    );
    let recovered_after = back.elapsed();
    // And a little longer, so a second one would have had its chance.
    std::thread::sleep(Duration::from_secs(11));
    let end = notes(&file);
    eprintln!(
        "raised {raised_after:?} after the kill, recovered {recovered_after:?} after the \
         restart\nafter 3 minutes of the condition: {} unreachable line(s)\nall notifications \
         ({}):\n{}",
        count(&held, "unreachable", &bob_short),
        end.len(),
        end.join("\n")
    );
    assert_eq!(
        count(&held, "unreachable", &bob_short),
        1,
        "three minutes of one condition is one notification, not one per check"
    );
    assert_eq!(
        count(&end, "unreachable", &bob_short) - count(&end, "recovered", &bob_short),
        1,
        "still exactly one raised"
    );
    assert_eq!(
        count(&end, "recovered", &bob_short),
        1,
        "and exactly one when it cleared"
    );
}

/// **Opt-out.** With `notify = off` in alice's config the same death raises nothing, and
/// the daemon says at start that notifications are off.
#[test]
#[ignore = "two real daemons, one killed; CI runs it in release"]
fn notify_off_raises_nothing() {
    watchdog::arm();
    let rt = rt();
    let tmp = tempfile::tempdir().unwrap();
    let alice_dirs = Dirs::new(&tmp, "alice");
    let bob_dirs = Dirs::new(&tmp, "bob");
    let file = tmp.path().join("notifications.log");
    let script = tmp.path().join("notify.sh");
    std::fs::write(
        &script,
        format!(
            "#!/bin/sh\nprintf '%s|%s\\n' \"$1\" \"$2\" >> '{}'\n",
            file.display()
        ),
    )
    .unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let (alice_listen, bob_listen, bob_fp) = rt.block_on(async {
        let alice = networked(&alice_dirs).await;
        let bob = networked(&bob_dirs).await;
        let (_, url) = create_room(&alice).await;
        join(&bob, &url).await;
        trust(&alice, fp(&bob)).await;
        trust(&bob, fp(&alice)).await;
        let (a, b, bob_fp) = (loopback(&alice), loopback(&bob), fp(&bob));
        for n in [&alice, &bob] {
            assert!(n.apply(NodeCommand::Shutdown).await.is_done());
        }
        drop((alice, bob));
        port_free(a).await;
        port_free(b).await;
        (a, b, bob_fp)
    });
    std::fs::write(
        alice_dirs.paths().config_file(),
        "# set by the proof\nnotify = off\n",
    )
    .unwrap();
    let bob_id = b32_encode(&bob_fp);
    let alice = daemon(&alice_dirs, alice_listen, Some(&script));
    let mut bob = daemon(&bob_dirs, bob_listen, None);
    wait_until("alice's daemon to reach bob's", TIMEOUT, || {
        alice_dirs.status()["rooms"][0]["members"]
            .as_array()
            .is_some_and(|ms| {
                ms.iter()
                    .any(|m| m["id"].as_str() == Some(bob_id.as_str()) && m["connected"] == true)
            })
    });
    std::thread::sleep(Duration::from_secs(2));
    bob.kill();
    // Until the condition is certainly flagged — status shows it — and one check more.
    let short: String = bob_id.chars().take(12).collect();
    wait_until(
        "alice's status to flag bob",
        Duration::from_secs(150),
        || {
            alice_dirs.status()["unhealthy"]
                .as_array()
                .is_some_and(|u| {
                    u.iter()
                        .any(|l| l["key"].as_str().is_some_and(|k| k.contains(&bob_id)))
                })
        },
    );
    std::thread::sleep(Duration::from_secs(11));
    let lines = notes(&file);
    eprintln!(
        "notify = off: {} notification(s) {lines:?}; alice said: {}",
        lines.len(),
        alice.said()
    );
    assert!(
        lines.is_empty(),
        "notify = off must raise nothing about {short}"
    );
    assert!(
        alice.said().contains("notifications off"),
        "and the daemon must say they are off"
    );
}
