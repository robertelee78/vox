//! **Two nodes on one presence: detaching one leaves the other's tunnel and sync moving** (#403 /
//! D5; ADR-026 D-3, D-5), with real node actors in one process.
//!
//! Nodes A and B attach to one [`NetPresence`] (`Bind::Shared`), as two nodes of one daemon do. A
//! third node, C, runs on a presence of its own. B serves a TCP echo service in a service room; C
//! joins it, forwards a local port to the service, and the two trust each other. A makes a room of
//! its own and C joins that too, so A holds a connection to C as well. Then A detaches (its
//! actor's stop: goodbye, its own connections closed, off the exchange). What must hold:
//! - a TCP stream C had open through the forward before A left keeps echoing, and a new one
//!   echoes too (the tunnel moves);
//! - a message B posts after A left reaches C (sync moves).
//!
//! **Mutant that must turn it red, as PRODUCT:** a node's stop closes the presence even when it
//! did not make it (the endpoint closed on a detach).
//!
//! In-process because nothing yet hosts two nodes on one presence in the shipped binary (the
//! daemon process is D7); the real-binary form comes with D12. Production Argon2id and a real PoW:
//! run in release. Every wait is bounded (vox-core forbids the `unsafe` the shared watchdog
//! needs).

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use vox_core::hash::Digest32;
use vox_core::node::actor::{Bind, EventStreamItem, Node, NodeConfig, NodeHandle};
use vox_core::node::api::{NodeCommand, NodeEvent, Secret};
use vox_core::node::paths::{Account, NodeName};
use vox_core::node::presence::NetPresence;

const PASS: &str = "identity passphrase for the proof";

/// A fresh directory under the system temp dir, removed when dropped.
struct Dir(PathBuf);

impl Dir {
    fn new(tag: &str) -> Self {
        let mut r = [0u8; 8];
        getrandom::fill(&mut r).expect("APPARATUS: random");
        let p = std::env::temp_dir().join(format!(
            "vox-presence-{tag}-{}-{:x}",
            std::process::id(),
            u64::from_le_bytes(r)
        ));
        std::fs::create_dir_all(&p).expect("APPARATUS: temp dir");
        Self(p)
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A node `name` in its own account under `dir`, with a fresh identity, its network on `bind`.
async fn node(dir: &Dir, name: &str, bind: Bind) -> (NodeHandle, tokio::task::JoinHandle<()>) {
    let account = Account::of(
        Some(&dir.0.join(name).join("d")),
        Some(&dir.0.join(name).join("c")),
    )
    .expect("APPARATUS: account");
    let paths = account
        .node_paths(&NodeName::parse(name).expect("APPARATUS: name"))
        .expect("APPARATUS: node paths");
    let cfg = NodeConfig::new().bind(bind);
    let (handle, actor) = tokio::task::spawn_blocking(move || Node::spawn_supervised(paths, cfg))
        .await
        .expect("APPARATUS: spawn")
        .expect("APPARATUS: the node did not start");
    let made = handle
        .apply(NodeCommand::CreateIdentity {
            passphrase: Secret::new(PASS.as_bytes().to_vec()),
        })
        .await;
    assert!(
        made.is_done(),
        "APPARATUS: create {name}'s identity: {made}"
    );
    let actor = tokio::spawn(async move {
        let _ = vox_core::node::actor::ActorEnd::of(actor).await;
    });
    (handle, actor)
}

fn fp(h: &NodeHandle) -> Digest32 {
    h.view()
        .identity
        .expect("APPARATUS: the node has an identity")
        .fingerprint
}

/// The first event of `h`'s after `start` that `pick` takes, within `wait`.
async fn event<T>(
    events: &mut vox_core::node::actor::EventStream,
    wait: Duration,
    what: &str,
    mut pick: impl FnMut(&NodeEvent) -> Option<T>,
) -> T {
    let found = tokio::time::timeout(wait, async {
        while let Some(item) = events.next().await {
            if let EventStreamItem::Event(ev) = item {
                if let Some(t) = pick(&ev) {
                    return Some(t);
                }
            }
        }
        None
    })
    .await;
    match found {
        Ok(Some(t)) => t,
        _ => panic!("PRODUCT (staging): no {what} within {wait:?}"),
    }
}

/// A room `h` holds by its local name.
fn room(h: &NodeHandle, name: &str) -> Digest32 {
    h.view()
        .channels
        .iter()
        .find(|c| c.local_name.as_deref() == Some(name))
        .map(|c| c.channel_id)
        .unwrap_or_else(|| panic!("PRODUCT (staging): no room {name}"))
}

/// `h` invites to `channel_id`; `joiner` joins with `pass`.
async fn invite_and_join(h: &NodeHandle, channel_id: Digest32, joiner: &NodeHandle, pass: &str) {
    let mut events = h.subscribe();
    let asked = h.apply(NodeCommand::Invite { channel_id }).await;
    assert!(asked.is_done(), "PRODUCT (staging): invite: {asked}");
    let url = event(
        &mut events,
        Duration::from_secs(30),
        "invite link",
        |e| match e {
            NodeEvent::InviteLink { url, .. } => Some(url.clone()),
            _ => None,
        },
    )
    .await;
    let mut joined = joiner.subscribe();
    let join = joiner
        .apply(NodeCommand::JoinChannel {
            link: url,
            local_name: format!("joined-{:02x}{:02x}", channel_id[0], channel_id[1]),
            passphrase: Secret::new(pass.as_bytes().to_vec()),
        })
        .await;
    assert!(join.is_done(), "PRODUCT (staging): join: {join}");
    event(&mut joined, Duration::from_secs(120), "join", |e| match e {
        NodeEvent::Joined { channel_id: c, .. } if *c == channel_id => Some(()),
        _ => None,
    })
    .await;
}

/// A TCP echo service on loopback.
fn echo_service() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").expect("APPARATUS: echo listener");
    let at = l.local_addr().expect("APPARATUS: echo addr");
    std::thread::spawn(move || {
        for s in l.incoming().flatten() {
            std::thread::spawn(move || {
                let mut s = s;
                let mut buf = [0u8; 4096];
                while let Ok(n) = s.read(&mut buf) {
                    if n == 0 || s.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
            });
        }
    });
    at
}

/// Write `msg` on `s` and read the echo back, within 10 s.
fn echoes(s: &mut TcpStream, msg: &[u8]) -> bool {
    let _ = s.set_read_timeout(Some(Duration::from_secs(10)));
    if s.write_all(msg).is_err() {
        return false;
    }
    let mut got = vec![0u8; msg.len()];
    s.read_exact(&mut got).is_ok() && got == msg
}

/// `b` posts `text` in `room`; it must be readable at `c` within 60 s, else a red labelled `side`.
async fn posted(b: &NodeHandle, c: &NodeHandle, room: Digest32, text: &str, side: &str) {
    let sent = b
        .apply(NodeCommand::SendText {
            channel_id: room,
            text: text.into(),
        })
        .await;
    assert!(sent.is_done(), "PRODUCT (staging): B's post: {sent}");
    let author = fp(b);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    loop {
        let read = c.view().open_channels.iter().any(|d| {
            d.channel_id == room
                && d.timeline
                    .iter()
                    .any(|r| r.author == author && r.text == text)
        });
        if read {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "{side}: B's post {text:?} was not readable at C within 60 s"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
#[ignore = "real node actors, production Argon2id and a real PoW; run in release"]
async fn detaching_one_node_leaves_the_others_tunnel_and_sync_moving() {
    let dir = Dir::new("d5");
    let presence = NetPresence::bind("127.0.0.1:0".parse().expect("addr"))
        .expect("APPARATUS: bind the presence");
    let (a, a_actor) = node(&dir, "a", Bind::Shared(Arc::clone(&presence))).await;
    let (b, _b_actor) = node(&dir, "b", Bind::Shared(Arc::clone(&presence))).await;
    let (c, _c_actor) = node(&dir, "c", Bind::Addr("127.0.0.1:0".parse().expect("addr"))).await;
    let (fa, fb, fc) = (fp(&a), fp(&b), fp(&c));

    // B serves an echo service; C joins its room; each trusts the other.
    let service = echo_service();
    let pass_b = vox_core::node::passphrase::generate(6).expect("APPARATUS: passphrase");
    let served = b
        .apply(NodeCommand::Serve {
            local_name: "b-room".into(),
            passphrase: Secret::new(pass_b.as_bytes().to_vec()),
            name: "echo".into(),
            port: service.port(),
            udp: false,
            at: Some(service),
        })
        .await;
    assert!(served.is_done(), "PRODUCT (staging): serve: {served}");
    let b_room = room(&b, "b-room");
    invite_and_join(&b, b_room, &c, &pass_b).await;
    for (h, other, name) in [(&b, fc, "c"), (&c, fb, "b")] {
        let t = h
            .apply(NodeCommand::Trust {
                fingerprint: other,
                petname: name.into(),
            })
            .await;
        assert!(t.is_done(), "PRODUCT (staging): trust: {t}");
    }

    // A's own room, which C joins too: A holds a connection to C.
    let pass_a = vox_core::node::passphrase::generate(6).expect("APPARATUS: passphrase");
    let made = a
        .apply(NodeCommand::CreateChannel {
            local_name: "a-room".into(),
            passphrase: Secret::new(pass_a.as_bytes().to_vec()),
        })
        .await;
    assert!(made.is_done(), "PRODUCT (staging): A's room: {made}");
    let a_room = room(&a, "a-room");
    invite_and_join(&a, a_room, &c, &pass_a).await;

    // C forwards a port to B's echo service; a stream through it echoes.
    let mut c_events = c.subscribe();
    let fwd = c
        .apply(NodeCommand::Forward {
            channel_id: b_room,
            host: fb,
            service_tag: "echo".into(),
            local: "127.0.0.1:0".parse().expect("addr"),
        })
        .await;
    assert!(fwd.is_done(), "PRODUCT (staging): forward: {fwd}");
    let local = event(
        &mut c_events,
        Duration::from_secs(30),
        "forward",
        |e| match e {
            NodeEvent::Forwarding { local, .. } => Some(*local),
            _ => None,
        },
    )
    .await;
    let held = tokio::task::spawn_blocking(move || {
        let mut s = TcpStream::connect(local).expect("APPARATUS: connect to the forward");
        let ok = echoes(&mut s, b"before A left");
        (s, ok)
    })
    .await
    .expect("APPARATUS: echo task");
    assert!(
        held.1,
        "PRODUCT (staging): no echo through B's tunnel before A left"
    );

    // Before A leaves: a post of B's reaches C (the staging's own check).
    posted(&b, &c, b_room, "written before A left", "PRODUCT (staging)").await;

    // A detaches: its actor stops (goodbye, its own connections closed, off the exchange).
    let stopped = a.apply(NodeCommand::Shutdown).await;
    assert!(stopped.is_done(), "APPARATUS: A's stop: {stopped}");
    drop(a);
    tokio::time::timeout(Duration::from_secs(15), a_actor)
        .await
        .expect("PRODUCT: A's actor did not stop within 15 s")
        .expect("APPARATUS: A's actor task");
    assert!(
        !presence.shared().registered().contains(&fa),
        "PRODUCT: A was still answered for after its detach"
    );

    // B's tunnel still moves: the stream held across the detach, and a new one.
    let (s, _) = held;
    let after = tokio::task::spawn_blocking(move || {
        let mut s = s;
        let old = echoes(&mut s, b"after A left, same stream");
        let mut n = TcpStream::connect(local).expect("APPARATUS: connect again");
        (old, echoes(&mut n, b"after A left, new stream"))
    })
    .await
    .expect("APPARATUS: echo task");
    assert!(
        after.0,
        "PRODUCT: B's tunnel stream held across A's detach stopped echoing"
    );
    assert!(
        after.1,
        "PRODUCT: a new stream through B's tunnel did not echo after A's detach"
    );

    // B's sync still moves: a message B posts now reaches C.
    posted(&b, &c, b_room, "written after A left", "PRODUCT").await;
    eprintln!("[proof] after A detached, B's tunnel echoed and B's post reached C");
    let _ = b.apply(NodeCommand::Shutdown).await;
    let _ = c.apply(NodeCommand::Shutdown).await;
    presence.close().await;
}
