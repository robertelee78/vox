//! V030-35 D4 (#402), on the shipped binary (#410) — **two nodes in one daemon keep their own
//! tunnels** (ADR-026 P-1).
//!
//! One data root holds nodes `a` and `b`, both attached to its one daemon, each serving the same
//! echo service in a room of its own. One guest joins both rooms and forwards to each node's
//! service: the same member, one tunnel to `a` and one to `b`, in one host process. What each node
//! says is read the way a person reads it, `vox status --json --node <n>`, and a tunnel is closed
//! the way a person closes it, `vox tunnel close --node <n>`.
//!
//! 1. **A node closes only its own tunnels.** `a` closing by `b`'s tunnel number closes nothing of
//!    `b`'s; `a` closing the guest's tunnels — the same member `b` serves — closes `a`'s and only
//!    `a`'s closed list shows it, while `b`'s tunnel stays on `b`'s live list.
//! 2. **A stuck tunnel closes by its own node's setting.** `a`'s `config/tunnel-stuck-after` is
//!    [`STUCK_AFTER`], `b`'s far longer. A session to each whose application writes and never reads
//!    the echo: `a`'s tunnel is closed as stuck, not before its setting; `b`'s is still live then,
//!    and `b`'s closed list is empty.
//!
//! The in-process gate `two_nodes_keep_their_own_tunnel_state` keeps what has no surface a person
//! sees: a node's stop waiting only for its own finishing tunnels, and the mux's circuit tables
//! kept per node.
//!
//! **Which side a red is on.** A node listing, closing or timing out another node's tunnel is
//! `PRODUCT:`; a verb the scene needs failing is `APPARATUS (staging not achieved):`, since the
//! scene never formed and nothing was measured; this file's own sockets and threads are
//! `APPARATUS:`. The two rooms have names of their own (`room-a`, `room-b`): a node holds one room
//! of a name, so the guest could not join two rooms named alike.
//!
//! **Mutations that must turn it red** (each reverted after): the owner filter removed from
//! `close_tunnels` → red on 1; `LocalNode::stuck_after` read from one process-wide value → red
//! on 2.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/world.rs"]
mod world;

use std::io::{Read as _, Write as _};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use world::{
    address_in, after_label, args, echo_service, fingerprint, mkdir, room_pass_file, tempdir,
    vox_once, VoxProc,
};

/// `a`'s stuck time: long enough that a session carrying bytes is not mistaken for stuck, short
/// enough to wait out (as `tunnel_honesty_proof` gives its host).
const STUCK_AFTER: Duration = Duration::from_secs(15);
/// `b`'s and the guest's: past this proof's whole wait, so only `a`'s own setting can close a
/// tunnel here.
const LONG: Duration = Duration::from_secs(600);

/// The host's data root, its two nodes, and the guest that reaches both.
struct Scene {
    _reaper: world::Reaper,
    tmp: tempfile::TempDir,
    _anchor: VoxProc,
    host: PathBuf,
    guest_fp: String,
    service: String,
    /// Each node's `vox serve`, held for the scene's life.
    _serves: Vec<VoxProc>,
    /// Each node's forward from the guest, and the address it bound: `a`'s, then `b`'s.
    forwards: Vec<(VoxProc, SocketAddr)>,
}

/// Write `after` as `node`'s own `config/tunnel-stuck-after` under the data root `root`.
fn stuck_after(root: &Path, node: &str, after: Duration) {
    let dir = root.join("nodes").join(node).join("config");
    mkdir(&dir);
    std::fs::write(
        dir.join("tunnel-stuck-after"),
        format!("{}s\n", after.as_secs()),
    )
    .expect("APPARATUS: write a node's tunnel-stuck-after");
}

impl Scene {
    fn new() -> Self {
        let tmp = tempdir();
        let (host, guest, anchor_dir) = (
            tmp.path().join("host"),
            tmp.path().join("guest"),
            tmp.path().join("anchor"),
        );
        for d in [&host, &guest, &anchor_dir] {
            mkdir(&d.join("cfg"));
        }
        let reaper = world::Reaper(vec![host.clone(), guest.clone(), anchor_dir.clone()]);
        let mut anchor = VoxProc::spawn(
            "anchor",
            &anchor_dir,
            &args(&["node", "--listen", "127.0.0.1:0"]),
        );
        let spec = anchor
            .expect_line("an --anchor spec", |l| {
                !l.starts_with("! ")
                    && l.trim_start().contains('@')
                    && l.trim_start().starts_with(|c: char| c.is_alphanumeric())
            })
            .trim()
            .to_owned();

        // The two nodes, each made as a person makes one, each with its own stuck time; the
        // guest's account-wide one is long, so the host is the end that finds a tunnel stuck.
        for node in ["a", "b"] {
            let (ok, out, err) = vox_once(&host, &args(&["id", "--node", node]));
            assert!(
                ok,
                "APPARATUS (staging not achieved): `vox id --node {node}` failed: {out}{err}"
            );
        }
        stuck_after(&host, "a", STUCK_AFTER);
        stuck_after(&host, "b", LONG);
        std::fs::write(
            guest.join("cfg").join("tunnel-stuck-after"),
            format!("{}s\n", LONG.as_secs()),
        )
        .expect("APPARATUS: write the guest's tunnel-stuck-after");
        let guest_fp = fingerprint(&guest, "guest");
        for node in ["a", "b"] {
            let (ok, out, err) = vox_once(
                &host,
                &args(&[
                    "trust",
                    "add",
                    "--node",
                    node,
                    &guest_fp,
                    "--name",
                    "the guest",
                ]),
            );
            assert!(
                ok,
                "APPARATUS (staging not achieved): node {node}'s `vox trust add` of the guest failed: {out}{err}"
            );
        }

        // Each node serves the echo service in a room of its own, in the host's one daemon.
        let port = echo_service();
        let service = port.to_string();
        let mut serves = Vec::new();
        let mut rooms = Vec::new();
        for node in ["a", "b"] {
            let mut serve = VoxProc::spawn(
                &format!("serve-{node}"),
                &host,
                &args(&[
                    "serve",
                    &format!("{port}={port}"),
                    "--node",
                    node,
                    "--anchor",
                    &spec,
                    "--listen",
                    "127.0.0.1:0",
                    "--name",
                    &format!("room-{node}"),
                ]),
            );
            let room = after_label(
                &serve.expect_line("room", |l| l.starts_with("room ")),
                "room",
            );
            let address = after_label(
                &serve.expect_line("address", |l| l.starts_with("address ")),
                "address",
            );
            let pass = after_label(
                &serve.expect_line("passphrase", |l| l.starts_with("passphrase ")),
                "passphrase",
            );
            serves.push(serve);
            rooms.push((node, room, address, pass));
        }
        let daemons = world::daemon_pid(&host);
        assert!(
            daemons.is_some(),
            "APPARATUS (staging not achieved): no daemon holds the host's data root after both nodes serve"
        );

        // The guest joins both rooms, and forwards to each node's service.
        let mut forwards = Vec::new();
        for (node, room, address, pass) in &rooms {
            let pass_file = room_pass_file(tmp.path(), pass);
            let (ok, out, err) = vox_once(
                &guest,
                &args(&[
                    "connect",
                    address,
                    "--passphrase-file",
                    &pass_file,
                    "--anchor",
                    &spec,
                    "--listen",
                    "127.0.0.1:0",
                ]),
            );
            assert!(
                ok,
                "APPARATUS (staging not achieved): the guest could not join node {node}'s room: {out}{err}"
            );
            let (ok, fp, err) = vox_once(&host, &args(&["id", "--node", node]));
            assert!(
                ok,
                "APPARATUS (staging not achieved): `vox id --node {node}`: {err}"
            );
            let mut fwd = VoxProc::spawn(
                &format!("forward-{node}"),
                &guest,
                &args(&[
                    "forward",
                    &format!("{service}.{}.{room}.vox", fp.trim()),
                    "127.0.0.1:0",
                    "--anchor",
                    &spec,
                    "--listen",
                    "127.0.0.1:0",
                ]),
            );
            let line = fwd.expect_line("the forward's bound address", |l| {
                l.starts_with("vox: forwarding ")
            });
            let at = address_in(&mut fwd, &line, 2);
            forwards.push((fwd, at));
        }
        Self {
            _reaper: reaper,
            tmp,
            _anchor: anchor,
            host,
            guest_fp,
            service,
            _serves: serves,
            forwards,
        }
    }

    /// `vox status --json --node <node>` on the host, parsed.
    fn status(&self, node: &str) -> serde_json::Value {
        let (ok, out, err) = vox_once(&self.host, &args(&["status", "--json", "--node", node]));
        assert!(
            ok,
            "PRODUCT: node {node}'s `vox status --json` failed: {err}"
        );
        serde_json::from_str(out.trim()).unwrap_or_else(|e| {
            panic!("PRODUCT: node {node}'s `vox status --json` is not JSON, {out:?}: {e}")
        })
    }

    /// Node `node`'s inbound tunnels to the service in `section` (`tunnels`, `closed_tunnels`).
    fn rows(&self, node: &str, section: &str) -> Vec<serde_json::Value> {
        self.status(node)[section]
            .as_array()
            .map(|rows| {
                rows.iter()
                    .filter(|t| {
                        t["service"].as_str() == Some(self.service.as_str())
                            && t["direction"].as_str() == Some("in")
                    })
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Wait until node `node` lists `n` live inbound tunnels to the service; its rows.
    fn live(&self, node: &str, n: usize) -> Vec<serde_json::Value> {
        let t0 = Instant::now();
        loop {
            let rows = self.rows(node, "tunnels");
            if rows.len() == n || t0.elapsed() > Duration::from_secs(20) {
                return rows;
            }
            std::thread::sleep(Duration::from_millis(200));
        }
    }

    /// `vox tunnel close --node <node> <rest…>` on the host: whether it succeeded, and its words.
    fn close(&self, node: &str, rest: &[&str]) -> (bool, String) {
        let mut argv = vec!["tunnel", "close", "--node", node];
        argv.extend_from_slice(rest);
        let (ok, out, err) = vox_once(&self.host, &args(&argv));
        (ok, format!("{}{}", out.trim(), err.trim()))
    }
}

/// A session to `at` that echoes once and then stays open, idle.
fn session(at: SocketAddr) -> TcpStream {
    let mut s = TcpStream::connect(at).unwrap_or_else(|e| {
        panic!("APPARATUS (staging not achieved): the forward refused a session: {e}")
    });
    s.set_read_timeout(Some(Duration::from_secs(20)))
        .expect("APPARATUS: set a read timeout");
    s.write_all(b"ping")
        .expect("APPARATUS (staging not achieved): write to the forward");
    let mut got = [0u8; 4];
    s.read_exact(&mut got).unwrap_or_else(|e| {
        panic!("APPARATUS (staging not achieved): no echo through the forward: {e}")
    });
    s
}

#[test]
#[ignore = "real daemons with production Argon2id and a real PoW; run in release"]
fn a_node_closes_only_its_own_tunnels() {
    watchdog::arm();
    let s = Scene::new();
    let _a_session = session(s.forwards[0].1);
    let _b_session = session(s.forwards[1].1);
    let (a_live, b_live) = (s.live("a", 1), s.live("b", 1));
    assert!(
        a_live.len() == 1 && b_live.len() == 1,
        "APPARATUS (staging not achieved): each node should list its one tunnel: a {a_live:?}, b {b_live:?}"
    );
    let a_id = a_live[0]["id"]
        .as_u64()
        .expect("PRODUCT: a tunnel row has an id");
    let b_id = b_live[0]["id"]
        .as_u64()
        .expect("PRODUCT: a tunnel row has an id");
    assert_ne!(
        a_id, b_id,
        "PRODUCT: two nodes' tunnels share the number {a_id}"
    );

    // `a` closing by `b`'s tunnel number closes nothing of `b`'s.
    let (_, said) = s.close("a", &["--id", &b_id.to_string()]);
    eprintln!("[proof] a closing b's tunnel {b_id}: {said}");
    assert!(
        !said.contains("closed 1 tunnel"),
        "PRODUCT: `vox tunnel close --node a --id {b_id}` (b's tunnel) said it closed one: {said}"
    );
    std::thread::sleep(Duration::from_secs(1));
    assert_eq!(
        s.rows("b", "tunnels").len(),
        1,
        "PRODUCT: a closing by b's number took b's tunnel off b's live list"
    );

    // `a` closing the guest's tunnels — a member `b` serves too — closes `a`'s alone.
    let prefix = &s.guest_fp[..12];
    let (ok, said) = s.close("a", &[prefix]);
    eprintln!("[proof] a closing the guest's tunnels: {said}");
    assert!(
        ok && said.contains("closed 1 tunnel"),
        "PRODUCT: `vox tunnel close --node a {prefix}` did not close a's one tunnel: {said}"
    );
    let t0 = Instant::now();
    let a_closed = loop {
        let rows = s.rows("a", "closed_tunnels");
        if !rows.is_empty() || t0.elapsed() > Duration::from_secs(8) {
            break rows;
        }
        std::thread::sleep(Duration::from_millis(200));
    };
    assert!(
        a_closed.iter().any(|t| t["id"].as_u64() == Some(a_id)),
        "PRODUCT: a's closed list does not show a's tunnel {a_id}: {a_closed:?}"
    );
    let (b_now, b_closed) = (s.rows("b", "tunnels"), s.rows("b", "closed_tunnels"));
    assert!(
        b_now.len() == 1 && b_closed.is_empty(),
        "PRODUCT: a's close reached b: b lists {b_now:?} live and {b_closed:?} closed"
    );
    eprintln!("[proof] a closed its tunnel {a_id}; b's {b_id} is still live, and b closed nothing");
    let _ = &s.tmp;
}

#[test]
#[ignore = "real daemons with production Argon2id and a real PoW; run in release"]
fn a_stuck_tunnel_closes_by_its_own_nodes_setting() {
    watchdog::arm();
    let s = Scene::new();
    let reported = [
        s.status("a")["tunnel_stuck_after"].as_u64(),
        s.status("b")["tunnel_stuck_after"].as_u64(),
    ];
    assert!(
        reported == [Some(STUCK_AFTER.as_secs()), Some(LONG.as_secs())],
        "PRODUCT: the nodes' own `config/tunnel-stuck-after` say {STUCK_AFTER:?} (a) and {LONG:?} \
         (b), but `vox status --node` reports {reported:?}"
    );

    // A session to each node whose application writes and never reads the echo.
    let mut writers = Vec::new();
    let mut sockets = Vec::new();
    for (_, at) in &s.forwards {
        let stuck = TcpStream::connect(at).unwrap_or_else(|e| {
            panic!("APPARATUS (staging not achieved): the forward refused a session: {e}")
        });
        let mut w = stuck
            .try_clone()
            .expect("APPARATUS: clone a session's socket");
        writers.push(std::thread::spawn(move || {
            let chunk = vec![0x5a_u8; 64 * 1024];
            while w.write(&chunk).is_ok() {}
        }));
        sockets.push(stuck);
    }
    let stuck_from = Instant::now();
    let within = STUCK_AFTER * 2 + Duration::from_secs(20);
    let a_closed = loop {
        let rows: Vec<String> = s
            .rows("a", "closed_tunnels")
            .iter()
            .filter_map(|t| t["why"].as_str().map(str::to_owned))
            .filter(|why| why.starts_with("closed as stuck:"))
            .collect();
        if !rows.is_empty() || stuck_from.elapsed() > within {
            break rows;
        }
        std::thread::sleep(Duration::from_millis(500));
    };
    let ended = stuck_from.elapsed();
    assert!(
        !a_closed.is_empty(),
        "PRODUCT: a's stuck tunnel was not closed as stuck within {within:?}, with a's setting at \
         {STUCK_AFTER:?}; a's closed list: {:?}",
        s.rows("a", "closed_tunnels")
    );
    assert!(
        ended >= STUCK_AFTER,
        "PRODUCT: a's tunnel was closed {ended:?} after its session began, before a's \
         {STUCK_AFTER:?}: {a_closed:?}"
    );
    // `b`'s waited as long, and more: it lives, by `b`'s own setting.
    std::thread::sleep(Duration::from_secs(1));
    let (b_live, b_closed) = (s.rows("b", "tunnels"), s.rows("b", "closed_tunnels"));
    eprintln!(
        "[proof] a's stuck tunnel closed after {ended:?}: {a_closed:?}; b lists {} live, {} closed",
        b_live.len(),
        b_closed.len()
    );
    assert!(
        b_live.len() == 1 && b_closed.is_empty(),
        "PRODUCT: b's tunnel did not outlive a's stuck close, though b gives a stuck tunnel \
         {LONG:?}: b lists {b_live:?} live and {b_closed:?} closed"
    );
    for s in &sockets {
        let _ = s.shutdown(std::net::Shutdown::Both);
    }
    for w in writers {
        let _ = w.join();
    }
}
