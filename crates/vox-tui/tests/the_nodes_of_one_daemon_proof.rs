//! ADR-026 §2 N-1a, §3 L-2 and L-7, and §10 proofs 2, 3, 7 and 9 (#403) — the nodes of one daemon,
//! driven through the shipped `vox` binary as a person types it. Each test names its claim and the
//! mutant that turns it red.
//!
//! - **Names** (N-1a): `vox node create` folds a name to lower case and refuses one that is empty,
//!   longer than 64 bytes, holds a byte outside `[a-z0-9._-]`, starts with `.` or is `nodes`.
//!   Mutant: the reserved-name check dropped from `NodeName::parse`.
//! - **A one-shot verb refuses an unattached node** (L-2, proof 9): with node a attached and b not,
//!   `vox room list --node b` fails, saying how to attach b, and b stays detached. Mutant: a
//!   one-shot verb's `Use` attaching its node.
//! - **A held verb ends with its daemon** (L-7, proof 7): a foreground `vox serve` exits non-zero
//!   once its daemon stops, saying it stopped (the daemon detaches its node as it goes, and the
//!   verb says that). Mutant: the held verb ignoring its connection's close.
//! - **Node to node within one daemon, through a loss and a redial** (I-4, proof 2): b joins a's
//!   room through the daemon's own address, b's post reaches a; b detaches and attaches again, and
//!   its next post reaches a over a new connection. Mutant: the socket dropping datagrams sent to
//!   its own port.
//! - **A detach keeps the other node's tunnel and sync** (D-5, proof 3): a serves, a remote r holds
//!   a stream through a's tunnel and is a member of b's room; b detaches, and the held stream still
//!   echoes, a new one does, and a's post reaches r. Mutant: a node's stop closing the daemon's
//!   presence.
//!
//! `#[ignore]`d: production Argon2id and a real PoW. Run them in release.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

const VOX: &str = env!("CARGO_BIN_EXE_vox");

/// A child `vox`, killed by its own PID when dropped.
struct Kid(Child);

impl Drop for Kid {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// The pid of the daemon holding `dir`'s lock, if one does.
fn daemon_pid(dir: &Path) -> Option<u32> {
    std::fs::read_to_string(dir.join(".daemon").join("lock"))
        .ok()?
        .trim()
        .parse()
        .ok()
}

fn alive(pid: u32) -> bool {
    Command::new("kill")
        .args(["-0", &pid.to_string()])
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// SIGTERM to the daemon of `dir` (a process this proof's verbs started), then wait for it to go.
fn stop_daemon(dir: &Path) {
    let Some(pid) = daemon_pid(dir) else { return };
    let _ = Command::new("kill").arg(pid.to_string()).status();
    let deadline = Instant::now() + Duration::from_secs(15);
    while alive(pid) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(100));
    }
    if alive(pid) {
        let _ = Command::new("kill").args(["-9", &pid.to_string()]).status();
    }
}

/// Stops the daemon of a data root when dropped.
struct Reaper(PathBuf);

impl Drop for Reaper {
    fn drop(&mut self) {
        stop_daemon(&self.0);
    }
}

/// One data root, with a passphrase file per node.
struct Root {
    dir: PathBuf,
}

impl Root {
    fn new(base: &Path, name: &str) -> Self {
        let dir = base.join(name);
        std::fs::create_dir_all(dir.join("cfg")).expect("APPARATUS: harness file I/O");
        Self { dir }
    }

    fn pass_file(&self, node: &str) -> String {
        let p = self.dir.join(format!("{node}.pass"));
        if !p.exists() {
            std::fs::write(&p, format!("{node}'s identity passphrase\n"))
                .expect("APPARATUS: harness file I/O");
        }
        p.to_str().expect("APPARATUS: utf-8 path").to_owned()
    }

    fn file(&self, name: &str, text: &str) -> String {
        let p = self.dir.join(name);
        std::fs::write(&p, format!("{text}\n")).expect("APPARATUS: harness file I/O");
        p.to_str().expect("APPARATUS: utf-8 path").to_owned()
    }

    /// `vox args`; a leading `--node <name>` goes after the verb, where it is a flag.
    fn cmd(&self, args: &[&str]) -> Command {
        let mut cmd = Command::new(VOX);
        match args {
            ["--node", node, rest @ ..] => cmd.args(rest).args(["--node", node]),
            _ => cmd.args(args),
        };
        cmd.env("VOX_DATA_DIR", &self.dir)
            .env("VOX_CONFIG_DIR", self.dir.join("cfg"))
            .env_remove("VOX_NODE")
            .env_remove("VOX_PROFILE")
            .env_remove("VOX_IDENTITY_PASSPHRASE")
            .env_remove("VOX_ANCHORS")
            .env("VOX_LISTEN", "127.0.0.1:0");
        cmd
    }

    fn run(&self, args: &[&str]) -> (bool, String, String) {
        let out = self
            .cmd(args)
            .stdin(Stdio::null())
            .output()
            .expect("APPARATUS: run vox");
        (
            out.status.success(),
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    }

    fn ok(&self, side: &str, args: &[&str]) -> String {
        let (ok, out, err) = self.run(args);
        assert!(ok, "{side} `vox {}` failed:\n{out}{err}", args.join(" "));
        out
    }

    /// A long-running `vox args`, its stdout lines on the returned channel, stderr in a file.
    fn spawn(&self, tag: &str, args: &[&str]) -> (Kid, mpsc::Receiver<String>) {
        let err = std::fs::File::create(self.dir.join(format!("{tag}.err")))
            .expect("APPARATUS: harness file I/O");
        let mut child = self
            .cmd(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::from(err))
            .spawn()
            .expect("APPARATUS: spawn vox");
        let out = child.stdout.take().expect("APPARATUS: vox stdout");
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(out).lines().map_while(Result::ok) {
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        (Kid(child), rx)
    }

    fn said(&self, tag: &str) -> String {
        std::fs::read_to_string(self.dir.join(format!("{tag}.err"))).unwrap_or_default()
    }

    /// Make node `name`: its fingerprint.
    fn make(&self, name: &str) -> String {
        let pf = self.pass_file(name);
        self.ok(
            "PRODUCT (staging):",
            &["node", "create", name, "--passphrase-file", &pf],
        );
        self.ok("PRODUCT (staging):", &["--node", name, "id"])
            .trim()
            .to_owned()
    }

    fn attach(&self, side: &str, name: &str) {
        let pf = self.pass_file(name);
        self.ok(side, &["node", "attach", name, "--passphrase-file", &pf]);
    }

    /// Whether `vox node list` shows `node` attached.
    fn is_attached(&self, node: &str) -> bool {
        let (_, out, _) = self.run(&["node", "list"]);
        out.lines()
            .any(|l| l.split_whitespace().take(2).eq([node, "attached"]))
    }

    fn trust(&self, node: &str, who: &str, name: &str) {
        let pf = self.pass_file(node);
        self.ok(
            "PRODUCT (staging):",
            &[
                "--node",
                node,
                "trust",
                "add",
                who,
                "--name",
                name,
                "--identity-passphrase-file",
                &pf,
            ],
        );
    }

    /// Wait up to 90 s for `node`'s `room read` of `room` to hold `text`.
    fn reads(&self, side: &str, node: &str, room: &str, text: &str) {
        let deadline = Instant::now() + Duration::from_secs(90);
        loop {
            let (_, out, _) = self.run(&["--node", node, "room", "read", room, "--json"]);
            if out.contains(text) {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "{side} node {node} never read {text:?} in room {room}:\n{out}"
            );
            std::thread::sleep(Duration::from_millis(300));
        }
    }
}

/// The first line from `rx` starting with `prefix`, within `within`.
fn line_with(rx: &mpsc::Receiver<String>, prefix: &str, within: Duration, side: &str) -> String {
    let deadline = Instant::now() + within;
    loop {
        match rx.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
            Ok(line) if line.starts_with(prefix) => return line,
            Ok(_) => {}
            Err(_) => panic!("{side} no line starting {prefix:?} within {within:?}"),
        }
    }
}

fn echo_service() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").expect("APPARATUS: bind the echo service");
    let port = l.local_addr().expect("APPARATUS: echo address").port();
    std::thread::spawn(move || {
        for s in l.incoming().map_while(Result::ok) {
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
    port
}

/// Whether `text` sent on `s` comes back whole within 20 s.
fn echoes(s: &mut TcpStream, text: &str) -> bool {
    let _ = s.set_read_timeout(Some(Duration::from_secs(20)));
    if s.write_all(text.as_bytes()).is_err() {
        return false;
    }
    let mut back = vec![0u8; text.len()];
    s.read_exact(&mut back).is_ok() && back == text.as_bytes()
}

/// Node a of `d` serving an echo service in a service room: the serve process, its stdout, the
/// room, its address and its passphrase.
fn serve_a(d: &Root) -> (Kid, mpsc::Receiver<String>, String, String, String, u16) {
    let echo = echo_service();
    let a_pf = d.pass_file("a");
    let spec = format!("web={echo}");
    let (serve, out) = d.spawn(
        "serve",
        &[
            "--node",
            "a",
            "serve",
            &spec,
            "--listen",
            "127.0.0.1:0",
            "--identity-passphrase-file",
            &a_pf,
        ],
    );
    let field = |prefix: &str, within: u64| {
        line_with(
            &out,
            prefix,
            Duration::from_secs(within),
            &format!(
                "PRODUCT (staging): vox serve printed no {prefix:?}: {}",
                d.said("serve")
            ),
        )
        .split_once(' ')
        .map(|(_, v)| v.trim().to_owned())
        .unwrap_or_default()
    };
    let room = field("room ", 120);
    let address = field("address ", 30);
    let passphrase = field("passphrase ", 5);
    (serve, out, room, address, passphrase, echo)
}

#[test]
#[ignore = "real vox binaries and production Argon2id; run in release"]
fn node_names_follow_their_rules() {
    watchdog::arm();
    let tmp = tempfile::tempdir().expect("APPARATUS: tempdir");
    let d = Root::new(tmp.path(), "d");
    let pf = d.pass_file("any");
    let create = |name: &str| d.run(&["node", "create", name, "--passphrase-file", &pf]);
    let long = "a".repeat(65);
    for (name, why) in [
        ("nodes", "is reserved"),
        (".daemon", "must not start with '.'"),
        (".hidden", "must not start with '.'"),
        ("a/b", "holds '/'"),
        ("caf\u{e9}", "holds"),
        (long.as_str(), "must be 1 to 64 bytes long"),
    ] {
        let (ok, out, err) = create(name);
        eprintln!("[proof] vox node create {name:?}: ok={ok} {}", err.trim());
        assert!(
            !ok && err.contains(why),
            "PRODUCT: `vox node create {name:?}` must be refused saying {why:?}; ok={ok}: {out}{err}"
        );
    }
    let (ok, out, err) = create("Agent.Claude-1_x");
    assert!(ok, "PRODUCT: a valid name was refused: {out}{err}");
    let (_, list, _) = d.run(&["node", "list"]);
    assert!(
        list.lines()
            .any(|l| l.split_whitespace().next() == Some("agent.claude-1_x")),
        "PRODUCT: the name was not folded to lower case; `vox node list` says:\n{list}"
    );
    let (ok, _, err) = create("AGENT.CLAUDE-1_X");
    assert!(
        !ok,
        "PRODUCT: the same name in other case made a second node: {err}"
    );
    let sixty_four = "b".repeat(64);
    let (ok, out, err) = create(&sixty_four);
    assert!(ok, "PRODUCT: a 64-byte name was refused: {out}{err}");
}

#[test]
#[ignore = "real vox daemons and production Argon2id; run in release"]
fn a_one_shot_verb_refuses_an_unattached_node() {
    watchdog::arm();
    let tmp = tempfile::tempdir().expect("APPARATUS: tempdir");
    let d = Root::new(tmp.path(), "d");
    let _reaper = Reaper(d.dir.clone());
    d.make("a");
    d.make("b");
    d.attach("PRODUCT (staging):", "a");
    assert!(
        !d.is_attached("b"),
        "PRODUCT (staging): node b is attached before anything asked for it"
    );
    let (ok, out, err) = d.run(&["--node", "b", "room", "list"]);
    eprintln!(
        "[proof] `vox room list --node b` with b not attached: ok={ok} {}",
        err.trim()
    );
    assert!(
        !ok && err.contains("node b is not attached") && err.contains("vox node attach b"),
        "PRODUCT: a one-shot verb for an unattached node must refuse, saying how to attach it; \
         ok={ok}: {out}{err}"
    );
    assert!(
        !d.is_attached("b"),
        "PRODUCT: the refused one-shot verb attached node b"
    );
}

#[test]
#[ignore = "real vox daemons and production Argon2id; run in release"]
fn a_foreground_serve_exits_when_its_daemon_stops() {
    watchdog::arm();
    let tmp = tempfile::tempdir().expect("APPARATUS: tempdir");
    let d = Root::new(tmp.path(), "d");
    let _reaper = Reaper(d.dir.clone());
    d.make("a");
    let (mut serve, out, _room, _address, _pass, _echo) = serve_a(&d);
    assert!(
        serve.0.try_wait().ok().flatten().is_none(),
        "PRODUCT (staging): vox serve ended before its daemon was stopped: {}",
        d.said("serve")
    );
    stop_daemon(&d.dir);
    let t0 = Instant::now();
    let status = loop {
        if let Some(s) = serve.0.try_wait().ok().flatten() {
            break Some(s);
        }
        if t0.elapsed() > Duration::from_secs(15) {
            break None;
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    let stdout: Vec<String> = out.try_iter().collect();
    let said = format!("{}{}", stdout.join("\n"), d.said("serve"));
    eprintln!("[proof] after its daemon stopped, vox serve: {status:?}; it said:\n{said}");
    let status = status.unwrap_or_else(|| {
        panic!("PRODUCT: vox serve was still running 15 s after its daemon stopped:\n{said}")
    });
    assert!(
        // The daemon detaches its nodes as it stops, so the held verb hears either.
        !status.success()
            && (said.contains("the vox daemon stopped, so this stopped")
                || said.contains("was detached from the vox daemon, so this stopped")),
        "PRODUCT: vox serve must exit non-zero saying its daemon stopped; it exited {status}:\n{said}"
    );
}

#[test]
#[ignore = "real vox daemons, production Argon2id and a real PoW; run in release"]
fn two_nodes_of_one_daemon_reach_each_other_through_a_loss_and_a_redial() {
    watchdog::arm();
    let tmp = tempfile::tempdir().expect("APPARATUS: tempdir");
    let d = Root::new(tmp.path(), "d");
    let _reaper = Reaper(d.dir.clone());
    let a_fp = d.make("a");
    let b_fp = d.make("b");
    let (_serve, _out, room, address, passphrase, _echo) = serve_a(&d);
    d.attach("PRODUCT (staging):", "b");
    // b joins a's room through the daemon's own address: node to node within one daemon (I-4).
    let room_pf = d.file("a-room.pass", &passphrase);
    let b_pf = d.pass_file("b");
    d.ok(
        "PRODUCT:",
        &[
            "--node",
            "b",
            "connect",
            &address,
            "--passphrase-file",
            &room_pf,
            "--identity-passphrase-file",
            &b_pf,
        ],
    );
    d.trust("a", &b_fp, "b");
    d.trust("b", &a_fp, "a");
    d.ok(
        "PRODUCT:",
        &["--node", "b", "room", "post", &room, "b to a, first"],
    );
    d.reads("PRODUCT:", "a", &room, "b to a, first");
    eprintln!("[proof] b reached a through their one daemon's address; a read b's post");

    // The loss: b detaches, so every connection between them goes; then b comes back.
    d.ok("PRODUCT:", &["node", "detach", "b"]);
    assert!(
        !d.is_attached("b"),
        "PRODUCT (staging): b still attached after its detach"
    );
    d.attach("PRODUCT:", "b");
    d.ok(
        "PRODUCT:",
        &[
            "--node",
            "b",
            "room",
            "post",
            &room,
            "b to a, after the redial",
        ],
    );
    d.reads("PRODUCT:", "a", &room, "b to a, after the redial");
    eprintln!("[proof] after b's detach and attach, its post reached a again");
}

#[test]
#[ignore = "real vox daemons, production Argon2id and a real PoW; run in release"]
fn a_detach_keeps_the_other_nodes_tunnel_and_sync() {
    watchdog::arm();
    let tmp = tempfile::tempdir().expect("APPARATUS: tempdir");
    let d = Root::new(tmp.path(), "d");
    let r = Root::new(tmp.path(), "r");
    let _d_reaper = Reaper(d.dir.clone());
    let _r_reaper = Reaper(r.dir.clone());
    let a_fp = d.make("a");
    let b_fp = d.make("b");
    let r_fp = r.make("r");
    let (_serve, _out, a_room, address, passphrase, _echo) = serve_a(&d);

    // b has a room r joins: r holds a connection to each of a and b.
    d.attach("PRODUCT (staging):", "b");
    let bx_pf = d.file("bx.pass", "b's room passphrase");
    d.ok(
        "PRODUCT (staging):",
        &[
            "--node",
            "b",
            "room",
            "create",
            "--name",
            "bx",
            "--passphrase-file",
            &bx_pf,
        ],
    );
    let bx = d
        .ok("PRODUCT (staging):", &["--node", "b", "room", "list"])
        .lines()
        .find(|l| l.split_whitespace().nth(1) == Some("bx"))
        .and_then(|l| l.split_whitespace().next())
        .expect("PRODUCT (staging): b's room list does not show bx")
        .to_owned();
    let b_link = d
        .ok("PRODUCT (staging):", &["--node", "b", "room", "link", &bx])
        .lines()
        .next()
        .unwrap_or_default()
        .trim()
        .to_owned();
    let a_room_pf = r.file("a-room.pass", &passphrase);
    let r_pf = r.pass_file("r");
    // Attached by hand first, so nothing in the staging detaches a node: the claim is about the
    // one detach below.
    r.attach("PRODUCT (staging):", "r");
    r.ok(
        "PRODUCT (staging):",
        &[
            "--node",
            "r",
            "connect",
            &address,
            "--passphrase-file",
            &a_room_pf,
            "--identity-passphrase-file",
            &r_pf,
        ],
    );
    let r_bx_pf = r.file("bx.pass", "b's room passphrase");
    r.ok(
        "PRODUCT (staging):",
        &[
            "--node",
            "r",
            "room",
            "join",
            &b_link,
            "--name",
            "bx",
            "--passphrase-file",
            &r_bx_pf,
        ],
    );
    d.trust("a", &r_fp, "r");
    d.trust("b", &r_fp, "r");
    r.trust("r", &a_fp, "a");
    r.trust("r", &b_fp, "b");
    d.ok(
        "PRODUCT (staging):",
        &["--node", "b", "room", "post", &bx, "b, before"],
    );
    r.reads("PRODUCT (staging):", "r", &bx, "b, before");

    // r's tunnel to a's service, with a stream held open across the detach.
    let name = format!("web.{a_fp}.{a_room}.vox");
    let (_forward, fwd_out) = r.spawn("forward", &["--node", "r", "forward", &name, "127.0.0.1:0"]);
    let local = line_with(
        &fwd_out,
        "vox: forwarding ",
        Duration::from_secs(120),
        &format!(
            "PRODUCT (staging): r's forward never bound: {}",
            r.said("forward")
        ),
    )
    .trim_start_matches("vox: forwarding ")
    .split_whitespace()
    .next()
    .unwrap_or_default()
    .to_owned();
    let mut held =
        TcpStream::connect(&local).expect("PRODUCT (staging): the forward takes nothing");
    assert!(
        echoes(&mut held, "before b detached"),
        "PRODUCT (staging): no echo through a's tunnel before b detached"
    );

    // b detaches.
    d.ok("PRODUCT:", &["node", "detach", "b"]);
    assert!(
        !d.is_attached("b"),
        "PRODUCT (staging): b still attached after its detach"
    );

    // a's tunnel and sync go on.
    for i in 0..3 {
        assert!(
            echoes(&mut held, &format!("after b detached, {i}")),
            "PRODUCT: the stream through a's tunnel stopped echoing when b detached (round {i})"
        );
    }
    let mut fresh =
        TcpStream::connect(&local).expect("PRODUCT: the forward takes nothing after b's detach");
    assert!(
        echoes(&mut fresh, "a new stream after b detached"),
        "PRODUCT: a new stream through a's tunnel did not echo after b detached"
    );
    d.ok(
        "PRODUCT:",
        &["--node", "a", "room", "post", &a_room, "a, after b left"],
    );
    r.reads("PRODUCT:", "r", &a_room, "a, after b left");
    eprintln!("[proof] after b detached: a's tunnel echoed on the held and a new stream, and a's post reached r");
}
