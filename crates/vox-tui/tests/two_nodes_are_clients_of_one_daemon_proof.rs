//! ADR-026 §10.1 and §10.4 (#406, V030-35-D8) — every verb is a client of the daemon. Two nodes in
//! one data root serve and post at once through one daemon, a remote reaches both at the daemon's
//! one ip:port, and neither node can list or close the other's tunnel. Driven through the shipped
//! `vox` binary, as a person types it:
//!
//! ```text
//! vox node create a; vox node create b                   (data root D)
//! vox --node a serve web=<echo port> --listen 127.0.0.1:0 (starts D's daemon; a held while it runs)
//! vox node attach b; vox --node b room create bx; vox --node b room link bx
//! vox node create r                                     (data root R, the remote)
//! vox --node r connect <a's address> --listen …; vox node attach r; vox --node r room join <b's link>
//! vox trust add … (a and b trust r, r trusts b)
//! vox --node b room post bx …; vox --node r room read …  (while a serves)
//! vox --node r forward web.<a>.<room>.vox                (r reaches a's service: bytes echo)
//! vox --node b status --json; vox --node b tunnel close --id <a's tunnel>
//! ```
//!
//! Each claim and its mutant:
//! - `vox serve` hosts no node: the process holds no UDP socket, the daemon holds the one (mutant:
//!   a verb that opens its own endpoint, red as `PRODUCT: vox serve holds a UDP socket`);
//! - a's address and b's link name the daemon's one port;
//! - b posts and r reads it while a serves; r reaches a's service through the daemon;
//! - b's status lists none of a's tunnels, and b's close of a's tunnel closes nothing (mutant: the
//!   owner filter in `close_tunnels` dropped, red as `PRODUCT: node b closed node a's tunnel`).

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/typed.rs"]
mod typed;

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

/// The pid of the daemon holding `dir`'s lock (it writes it there), if one does.
fn daemon_pid(dir: &Path) -> Option<u32> {
    std::fs::read_to_string(dir.join(".daemon").join("lock"))
        .ok()?
        .trim()
        .parse()
        .ok()
}

/// Stops the daemon of a data root by its pid when dropped, and waits for it to go (never by a
/// pattern).
struct Reaper(PathBuf);

impl Drop for Reaper {
    fn drop(&mut self) {
        let Some(pid) = daemon_pid(&self.0) else {
            return;
        };
        let _ = Command::new("kill").arg(pid.to_string()).status();
        let deadline = Instant::now() + Duration::from_secs(15);
        while Instant::now() < deadline
            && Command::new("kill")
                .args(["-0", &pid.to_string()])
                .status()
                .is_ok_and(|s| s.success())
        {
            std::thread::sleep(Duration::from_millis(100));
        }
        let _ = Command::new("kill").args(["-9", &pid.to_string()]).status();
    }
}

/// One data root: its directory, and a passphrase file per node.
struct Root {
    dir: PathBuf,
}

impl Root {
    fn new(base: &Path, name: &str) -> Self {
        let dir = base.join(name);
        std::fs::create_dir_all(dir.join("cfg")).expect("APPARATUS: harness file I/O");
        Self { dir }
    }

    fn pass_file(&self, node: &str) -> PathBuf {
        let p = self.dir.join(format!("{node}.pass"));
        if !p.exists() {
            std::fs::write(&p, format!("{node}'s identity passphrase\n"))
                .expect("APPARATUS: harness file I/O");
        }
        p
    }

    /// `vox args`; a leading `--node <name>` is given after the verb, where it is a flag.
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
            .env_remove("VOX_LISTEN");
        cmd
    }

    /// Run `vox args` to its end: success, stdout, stderr.
    fn run(&self, args: &[&str]) -> (bool, String, String) {
        let mut cmd = self.cmd(args);
        // A keyring change's passphrase is typed at a terminal, as a person types it (ADR-028
        // K-13).
        if typed::is_keyring_change(args) {
            let (ok, shown) = typed::keyring(&cmd);
            return (ok, shown.clone(), shown);
        }
        let out = cmd
            .stdin(Stdio::null())
            .output()
            .expect("APPARATUS: run vox");
        (
            out.status.success(),
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    }

    /// Run `vox args` that must succeed; its stdout. `side` labels a failure.
    fn ok(&self, side: &str, args: &[&str]) -> String {
        let (ok, out, err) = self.run(args);
        assert!(ok, "{side} `vox {}` failed:\n{out}{err}", args.join(" "));
        out
    }

    /// Start a long-running `vox args`, its stdout lines sent to the returned channel.
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

    /// Wait until `vox node list` shows `node` attached.
    fn attached(&self, side: &str, node: &str) {
        let deadline = Instant::now() + Duration::from_secs(90);
        loop {
            let (_, out, _) = self.run(&["node", "list"]);
            if out
                .lines()
                .any(|l| l.split_whitespace().take(2).eq([node, "attached"]))
            {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "{side} node {node} never showed attached:\n{out}"
            );
            std::thread::sleep(Duration::from_millis(200));
        }
    }
}

/// The first line from `rx` with `prefix`, waiting up to `within`; `side` labels a timeout.
fn line_with(rx: &mpsc::Receiver<String>, prefix: &str, within: Duration, side: &str) -> String {
    let deadline = Instant::now() + within;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        match rx.recv_timeout(left) {
            Ok(line) if line.starts_with(prefix) => return line,
            Ok(_) => {}
            Err(_) => panic!("{side} no line starting {prefix:?} within {within:?}"),
        }
    }
}

/// Every UDP port in a `vox://` link's addresses.
fn link_ports(url: &str) -> Vec<u16> {
    let url = url.replace("%2F", "/").replace("%2f", "/");
    url.split("/udp/")
        .skip(1)
        .filter_map(|rest| {
            rest.split(|c: char| !c.is_ascii_digit())
                .next()
                .and_then(|p| p.parse().ok())
        })
        .collect()
}

/// The UDP sockets process `pid` holds, as `lsof` lists them.
fn udp_sockets(pid: u32) -> Vec<String> {
    let out = Command::new("lsof")
        .args(["-nP", "-a", "-p", &pid.to_string(), "-iUDP"])
        .output()
        .expect("APPARATUS: run lsof");
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .skip(1)
        .map(str::to_owned)
        .collect()
}

/// A TCP echo service on loopback: its port.
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

/// Send `text` on `s` and read it back; `side` labels a failure.
fn echoes(s: &mut TcpStream, text: &str, side: &str) {
    s.set_read_timeout(Some(Duration::from_secs(30)))
        .expect("APPARATUS: socket timeout");
    s.write_all(text.as_bytes())
        .unwrap_or_else(|e| panic!("{side} writing to the forward: {e}"));
    let mut back = vec![0u8; text.len()];
    s.read_exact(&mut back)
        .unwrap_or_else(|e| panic!("{side} reading back through the forward: {e}"));
    assert_eq!(
        back,
        text.as_bytes(),
        "{side} the forward carried other bytes"
    );
}

/// The live tunnels `node`'s status lists: `(id, peer)`.
fn tunnels(root: &Root, node: &str) -> Vec<(u64, String)> {
    let json = root.ok("PRODUCT:", &["--node", node, "status", "--json"]);
    let v: serde_json::Value =
        serde_json::from_str(&json).expect("PRODUCT: vox status --json is not JSON");
    v["tunnels"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|t| {
            (
                t["id"].as_u64().unwrap_or_default(),
                t["peer"].as_str().unwrap_or_default().to_owned(),
            )
        })
        .collect()
}

#[test]
#[ignore = "real vox daemons and production Argon2id; run on demand in release"]
fn two_nodes_serve_and_post_through_one_daemon_and_keep_their_own_tunnels() {
    watchdog::arm();
    let tmp = tempfile::tempdir().expect("APPARATUS: tempdir");
    let d = Root::new(tmp.path(), "d");
    let r = Root::new(tmp.path(), "r");

    // ---- the nodes, made in the client; nothing attached --------------------------------
    for node in ["a", "b"] {
        let pf = d.pass_file(node);
        d.ok(
            "PRODUCT (staging):",
            &[
                "node",
                "create",
                node,
                "--passphrase-file",
                pf.to_str().unwrap(),
            ],
        );
    }
    let pf = r.pass_file("r");
    let r_fp = r
        .ok(
            "PRODUCT (staging):",
            &[
                "node",
                "create",
                "r",
                "--passphrase-file",
                pf.to_str().unwrap(),
            ],
        )
        .lines()
        .last()
        .unwrap_or_default()
        .trim()
        .to_owned();
    let a_fp = d
        .ok("PRODUCT (staging):", &["--node", "a", "id"])
        .trim()
        .to_owned();
    let b_fp = d
        .ok("PRODUCT (staging):", &["--node", "b", "id"])
        .trim()
        .to_owned();
    assert!(
        a_fp.len() == 52 && b_fp.len() == 52 && r_fp.len() == 52 && a_fp != b_fp,
        "PRODUCT (staging): three nodes, three fingerprints: {a_fp} {b_fp} {r_fp}"
    );

    // ---- no daemon yet: the first verb that holds a node starts it (S-2) ------------------
    let _d_daemon = Reaper(d.dir.clone());
    let _r_daemon = Reaper(r.dir.clone());

    // ---- a serves, held through the daemon -------------------------------------------------
    let echo = echo_service();
    let a_pf = d.pass_file("a");
    let spec = format!("web={echo}");
    let (mut serve, serve_out) = d.spawn(
        "serve",
        &[
            "--node",
            "a",
            "serve",
            &spec,
            "--listen",
            "127.0.0.1:0",
            "--identity-passphrase-file",
            a_pf.to_str().unwrap(),
        ],
    );
    let room_line = line_with(
        &serve_out,
        "room ",
        Duration::from_secs(120),
        &format!("PRODUCT: vox serve printed no room: {}", d.said("serve")),
    );
    let a_room = room_line
        .split_whitespace()
        .nth(1)
        .unwrap_or_default()
        .to_owned();
    let address = line_with(&serve_out, "address ", Duration::from_secs(30), "PRODUCT:")
        .split_whitespace()
        .nth(1)
        .unwrap_or_default()
        .to_owned();
    let passphrase = line_with(
        &serve_out,
        "passphrase ",
        Duration::from_secs(5),
        "PRODUCT:",
    )
    .split_once(' ')
    .map(|(_, p)| p.trim().to_owned())
    .unwrap_or_default();
    d.attached("PRODUCT:", "a");

    // **No verb hosts a node** (S-3): the serving process holds no UDP socket; the daemon holds
    // the one endpoint.
    let own = udp_sockets(serve.0.id());
    assert!(
        own.is_empty(),
        "PRODUCT: vox serve holds a UDP socket of its own, so it hosts a node:\n{}",
        own.join("\n")
    );
    let daemons = udp_sockets(daemon_pid(&d.dir).expect("PRODUCT: no daemon holds D's lock"));
    assert!(
        !daemons.is_empty(),
        "CANNOT MEASURE: lsof lists no UDP socket for the daemon either"
    );

    // ---- b, attached by hand, makes a room while a serves -------------------------------
    let b_pf = d.pass_file("b");
    d.ok(
        "PRODUCT:",
        &[
            "node",
            "attach",
            "b",
            "--passphrase-file",
            b_pf.to_str().unwrap(),
        ],
    );
    let room_pf = d.dir.join("bx.pass");
    std::fs::write(&room_pf, "b's room passphrase\n").expect("APPARATUS: harness file I/O");
    d.ok(
        "PRODUCT:",
        &[
            "--node",
            "b",
            "room",
            "create",
            "--name",
            "bx",
            "--passphrase-file",
            room_pf.to_str().unwrap(),
        ],
    );
    let bx = d
        .ok("PRODUCT:", &["--node", "b", "room", "list"])
        .lines()
        .find(|l| l.split_whitespace().nth(1) == Some("bx"))
        .and_then(|l| l.split_whitespace().next())
        .expect("PRODUCT: b's room list does not show bx")
        .to_owned();
    let b_link = d
        .ok("PRODUCT:", &["--node", "b", "room", "link", &bx])
        .lines()
        .next()
        .unwrap_or_default()
        .trim()
        .to_owned();

    // **One ip:port** (D-4): a's address and b's link name the daemon's one port, and only it.
    let (a_ports, b_ports) = (link_ports(&address), link_ports(&b_link));
    assert!(
        !a_ports.is_empty() && !b_ports.is_empty(),
        "CANNOT MEASURE: no port in a's address {address} or b's link {b_link}"
    );
    assert!(
        a_ports.iter().all(|p| b_ports.contains(p)) && b_ports.iter().all(|p| a_ports.contains(p)),
        "PRODUCT: nodes a and b of one daemon publish different ports: a {a_ports:?}, b {b_ports:?}"
    );

    // ---- r joins both, through the one port -------------------------------------------------
    let a_pass_file = r.dir.join("a-room.pass");
    std::fs::write(&a_pass_file, format!("{passphrase}\n")).expect("APPARATUS: harness file I/O");
    let r_pf = r.pass_file("r");
    r.ok(
        "PRODUCT:",
        &[
            "--node",
            "r",
            "connect",
            &address,
            "--listen",
            "127.0.0.1:0",
            "--passphrase-file",
            a_pass_file.to_str().unwrap(),
            "--identity-passphrase-file",
            r_pf.to_str().unwrap(),
        ],
    );
    r.ok(
        "PRODUCT:",
        &[
            "node",
            "attach",
            "r",
            "--passphrase-file",
            r_pf.to_str().unwrap(),
        ],
    );
    let b_room_pf = r.dir.join("bx.pass");
    std::fs::write(&b_room_pf, "b's room passphrase\n").expect("APPARATUS: harness file I/O");
    r.ok(
        "PRODUCT:",
        &[
            "--node",
            "r",
            "room",
            "join",
            &b_link,
            "--passphrase-file",
            b_room_pf.to_str().unwrap(),
        ],
    );
    for (root, node, pf, who, name) in [
        (&d, "a", &a_pf, &r_fp, "r"),
        (&d, "b", &b_pf, &r_fp, "r"),
        (&r, "r", &r_pf, &b_fp, "b"),
        (&r, "r", &r_pf, &a_fp, "a"),
    ] {
        root.ok(
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
                pf.to_str().unwrap(),
            ],
        );
    }

    // ---- b posts and r reads it, while a serves ------------------------------------------
    d.ok(
        "PRODUCT:",
        &[
            "--node",
            "b",
            "room",
            "post",
            &bx,
            "said by b while a serves",
        ],
    );
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        let (_, out, _) = r.run(&["--node", "r", "room", "read", &bx, "--json"]);
        if out.contains("said by b while a serves") {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "PRODUCT: r never read b's post through the daemon both share with a:\n{out}"
        );
        std::thread::sleep(Duration::from_millis(300));
    }
    assert!(
        serve.0.try_wait().ok().flatten().is_none(),
        "PRODUCT: vox serve ended while b posted: {}",
        d.said("serve")
    );

    // ---- r reaches a's service through a's address ----------------------------------------
    let name = format!("web.{a_fp}.{a_room}.vox");
    let (_forward, fwd_out) = r.spawn("forward", &["--node", "r", "forward", &name, "127.0.0.1:0"]);
    let bound = line_with(
        &fwd_out,
        "vox: forwarding ",
        Duration::from_secs(120),
        &format!("PRODUCT: r's forward never bound: {}", r.said("forward")),
    );
    let local = bound
        .trim_start_matches("vox: forwarding ")
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .to_owned();
    let mut conn = TcpStream::connect(&local).expect("PRODUCT: the forward's port takes nothing");
    echoes(&mut conn, "through a's daemon", "PRODUCT:");

    // ---- a's tunnel is a's: b lists none of it and cannot close it ---------------------------
    let deadline = Instant::now() + Duration::from_secs(30);
    let a_tunnel = loop {
        if let Some(t) = tunnels(&d, "a").into_iter().find(|(_, peer)| *peer == r_fp) {
            break t;
        }
        assert!(
            Instant::now() < deadline,
            "CANNOT MEASURE: a's status never listed r's tunnel"
        );
        std::thread::sleep(Duration::from_millis(200));
    };
    let b_sees = tunnels(&d, "b");
    assert!(
        b_sees.is_empty(),
        "PRODUCT: node b's status lists node a's tunnels: {b_sees:?}"
    );
    let (closed, out, err) = d.run(&[
        "--node",
        "b",
        "tunnel",
        "close",
        "--id",
        &a_tunnel.0.to_string(),
    ]);
    assert!(
        !closed,
        "PRODUCT: node b closed node a's tunnel {}: {out}{err}",
        a_tunnel.0
    );
    assert!(
        tunnels(&d, "a").contains(&a_tunnel),
        "PRODUCT: node b closed node a's tunnel {}: a lists it no more",
        a_tunnel.0
    );
    echoes(&mut conn, "still a's after b tried", "PRODUCT:");

    drop(conn);
    drop(serve);
}
