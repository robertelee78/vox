//! PRD-001 R20 / ADR-017 decision 7 — **local names**: `ssh nas.family.vox`, where `nas`
//! is the name *this* machine gave that node when it trusted it and `family` is *this*
//! machine's name for the room. Proved with the shipped binary only: every member is a
//! `vox daemon`, and everything they do is a `vox` verb (`vox trust add/rename/remove`,
//! `vox room create/invite/join/roster`, `vox service add`, `vox up`, `vox forward`).
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
//!
//! `vox service add` opens the profile itself, so it cannot run beside the daemon that holds
//! it. bob and carol therefore offer their services the way a person would have to: stop the
//! daemon, `vox service add`, start the daemon again with the room passphrases. Each comes
//! back on the UDP port it had.

#![cfg(unix)]

#[path = "support/world.rs"]
mod world;

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::io::{Read as _, Write as _};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use world::{args, VoxProc, IDENTITY, VOX};

const SETUP: Duration = Duration::from_secs(90);

/// A one-shot `vox` verb in `dir`'s profile, `stdin` piped in when given.
fn vox(dir: &Path, argv: &[&str], stdin: Option<&str>) -> (bool, String, String) {
    let mut child = Command::new(VOX)
        .args(argv)
        .env("VOX_DATA_DIR", dir)
        .env("VOX_CONFIG_DIR", dir.join("cfg"))
        .env("VOX_IDENTITY_PASSPHRASE", IDENTITY)
        .env_remove("VOX_ROOM")
        .env_remove("VOX_ANCHORS")
        .env_remove("VOX_ROOM_PASSPHRASE")
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("run vox");
    if let Some(text) = stdin {
        let mut pipe = child.stdin.take().expect("stdin");
        pipe.write_all(text.as_bytes()).unwrap();
    }
    let out = child.wait_with_output().expect("vox finished");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// One member: a profile directory, a fingerprint, the UDP port its daemon keeps, and the
/// daemon while it runs.
struct Member {
    name: &'static str,
    dir: PathBuf,
    fp: String,
    listen: String,
    daemon: Option<VoxProc>,
}

fn free_udp_port() -> u16 {
    std::net::UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn member(tmp: &Path, name: &'static str) -> Member {
    let dir = tmp.join(name);
    std::fs::create_dir_all(dir.join("cfg")).unwrap();
    let (ok, out, err) = vox(&dir, &["id", "--listen", "127.0.0.1:0"], None);
    assert!(ok, "vox id ({name}): {err}");
    let fp = out.trim().to_owned();
    assert_eq!(fp.len(), 52, "{name}'s fingerprint: {out:?}");
    Member {
        name,
        dir,
        fp,
        listen: format!("127.0.0.1:{}", free_udp_port()),
        daemon: None,
    }
}

impl Member {
    fn trust(&self, peer: &Member, as_name: &str) {
        let (ok, out, err) = vox(
            &self.dir,
            &[
                "trust",
                "add",
                &peer.fp,
                "--name",
                as_name,
                "--listen",
                "127.0.0.1:0",
            ],
            None,
        );
        assert!(
            ok,
            "{} trusts {} as {as_name}: {out}{err}",
            self.name, peer.name
        );
    }

    /// `vox daemon`, its passphrases from a file: the identity's, then one line per room.
    /// Returns once the daemon answers `vox room list` and holds every room in `rooms` open.
    fn start(&mut self, anchor: &str, room_passes: &[&str], rooms: &[&str]) {
        let pass_file = self.dir.join("passphrases");
        let mut text = format!("{IDENTITY}\n");
        for p in room_passes {
            text.push_str(p);
            text.push('\n');
        }
        std::fs::write(&pass_file, text).unwrap();
        let mut p = VoxProc::spawn(
            self.name,
            &self.dir,
            &args(&[
                "daemon",
                "--listen",
                &self.listen,
                "--anchor",
                anchor,
                "--passphrase-file",
                pass_file.to_str().unwrap(),
            ]),
        );
        let deadline = Instant::now() + SETUP;
        loop {
            let (ok, out, _) = vox(&self.dir, &["room", "list"], None);
            if ok
                && rooms.iter().all(|r| {
                    out.lines()
                        .any(|l| l.starts_with(r) && !l.contains("[closed]"))
                })
            {
                break;
            }
            if Instant::now() >= deadline {
                panic!(
                    "{}'s daemon never held {rooms:?} open; room list said {out:?}. It said:\n{}",
                    self.name,
                    p.transcript()
                );
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        self.daemon = Some(p);
    }

    /// Stop the daemon by its PID with SIGTERM and wait until it has exited, so the profile
    /// is free for a verb that opens it itself.
    fn stop(&mut self) {
        let Some(mut p) = self.daemon.take() else {
            return;
        };
        let ok = Command::new("kill")
            .args(["-TERM", &p.child.id().to_string()])
            .status()
            .is_ok_and(|s| s.success());
        assert!(ok, "kill -TERM {}", self.name);
        let deadline = Instant::now() + Duration::from_secs(20);
        while Instant::now() < deadline {
            if matches!(p.child.try_wait(), Ok(Some(_))) {
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        panic!("{}'s daemon did not exit on SIGTERM", self.name);
        // Drop would kill it by PID.
    }

    /// `vox room create --name <local>`, passphrase on stdin; the room's id as `vox room
    /// list` prints it.
    fn create(&self, local: &str, pass: &str) -> String {
        let (ok, out, err) = vox(
            &self.dir,
            &["room", "create", "--name", local],
            Some(&format!("{pass}\n")),
        );
        assert!(ok, "{} creates {local}: {out}{err}", self.name);
        let (ok, list, err) = vox(&self.dir, &["room", "list"], None);
        assert!(ok, "vox room list: {err}");
        list.lines()
            .find(|l| l.split_whitespace().nth(1) == Some(local))
            .and_then(|l| l.split_whitespace().next())
            .unwrap_or_else(|| panic!("{local} is not listed: {list}"))
            .to_owned()
    }

    fn invite(&self, room: &str) -> String {
        let (ok, link, err) = vox(&self.dir, &["room", "invite", room], None);
        assert!(ok, "vox room invite {room}: {err}");
        link.trim().to_owned()
    }

    fn join(&self, link: &str, local: &str, pass: &str) {
        let (ok, out, err) = vox(
            &self.dir,
            &["room", "join", link, "--name", local],
            Some(&format!("{pass}\n")),
        );
        assert!(ok, "{} joins {local}: {out}{err}", self.name);
    }

    /// `vox service add <room> 22 <at>` — the profile must not be held by a daemon.
    fn serve(&self, room: &str, pass: &str, at: SocketAddr) {
        let (ok, out, err) = vox(
            &self.dir,
            &[
                "service",
                "add",
                room,
                "22",
                &at.to_string(),
                "--passphrase",
                pass,
                "--listen",
                "127.0.0.1:0",
            ],
            None,
        );
        assert!(ok, "{} offers 22 in {room}: {out}{err}", self.name);
    }

    /// `vox forward <name> 22 0`: whether it bound, and what it said.
    fn forward(&self, name: &str) -> (bool, String) {
        let mut p = VoxProc::spawn(
            &format!("{} forward {name}", self.name),
            &self.dir,
            &args(&["forward", name, "22", "0"]),
        );
        let bound = p
            .line_within(Duration::from_secs(20), |l| l.contains("forwarding"))
            .is_some();
        // Whatever it printed as it went (a refusal ends the process, which ends the wait).
        std::thread::sleep(Duration::from_millis(100));
        let said = p.transcript();
        (bound, said)
    }
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
    // To the end of the line: one `read` may return only part of the answer, and a
    // partial `car` would read as a wrong host.
    let mut line = String::new();
    std::io::BufRead::read_line(&mut std::io::BufReader::new(s), &mut line).unwrap();
    Ok(line.split(':').next().unwrap_or("").to_owned())
}

#[test]
#[ignore = "an anchor, three vox daemons and real child processes; CI runs it in release"]
fn a_local_name_reaches_the_node_it_names() {
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();
    let (nas_echo, laptop_echo, laptop_work_echo) =
        (echo("bob"), echo("carol"), echo("carol-work"));

    let anchor_dir = tmp.path().join("anchor");
    std::fs::create_dir_all(anchor_dir.join("cfg")).unwrap();
    let mut anchor = VoxProc::spawn(
        "anchor",
        &anchor_dir,
        &args(&["node", "--listen", "127.0.0.1:0"]),
    );
    let spec = anchor
        .expect_line("an --anchor spec", |l| {
            l.trim_start().contains("@/ip4/127.0.0.1/udp/")
        })
        .trim()
        .to_owned();

    let mut alice = member(tmp.path(), "alice");
    let mut bob = member(tmp.path(), "bob");
    let mut carol = member(tmp.path(), "carol");
    alice.trust(&bob, "nas");
    alice.trust(&carol, "laptop");
    bob.trust(&alice, "alice");
    carol.trust(&alice, "alice");

    // The rooms: bob makes family and carol joins it; carol makes work.
    let (family_pass, work_pass) = ("family passphrase", "work passphrase");
    bob.start(&spec, &[], &[]);
    carol.start(&spec, &[], &[]);
    let family = bob.create("family", family_pass);
    let work = carol.create("work", work_pass);
    carol.join(&bob.invite(&family), "family", family_pass);

    // The services, offered with the daemons down, then the daemons back on their ports.
    bob.stop();
    carol.stop();
    bob.serve(&family, family_pass, nas_echo);
    carol.serve(&family, family_pass, laptop_echo);
    carol.serve(&work, work_pass, laptop_work_echo);
    bob.start(&spec, &[family_pass], &[&family]);
    carol.start(&spec, &[family_pass, work_pass], &[&family, &work]);

    // alice joins both.
    alice.start(&spec, &[], &[]);
    alice.join(&bob.invite(&family), "family", family_pass);
    alice.join(&carol.invite(&work), "work", work_pass);

    // **Precondition: alice knows carol is in `family`.** carol joined through bob, so alice
    // learns her as a member from the board, not from a join of her own. On v0.2.9 that takes a
    // sync interval (measured on the v0.3.0 integration: about 26 s; the naming branch's base was
    // faster), and this proof is about names, not about how fast membership travels. Waited for,
    // bounded, and timed — through `vox room roster` — so a regression in that latency still
    // shows here as a number.
    {
        let started = Instant::now();
        loop {
            let (_, roster, _) = vox(&alice.dir, &["room", "roster", &family], None);
            if roster.lines().any(|l| l.trim() == carol.fp) {
                break;
            }
            assert!(
                started.elapsed() < SETUP,
                "alice never learned that carol is in family; her roster: {roster:?}"
            );
            std::thread::sleep(Duration::from_millis(200));
        }
        eprintln!(
            "alice learned carol is in family after {} ms",
            started.elapsed().as_millis()
        );
    }

    // `vox up`, no room: the proxy inside alice's daemon, across every room it holds.
    let mut up = VoxProc::spawn(
        "alice up",
        &alice.dir,
        &args(&["up", "--bind", "127.0.0.1:0"]),
    );
    let first = up.expect_line("vox up's address", |l| l.starts_with("vox up on "));
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
    let unknown_room = alice.forward("nas.nowhere.vox");
    let unknown_node = alice.forward("ghost.family.vox");
    let not_there = alice.forward("nas.work.vox");
    let named = alice.forward("laptop.family.vox");
    // Two trusted nodes called `nas` in family: ambiguous.
    let rename = vox(&alice.dir, &["trust", "rename", &carol.fp, "nas"], None);
    let ambiguous = alice.forward("nas.family.vox");
    let ambiguous_socks = who_answers(proxy, "nas.family.vox");
    // (4): untrusting carol takes her name away.
    let untrust = vox(&alice.dir, &["trust", "remove", &carol.fp], None);
    let untrusted = alice.forward("nas.family.vox");
    let now_bob = who_answers(proxy, "nas.family.vox");
    let untrusted_laptop = who_answers(proxy, "laptop.work.vox");

    eprintln!(
        "reached: {reached:?}\nunknown room: {unknown_room:?}\nunknown node: {unknown_node:?}\n\
         nas in work: {not_there:?}\nforward laptop.family: {:?}\nrename: {rename:?}\n\
         ambiguous: {ambiguous:?} / socks {ambiguous_socks:?}\nuntrust: {untrust:?}\n\
         after untrusting carol: forward nas.family {untrusted:?}, socks nas.family \
         {now_bob:?}, laptop.work {untrusted_laptop:?}",
        named.0,
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
    assert!(rename.0, "the rename must succeed: {rename:?}");
    assert!(
        !ambiguous.0 && ambiguous.1.contains("names 2 nodes you trust in `family`"),
        "{ambiguous:?}"
    );
    assert_eq!(
        ambiguous_socks,
        Err(2),
        "the proxy refuses an ambiguous name"
    );
    assert!(untrust.0, "the untrust must succeed: {untrust:?}");
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
    drop((up, alice, bob, carol, anchor));
}
