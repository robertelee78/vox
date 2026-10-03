//! PRD-001 R20 / ADR-017 decision 7 — **local names**: `ssh 22.nas.family.vox`, where `22` is
//! the name the node shared its service under, `nas` is the name *this* machine gave that node
//! when it trusted it and `family` is *this* machine's name for the room (V030-25:
//! `<service>.<node>.<room>.vox` is the only `.vox` name that resolves). Proved with the
//! shipped binary only: every member is a `vox daemon`, and everything they do is a `vox` verb
//! (`vox trust add/rename/remove`, `vox room create/invite/join/roster`, `vox service add`,
//! `vox up`, `vox forward`).
//!
//! The scene, from alice's side:
//!
//! - bob created room *family*; alice joined it, and **then** carol joined it through bob.
//!   bob and carol each serve "port 22" there — an echo that answers with its owner's name.
//! - alice trusts bob as `nas` and carol as `laptop`.
//! - carol also created room *work*, which alice joined; carol serves 22 there too.
//!
//! What must hold:
//!
//! 0. **A member who joins later is learned from the board** (V030-07, #239). carol joins
//!    `family` through bob after alice is already in, so alice's join told her nothing about
//!    carol: she learns that carol is a member only from the room's board, and `vox room
//!    roster` on alice shows it.
//! 1. `22.nas.family.vox` reaches bob and `22.laptop.family.vox` reaches carol — the member the
//!    name names, not the room's creator.
//! 2. `22.laptop.work.vox` reaches carol through the second room, under its own name.
//! 3. An unknown room, an unknown node, and an ambiguous node name are refused, each with
//!    a sentence saying which.
//! 4. A node that is no longer trusted has no name.
//!
//! 5. **A service added to a running daemon is offered without a restart** (V030-06, #238). bob and
//!    carol add theirs with `vox service add` while their daemons run; `vox service add` asks the
//!    daemon, and alice reaches each service through the name in (1) and (2) with no daemon ever
//!    restarted. (It used to open the profile itself, so the daemon had to be stopped first, and
//!    started again with every room's passphrase.)
//! 6. **`vox service list` shows it while the daemon runs** (V030-24): carol lists *work* with her
//!    daemon running, and the service just added is there; after her daemon stops, the one-shot
//!    `vox service list` still shows it. (`list` used to open the profile while `add` asked the
//!    daemon, so it was refused for a profile the daemon held.)
//!
//! **A red names its side.** A `vox` command that fails while setting the scene — an identity, a
//! trust, a daemon, a room, an invite, a join, bob holding carol as a member, the proxy — is the
//! product failing: PRODUCT (staging). Anything this proof claims — alice learning carol from
//! the board, the service offered, a name reaching its node, a refusal and its sentence — is
//! PRODUCT, quoting what vox said. The test's own files, ports, pipes and echo services are
//! APPARATUS.

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
        .expect("APPARATUS: run vox");
    if let Some(text) = stdin {
        let mut pipe = child.stdin.take().expect("APPARATUS: vox's stdin");
        pipe.write_all(text.as_bytes())
            .expect("APPARATUS: write to vox's stdin");
    }
    let out = child.wait_with_output().expect("APPARATUS: wait for vox");
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
        .and_then(|s| s.local_addr())
        .expect("APPARATUS: a free UDP port")
        .port()
}

fn member(tmp: &Path, name: &'static str) -> Member {
    let dir = tmp.join(name);
    std::fs::create_dir_all(dir.join("cfg")).expect("APPARATUS: a profile directory");
    let (ok, out, err) = vox(&dir, &["id", "--listen", "127.0.0.1:0"], None);
    assert!(ok, "PRODUCT (staging): vox id ({name}): {err}");
    let fp = out.trim().to_owned();
    assert_eq!(
        fp.len(),
        52,
        "PRODUCT (staging): {name}'s fingerprint: {out:?}"
    );
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
            "PRODUCT (staging): {} trusts {} as {as_name}: {out}{err}",
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
        std::fs::write(&pass_file, text).expect("APPARATUS: write the passphrase file");
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
                    "PRODUCT (staging): {}'s daemon never held {rooms:?} \
                     open; room list said {out:?}. It said:\n{}",
                    self.name,
                    p.transcript()
                );
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        self.daemon = Some(p);
    }

    /// The running daemon's PID, while it still runs; `None` once it has exited.
    fn pid(&mut self) -> Option<u32> {
        let p = self.daemon.as_mut()?;
        matches!(p.child.try_wait(), Ok(None)).then(|| p.child.id())
    }

    /// `vox room create --name <local>`, passphrase on stdin; the room's id as `vox room
    /// list` prints it.
    fn create(&self, local: &str, pass: &str) -> String {
        let (ok, out, err) = vox(
            &self.dir,
            &["room", "create", "--passphrase-file", "-", "--name", local],
            Some(&format!("{pass}\n")),
        );
        assert!(
            ok,
            "PRODUCT (staging): {} creates {local}: {out}{err}",
            self.name
        );
        let (ok, list, err) = vox(&self.dir, &["room", "list"], None);
        assert!(ok, "PRODUCT (staging): vox room list: {err}");
        list.lines()
            .find(|l| l.split_whitespace().nth(1) == Some(local))
            .and_then(|l| l.split_whitespace().next())
            .unwrap_or_else(|| panic!("PRODUCT (staging): {local} is not listed: {list}"))
            .to_owned()
    }

    fn invite(&self, room: &str) -> String {
        let (ok, link, err) = vox(&self.dir, &["room", "invite", room], None);
        assert!(ok, "PRODUCT (staging): vox room invite {room}: {err}");
        link.trim().to_owned()
    }

    fn join(&self, link: &str, local: &str, pass: &str) {
        let (ok, out, err) = vox(
            &self.dir,
            &[
                "room",
                "join",
                "--passphrase-file",
                "-",
                link,
                "--name",
                local,
            ],
            Some(&format!("{pass}\n")),
        );
        assert!(
            ok,
            "PRODUCT (staging): {} joins {local}: {out}{err}",
            self.name
        );
    }

    /// `vox service add <room> 22 <at>`, with this member's daemon running (V030-06): it asks the
    /// daemon, which offers the service at once. The room passphrase is passed as a person who
    /// scripted the one-shot form would have; the daemon already holds the room open.
    fn serve(&self, room: &str, pass: &str, at: SocketAddr) {
        // From a file, never argv (V210-72: a room passphrase on the command line is refused).
        let pass_file = self.dir.join("room.pass");
        std::fs::write(&pass_file, pass).expect("APPARATUS: write the room passphrase file");
        let (ok, out, err) = vox(
            &self.dir,
            &[
                "service",
                "add",
                room,
                "22",
                &at.to_string(),
                "--passphrase-file",
                pass_file.to_str().unwrap(),
                "--listen",
                "127.0.0.1:0",
            ],
            None,
        );
        assert!(
            ok,
            "PRODUCT: {} could not offer 22 in {room} with its daemon running — `vox service add` \
             did not ask the daemon: {out}{err}",
            self.name
        );
        assert!(
            out.contains("vox: offering \"22\""),
            "PRODUCT: {}'s `vox service add` did not say it is offering 22: {out}{err}",
            self.name
        );
    }

    /// `vox service list <room>`: whether it succeeded, and what it said. With the room
    /// passphrase from a file, as the one-shot form needs it once no daemon holds the room.
    fn list(&self, room: &str, pass: &str) -> (bool, String) {
        let pass_file = self.dir.join("room.pass");
        std::fs::write(&pass_file, pass).expect("APPARATUS: write the room passphrase file");
        let (ok, out, err) = vox(
            &self.dir,
            &[
                "service",
                "list",
                room,
                "--passphrase-file",
                pass_file.to_str().unwrap(),
                "--listen",
                "127.0.0.1:0",
            ],
            None,
        );
        (ok, format!("{out}{err}"))
    }

    /// `vox forward <name> 0`, the name naming the service (V030-25): whether it bound, and what
    /// it said.
    fn forward(&self, name: &str) -> (bool, String) {
        let mut p = VoxProc::spawn(
            &format!("{} forward {name}", self.name),
            &self.dir,
            &args(&["forward", name, "0"]),
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
    let l = std::net::TcpListener::bind("127.0.0.1:0").expect("APPARATUS: an echo listener");
    let at = l.local_addr().expect("APPARATUS: the echo's address");
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
    let mut s = TcpStream::connect(proxy).expect("PRODUCT: `vox up`'s proxy refused a connection");
    s.set_read_timeout(Some(
        vox_core::node::up::HOST_PATIENCE + Duration::from_secs(30),
    ))
    .expect("APPARATUS: set a read timeout");
    s.write_all(&[0x05, 0x01, 0x00])
        .expect("PRODUCT: `vox up`'s proxy closed on the SOCKS greeting");
    let mut hello = [0u8; 2];
    s.read_exact(&mut hello)
        .expect("PRODUCT: `vox up`'s proxy did not answer the SOCKS greeting");
    let mut req = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
    req.extend_from_slice(host.as_bytes());
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req)
        .expect("PRODUCT: `vox up`'s proxy closed on the CONNECT");
    let mut head = [0u8; 4];
    s.read_exact(&mut head)
        .unwrap_or_else(|e| panic!("PRODUCT: `vox up`'s proxy did not answer CONNECT {host}: {e}"));
    if head[1] != 0 {
        return Err(head[1]);
    }
    let skip = match head[3] {
        0x01 => 6,
        0x04 => 18,
        _ => {
            let mut l = [0u8; 1];
            s.read_exact(&mut l)
                .expect("PRODUCT: `vox up`'s proxy cut its CONNECT reply short");
            usize::from(l[0]) + 2
        }
    };
    let mut rest = vec![0u8; skip];
    s.read_exact(&mut rest)
        .expect("PRODUCT: `vox up`'s proxy cut its CONNECT reply short");
    Ok(s)
}

/// Who answers at `name` through the proxy: the owner's name from the echo.
fn who_answers(proxy: SocketAddr, name: &str) -> Result<String, u8> {
    let mut s = socks(proxy, name, 22)?;
    s.write_all(b"hello\n")
        .unwrap_or_else(|e| panic!("PRODUCT: {name}'s tunnel closed before a line was sent: {e}"));
    // To the end of the line: one `read` may return only part of the answer, and a
    // partial `car` would read as a wrong host.
    let mut line = String::new();
    std::io::BufRead::read_line(&mut std::io::BufReader::new(s), &mut line)
        .unwrap_or_else(|e| panic!("PRODUCT: no answer came back through {name}: {e}"));
    Ok(line.split(':').next().unwrap_or("").to_owned())
}

#[test]
#[ignore = "an anchor, three vox daemons and real child processes; CI runs it in release"]
fn a_local_name_reaches_the_node_it_names() {
    watchdog::arm();
    let tmp = tempfile::tempdir().expect("APPARATUS: a temporary directory");
    let (nas_echo, laptop_echo, laptop_work_echo) =
        (echo("bob"), echo("carol"), echo("carol-work"));

    let anchor_dir = tmp.path().join("anchor");
    std::fs::create_dir_all(anchor_dir.join("cfg")).expect("APPARATUS: the anchor's directory");
    let mut anchor = VoxProc::spawn(
        "anchor",
        &anchor_dir,
        &args(&["node", "--listen", "127.0.0.1:0"]),
    );
    let spec = anchor
        .expect_line("PRODUCT (staging): an --anchor spec", |l| {
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

    // The rooms: bob makes family, alice joins it, and only then carol; carol makes work.
    let (family_pass, work_pass) = ("family passphrase", "work passphrase");
    bob.start(&spec, &[], &[]);
    carol.start(&spec, &[], &[]);
    let family = bob.create("family", family_pass);
    let work = carol.create("work", work_pass);
    // alice joins family first, so her join cannot tell her about carol, who is not in it yet.
    alice.start(&spec, &[], &[]);
    alice.join(&bob.invite(&family), "family", family_pass);
    {
        let (_, roster, _) = vox(&alice.dir, &["room", "roster", &family], None);
        assert!(
            !roster.lines().any(|l| l.trim() == carol.fp),
            "PRODUCT (staging): carol is in alice's roster before she has \
             joined family: {roster:?}"
        );
    }
    carol.join(&bob.invite(&family), "family", family_pass);

    // (5) The services, added while the daemons run: `vox service add` asks each daemon, and no
    // daemon is restarted from here to the end. Each daemon's PID is checked at the end.
    let pids = (bob.pid(), carol.pid());
    assert!(
        pids.0.is_some() && pids.1.is_some(),
        "PRODUCT (staging): bob's and carol's daemons must be running before \
         their services are added: {pids:?}"
    );
    bob.serve(&family, family_pass, nas_echo);
    carol.serve(&family, family_pass, laptop_echo);
    carol.serve(&work, work_pass, laptop_work_echo);
    // (6) Listed while the daemon runs: `vox service list` asks it.
    let (ok, listed) = carol.list(&work, work_pass);
    let offered = format!("22  →  {laptop_work_echo}");
    assert!(
        ok && listed.contains(&offered),
        "PRODUCT: carol's `vox service list` with her daemon running does not show the service \
         she just added ({offered}): {listed}"
    );

    // alice joins work too.
    alice.join(&carol.invite(&work), "work", work_pass);

    // **(0) alice learns carol from the board.** carol joined through bob after alice was in,
    // so nothing but the room's board can have told alice. First the staging: bob, who let carol
    // in, holds her as a member; otherwise there is nothing on the board to learn. Then alice's
    // roster, bounded and timed, so a regression in how fast membership travels shows as a number.
    {
        let (_, roster, _) = vox(&bob.dir, &["room", "roster", &family], None);
        assert!(
            roster.lines().any(|l| l.trim() == carol.fp),
            "PRODUCT (staging): bob, who let carol into family, does not \
             hold her as a member; his roster: {roster:?}"
        );
        let started = Instant::now();
        loop {
            let (_, roster, _) = vox(&alice.dir, &["room", "roster", &family], None);
            if roster.lines().any(|l| l.trim() == carol.fp) {
                break;
            }
            assert!(
                started.elapsed() < SETUP,
                "PRODUCT: alice never learned from the board that carol joined family through \
                 bob ({} s); alice's roster: {roster:?}\nalice's daemon said:\n{}",
                SETUP.as_secs(),
                alice
                    .daemon
                    .as_mut()
                    .map(|d| d.transcript())
                    .unwrap_or_default()
            );
            std::thread::sleep(Duration::from_millis(200));
        }
        eprintln!(
            "alice learned from the board that carol is in family after {} ms",
            started.elapsed().as_millis()
        );
    }

    // `vox up`, no room: the proxy inside alice's daemon, across every room it holds.
    let mut up = VoxProc::spawn(
        "alice up",
        &alice.dir,
        &args(&["up", "--bind", "127.0.0.1:0"]),
    );
    let first = up.expect_line("PRODUCT (staging): vox up's address", |l| {
        l.starts_with("vox up on ")
    });
    let proxy: SocketAddr = first
        .split_whitespace()
        .nth(3)
        .and_then(|a| a.parse().ok())
        .unwrap_or_else(|| panic!("PRODUCT (staging): vox up said {first:?}"));

    // (1) and (2): each name reaches the node it names.
    let reached: Vec<(&str, Result<String, u8>)> = [
        "22.nas.family.vox",
        "22.laptop.family.vox",
        "22.laptop.work.vox",
        "22.NAS.Family.vox",
    ]
    .into_iter()
    .map(|n| (n, who_answers(proxy, n)))
    .collect();
    // (3): refusals, with reasons, from `vox forward`.
    let unknown_room = alice.forward("22.nas.nowhere.vox");
    let unknown_node = alice.forward("22.ghost.family.vox");
    let not_there = alice.forward("22.nas.work.vox");
    let named = alice.forward("22.laptop.family.vox");
    // Two trusted nodes called `nas` in family: ambiguous.
    let rename = vox(&alice.dir, &["trust", "rename", &carol.fp, "nas"], None);
    let ambiguous = alice.forward("22.nas.family.vox");
    let ambiguous_socks = who_answers(proxy, "22.nas.family.vox");
    // (4): untrusting carol takes her name away.
    let untrust = vox(&alice.dir, &["trust", "remove", &carol.fp], None);
    let untrusted = alice.forward("22.nas.family.vox");
    let now_bob = who_answers(proxy, "22.nas.family.vox");
    let untrusted_laptop = who_answers(proxy, "22.laptop.work.vox");

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
            .expect("APPARATUS: a name this proof did not try")
    };
    assert_eq!(
        answered("22.nas.family.vox"),
        Ok("bob".into()),
        "PRODUCT: 22.nas.family.vox did not reach bob's service, added to his running daemon"
    );
    assert_eq!(
        answered("22.laptop.family.vox"),
        Ok("carol".into()),
        "PRODUCT: 22.laptop.family.vox did not reach carol's service, added to her running daemon — laptop is carol, not the room's creator"
    );
    assert_eq!(
        answered("22.laptop.work.vox"),
        Ok("carol-work".into()),
        "PRODUCT: 22.laptop.work.vox did not reach carol's work service, added to her running daemon — the same node through a second room, under that room's name"
    );
    assert_eq!(
        answered("22.NAS.Family.vox"),
        Ok("bob".into()),
        "PRODUCT: names are case-insensitive"
    );
    assert!(
        named.0,
        "PRODUCT: vox forward takes a name too: {}",
        named.1
    );
    assert!(
        !unknown_room.0
            && unknown_room
                .1
                .contains("no room on this machine is called `nowhere`"),
        "PRODUCT: an unknown room is refused, saying so: {unknown_room:?}"
    );
    assert!(
        !unknown_node.0
            && unknown_node
                .1
                .contains("no node you trust is called `ghost`"),
        "PRODUCT: an unknown node is refused, saying so: {unknown_node:?}"
    );
    assert!(
        !not_there.0 && not_there.1.contains("not a member of `work`"),
        "PRODUCT: a node not in the room is refused, saying so: {not_there:?}"
    );
    assert!(rename.0, "PRODUCT: the rename must succeed: {rename:?}");
    assert!(
        !ambiguous.0 && ambiguous.1.contains("names 2 nodes you trust in `family`"),
        "PRODUCT: an ambiguous name is refused, saying so: {ambiguous:?}"
    );
    assert_eq!(
        ambiguous_socks,
        Err(2),
        "PRODUCT: the proxy refuses an ambiguous name"
    );
    assert!(untrust.0, "PRODUCT: the untrust must succeed: {untrust:?}");
    assert!(
        untrusted.0,
        "PRODUCT: with carol untrusted, `nas` is bob's again: {untrusted:?}"
    );
    assert_eq!(
        now_bob,
        Ok("bob".into()),
        "PRODUCT: with carol untrusted, 22.nas.family.vox is bob's again"
    );
    assert_eq!(
        untrusted_laptop,
        Err(2),
        "PRODUCT: carol is no longer trusted, so no name reaches her"
    );
    // (5) No daemon was restarted: bob's and carol's are the processes that ran when their
    // services were added, and still run.
    assert_eq!(
        (bob.pid(), carol.pid()),
        pids,
        "PRODUCT: a daemon was restarted or exited after its service was added"
    );
    // (6) The daemon stopped, the one-shot `vox service list` still shows carol's service: it
    // was kept, not only offered for the daemon's run.
    drop(carol.daemon.take());
    let (ok, listed) = carol.list(&work, work_pass);
    assert!(
        ok && listed.contains(&offered),
        "PRODUCT: after carol's daemon stopped, `vox service list` does not show the service she \
         added while it ran ({offered}): {listed}"
    );
    eprintln!(
        "[proof] 3 services added to 2 running daemons, each reached by name, none restarted; \
         listed with the daemon running and after it stopped"
    );
    drop((up, alice, bob, carol, anchor));
}
