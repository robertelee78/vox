//! V210-80 (#271) — **two members who dial each other through one relay at the same moment both
//! get through**, through the shipped `vox` binary.
//!
//! A node's mux kept one circuit per peer, and attaching a circuit unmapped the one attached before
//! it to the same peer. Two live circuits to one peer are ordinary: a member dialling a peer through
//! a relay while that peer dials it back through the same relay. Each end attaches one circuit for
//! the other's dial (on the relay's `Incoming`) and one for its own (on the relay's `Opened`), and
//! the second attach took the first one's address out of the table: the packets for it went to the
//! real socket and were lost, and a dial over it waited out its whole 10 s direct-attempt timeout
//! (CI's R42 sample of 10558 ms, "circuit via …: direct attempt timed out", run 36601388611). Each
//! circuit now stays attached until its own port drops.
//!
//! **Staging, forced on every run with no switch in the product** (the freeze of
//! `simultaneous_session_race_proof`). bob listens on `127.0.0.1` and carol on `[::1]`, so the
//! anchor's circuit is their only path to each other. Both daemons are restarted, so neither holds
//! a connection to the other, and that is **checked**: each one's `vox status --json` names no
//! circuit to the other. The anchor is then frozen (SIGSTOP), and bob and carol trust each other at
//! once, which makes each dial the other. Both circuit requests wait in the frozen anchor; on its
//! release they are served together, and the circuits cross.
//!
//! **Asserted.**
//! 1. The escalation: after the release, each end asked the relay for a circuit to the other
//!    (`reach.circuits` grew on both), or the run is `CANNOT MEASURE`: without two crossing dials
//!    there is nothing to measure.
//! 2. Each reads a post of the other's within [`BOUND`] of the release.
//! 3. Watched for [`WATCH`] after the release, past the 10 s a lost dial waits: neither daemon says
//!    a dial to the other could not reach it because an attempt timed out. The product says every
//!    failed dial and each rung's reason (`vox: could not reach <peer> — …`).
//!
//! **Mutation that must turn it red:** in `MuxSocket::attach`, remove the earlier circuit to the
//! same peer when a new one is attached (the code before V210-80).

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/world.rs"]
mod world;

#[path = "support/relay.rs"]
mod relay;

use std::io::{Read, Write};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use relay::{Anchor, Split};

const VOX: &str = env!("CARGO_BIN_EXE_vox");
const IDPASS: &str = "an identity passphrase";
const ROOMPASS: &str = "room passphrase";
/// How long the relay is held frozen while both members dial.
const FREEZE: Duration = Duration::from_secs(4);
/// Each reads the other within this of the release.
const BOUND: Duration = Duration::from_secs(8);
/// How long after the release the daemons are listened to: past the 10 s direct-attempt timeout a
/// lost dial waits out, with margin.
const WATCH: Duration = Duration::from_secs(16);

fn vox(dir: &std::path::Path, args: &[&str], stdin: Option<&str>) -> (bool, String, String) {
    let mut child = Command::new(VOX)
        .args(args)
        .env("VOX_DATA_DIR", dir)
        .env("VOX_CONFIG_DIR", dir.join("cfg"))
        .env("VOX_IDENTITY_PASSPHRASE", IDPASS)
        .env_remove("VOX_ROOM")
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn vox");
    if let Some(text) = stdin {
        let mut pipe = child.stdin.take().expect("stdin");
        pipe.write_all(text.as_bytes()).expect("write");
    }
    let out = child.wait_with_output().expect("wait");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn reads(dir: &std::path::Path, room: &str, text: &str) -> bool {
    vox(dir, &["room", "read", room], None).1.contains(text)
}

fn until(what: &str, secs: u64, ok: impl Fn() -> bool) -> bool {
    let deadline = Instant::now() + Duration::from_secs(secs);
    while Instant::now() < deadline {
        if ok() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    eprintln!("[proof] {what}: not within {secs} s");
    false
}

/// A daemon, killed by its own PID however the test ends, its output kept.
struct Daemon(Child, Arc<Mutex<String>>);

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

impl Daemon {
    fn said(&self) -> String {
        self.1.lock().unwrap().clone()
    }
}

fn daemon(dir: &std::path::Path, listen: &str, anchor: &str) -> Daemon {
    let mut child = Command::new(VOX)
        .args(["daemon", "--listen", listen, "--anchor", anchor])
        .env("VOX_DATA_DIR", dir)
        .env("VOX_CONFIG_DIR", dir.join("cfg"))
        .env_remove("VOX_ROOM")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn a daemon");
    let mut pipe = child.stdin.take().expect("stdin");
    pipe.write_all(format!("{IDPASS}\n").as_bytes()).unwrap();
    drop(pipe);
    let said = Arc::new(Mutex::new(String::new()));
    for stream in [
        child
            .stdout
            .take()
            .map(|s| Box::new(s) as Box<dyn Read + Send>),
        child
            .stderr
            .take()
            .map(|s| Box::new(s) as Box<dyn Read + Send>),
    ]
    .into_iter()
    .flatten()
    {
        let sink = Arc::clone(&said);
        let mut stream = stream;
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            loop {
                match stream.read(&mut buf) {
                    Ok(0) | Err(_) => return,
                    Ok(n) => sink
                        .lock()
                        .unwrap()
                        .push_str(&String::from_utf8_lossy(&buf[..n])),
                }
            }
        });
    }
    let d = Daemon(child, said);
    let deadline = Instant::now() + Duration::from_secs(90);
    while !d.1.lock().unwrap().contains("control socket") {
        assert!(
            Instant::now() < deadline,
            "a daemon never served its socket:\n{}",
            d.1.lock().unwrap()
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    d
}

fn signal(pid: u32, sig: &str) {
    let ok = Command::new("kill")
        .args([sig, &pid.to_string()])
        .status()
        .is_ok_and(|s| s.success());
    assert!(ok, "kill {sig} {pid}");
}

/// Circuits `dir`'s node has asked a relay for to `peer` (`vox status --json` `reach.circuits`).
fn circuits_to(dir: &std::path::Path, peer: &str) -> u64 {
    let (ok, out, err) = vox(dir, &["status", "--json"], None);
    assert!(ok, "CANNOT MEASURE: vox status --json: {err}");
    let v: serde_json::Value = serde_json::from_str(out.trim())
        .unwrap_or_else(|e| panic!("CANNOT MEASURE: vox status --json is not JSON ({e}): {out}"));
    v["reach"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|r| r["peer"].as_str() == Some(peer))
        .and_then(|r| r["circuits"].as_u64())
        .unwrap_or(0)
}

/// What `d` said about `peer` from its `mark`th line on: every line naming the peer's short id.
fn about(d: &Daemon, mark: usize, peer: &str) -> Vec<String> {
    d.said()
        .lines()
        .skip(mark)
        .filter(|l| l.contains(&peer[..26]))
        .map(str::to_owned)
        .collect()
}

#[test]
#[ignore = "three daemons and a relay anchor with production Argon2id; CI runs it in release"]
fn two_members_dialling_each_other_through_one_relay_both_get_through() {
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();
    let dirs: Vec<std::path::PathBuf> = ["alice", "bob", "carol"]
        .iter()
        .map(|n| tmp.path().join(n))
        .collect();
    for d in &dirs {
        std::fs::create_dir_all(d.join("cfg")).unwrap();
    }
    let (alice_dir, bob_dir, carol_dir) = (&dirs[0], &dirs[1], &dirs[2]);
    let anchor = Anchor::start(&tmp.path().join("anchor"));
    let mut fps = Vec::new();
    for d in &dirs {
        let (ok, out, err) = vox(d, &["id"], None);
        assert!(ok, "vox id: {err}");
        fps.push(out.trim().to_owned());
    }
    // alice and bob on IPv4, carol on IPv6: bob and carol reach each other only through the
    // anchor's relay.
    let carol_spec = Split::Families.guest_spec(&anchor).to_owned();
    let _alice = daemon(alice_dir, "127.0.0.1:0", &anchor.v4_spec);
    let bob = daemon(bob_dir, "127.0.0.1:0", &anchor.v4_spec);
    let carol = daemon(carol_dir, Split::Families.guest_listen(), &carol_spec);

    // alice's room; alice and each joiner trust each other. bob and carol do NOT, yet.
    for (i, name) in [(1usize, "bob"), (2, "carol")] {
        let (ok, _, err) = vox(alice_dir, &["trust", "add", &fps[i], "--name", name], None);
        assert!(ok, "alice trusts {name}: {err}");
        let (ok, _, err) = vox(
            &dirs[i],
            &["trust", "add", &fps[0], "--name", "alice"],
            None,
        );
        assert!(ok, "{name} trusts alice: {err}");
    }
    let (ok, _, err) = vox(
        alice_dir,
        &["room", "create", "--name", "crossed"],
        Some(&format!("{ROOMPASS}\n")),
    );
    assert!(ok, "room create: {err}");
    let listed = vox(alice_dir, &["room", "list"], None).1;
    let room = listed
        .split_whitespace()
        .find(|w| w.len() >= 12 && w.chars().all(|c| c.is_ascii_alphanumeric()))
        .expect("a room id in `room list`")
        .to_owned();
    let (ok, link, err) = vox(alice_dir, &["room", "invite", &room], None);
    assert!(ok, "invite: {err}");
    for d in [bob_dir, carol_dir] {
        let (ok, _, err) = vox(
            d,
            &["room", "join", link.trim(), "--name", "crossed"],
            Some(&format!("{ROOMPASS}\n")),
        );
        assert!(ok, "CANNOT MEASURE: a join failed: {err}");
    }

    // Fresh processes, so neither holds a connection to the other from the joins.
    drop(bob);
    drop(carol);
    let bob = daemon(bob_dir, "127.0.0.1:0", &anchor.v4_spec);
    let carol = daemon(carol_dir, Split::Families.guest_listen(), &carol_spec);
    assert!(
        until("bob and carol hold their room", 60, || {
            vox(bob_dir, &["room", "list"], None).1.contains(&room)
                && vox(carol_dir, &["room", "list"], None).1.contains(&room)
        }),
        "CANNOT MEASURE: a restarted daemon never listed the room"
    );

    // ---- precondition: neither has dialled the other ----
    let (bob_fp, carol_fp) = (fps[1].as_str(), fps[2].as_str());
    let before = (
        circuits_to(bob_dir, carol_fp),
        circuits_to(carol_dir, bob_fp),
    );
    assert!(
        before == (0, 0),
        "CANNOT MEASURE: bob and carol already asked for circuits to each other before the \
         freeze: {before:?}"
    );
    let marks = (bob.said().lines().count(), carol.said().lines().count());

    // ---- the crossing: both dial while the relay between them is frozen ----
    let anchor_pid = anchor.proc.child.id();
    signal(anchor_pid, "-STOP");
    let frozen = Instant::now();
    let (released, b, c) = std::thread::scope(|s| {
        let b = s.spawn(|| {
            vox(
                bob_dir,
                &["trust", "add", carol_fp, "--name", "carol"],
                None,
            )
        });
        let c = s.spawn(|| vox(carol_dir, &["trust", "add", bob_fp, "--name", "bob"], None));
        // Released on its own clock: a trust may wait for its dial, which waits for the anchor.
        std::thread::sleep(FREEZE.saturating_sub(frozen.elapsed()));
        signal(anchor_pid, "-CONT");
        let released = Instant::now();
        (released, b.join().unwrap(), c.join().unwrap())
    });
    assert!(b.0, "bob trusts carol: {}", b.2);
    assert!(c.0, "carol trusts bob: {}", c.2);

    // ---- each reads the other ----
    let (mut bob_reads_carol, mut carol_reads_bob) = (None, None);
    let mut n = 0;
    while (bob_reads_carol.is_none() || carol_reads_bob.is_none()) && released.elapsed() < WATCH {
        let (ok, _, _) = vox(
            bob_dir,
            &["room", "post", &room, &format!("BOB-PROBE-{n:02}")],
            None,
        );
        assert!(ok);
        let (ok, _, _) = vox(
            carol_dir,
            &["room", "post", &room, &format!("CAROL-PROBE-{n:02}")],
            None,
        );
        assert!(ok);
        std::thread::sleep(Duration::from_millis(500));
        if carol_reads_bob.is_none() && reads(carol_dir, &room, "BOB-PROBE-") {
            carol_reads_bob = Some(released.elapsed());
        }
        if bob_reads_carol.is_none() && reads(bob_dir, &room, "CAROL-PROBE-") {
            bob_reads_carol = Some(released.elapsed());
        }
        n += 1;
    }
    // Listened to past the time a lost dial takes to fail.
    std::thread::sleep(WATCH.saturating_sub(released.elapsed()));
    let after = (
        circuits_to(bob_dir, carol_fp),
        circuits_to(carol_dir, bob_fp),
    );
    let (bob_said, carol_said) = (
        about(&bob, marks.0, carol_fp),
        about(&carol, marks.1, bob_fp),
    );
    eprintln!(
        "[proof] relay frozen {:?}; circuits asked bob->carol {} carol->bob {}; bob reads carol \
         at {bob_reads_carol:?}, carol reads bob at {carol_reads_bob:?} after the release",
        released - frozen,
        after.0,
        after.1
    );
    for l in &bob_said {
        eprintln!("[proof] bob said: {l}");
    }
    for l in &carol_said {
        eprintln!("[proof] carol said: {l}");
    }

    // 1. The escalation: both dials went through the relay.
    assert!(
        after.0 > before.0 && after.1 > before.1,
        "CANNOT MEASURE: the dials did not cross: bob asked for {} circuit(s) to carol, carol {} \
         to bob",
        after.0,
        after.1
    );
    // 2. Each reads the other promptly.
    for (who, at) in [
        ("bob reads carol", bob_reads_carol),
        ("carol reads bob", carol_reads_bob),
    ] {
        assert!(
            at.is_some_and(|t| t < BOUND),
            "{who} at {at:?} after the release, over {BOUND:?}\nbob said:\n{}\ncarol said:\n{}",
            bob_said.join("\n"),
            carol_said.join("\n")
        );
    }
    // 3. No dial between them waited out its timeout.
    let lost: Vec<&String> = bob_said
        .iter()
        .chain(&carol_said)
        .filter(|l| l.contains("could not reach") && l.contains("timed out"))
        .collect();
    assert!(
        lost.is_empty(),
        "a dial between two members crossing through one relay waited out its timeout — its \
         circuit was unmapped by the other's:\n{}",
        lost.iter()
            .map(|s| s.as_str())
            .collect::<Vec<_>>()
            .join("\n")
    );
}
