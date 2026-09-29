//! PRD-001 (no anchor required) — **a member that restarts finds its room again**, driven
//! through the shipped `vox` binary.
//!
//! A node learns where members are from the rendezvous board, which lives in memory, so a
//! member that restarted came back knowing no member's address. With no anchor it stayed
//! alone: its peers held a connection to the process that had died and never dialled again,
//! and nothing either side posted reached the other. Found by the R10 retention gate.
//!
//! The node now keeps where it last reached each member directly (`node::peer_book`, sealed
//! under its identity) and dials them when a room opens. Two members, **no anchor**; one
//! restarts:
//!
//! - (a) on the **same** port;
//! - (b) on a **new** port — the member who kept theirs is dialled by the restarted one, and
//!   learns the new address from that connection.
//!
//! Each time, a message posted while it was down must reach it, and a message it posts once
//! back must reach the other, both within 10 s of the restarted node answering (printed).
//! Mutation: nothing persisted — it never reconverges.
//!
//! The 10 s bar also needs the survivor to stop using its connection to the dead process as soon
//! as the restarted one connects (`prd1/restart-probe` 582f18a). Without that, both directions
//! measured 29.4–30.1 s: the old connection held the room's sync until `SILENCE_IS_DEATH`.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const VOX: &str = env!("CARGO_BIN_EXE_vox");
const IDENTITY: &str = "an identity passphrase";
const ROOMPASS: &str = "the room passphrase";
/// How soon after the restarted node answers both sides must have each other's message.
const WITHIN: Duration = Duration::from_secs(10);

/// A `vox daemon`, killed by its own PID when dropped.
struct Daemon(Child);

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn vox(dir: &Path, args: &[&str], stdin: Option<&str>) -> (bool, String, String) {
    let mut cmd = Command::new(VOX);
    cmd.args(args)
        .env("VOX_DATA_DIR", dir)
        .env("VOX_CONFIG_DIR", dir.join("cfg"))
        .env("VOX_IDENTITY_PASSPHRASE", IDENTITY)
        .env_remove("VOX_ROOM")
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().expect("spawn vox");
    if let Some(text) = stdin {
        child
            .stdin
            .as_mut()
            .expect("stdin")
            .write_all(text.as_bytes())
            .expect("write stdin");
        drop(child.stdin.take());
    }
    // Bounded: a node that stops answering must fail this proof by name, not hang it.
    let deadline = Instant::now() + Duration::from_secs(120);
    while child.try_wait().expect("try_wait").is_none() {
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("`vox {}` got no answer in 120 s", args.join(" "));
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let out = child.wait_with_output().expect("wait");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// A free loopback UDP port, so a node can come back on the address its peers know.
fn free_port() -> String {
    let s = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    format!("127.0.0.1:{}", s.local_addr().unwrap().port())
}

/// `vox daemon` on `listen`, with `env` added, answering on its socket before this returns.
fn daemon(
    dir: &Path,
    tag: &str,
    stdin_lines: &str,
    listen: &str,
    env: &[(&str, String)],
) -> Daemon {
    let out = std::fs::File::create(dir.join(format!("daemon-{tag}.out"))).unwrap();
    let err = std::fs::File::create(dir.join(format!("daemon-{tag}.err"))).unwrap();
    let mut cmd = Command::new(VOX);
    cmd.args(["daemon", "--listen", listen])
        .env("VOX_DATA_DIR", dir)
        .env("VOX_CONFIG_DIR", dir.join("cfg"))
        .env_remove("VOX_ROOM")
        .stdin(Stdio::piped())
        .stdout(Stdio::from(out))
        .stderr(Stdio::from(err));
    for (k, v) in env {
        cmd.env(k, v);
    }
    let mut child = cmd.spawn().expect("spawn vox daemon");
    let mut pipe = child.stdin.take().expect("daemon stdin");
    pipe.write_all(stdin_lines.as_bytes()).unwrap();
    drop(pipe);
    let d = Daemon(child);
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        if vox(dir, &["room", "list"], None).0 {
            return d;
        }
        assert!(
            Instant::now() < deadline,
            "{tag}'s daemon never answered: {}",
            std::fs::read_to_string(dir.join(format!("daemon-{tag}.err"))).unwrap_or_default()
        );
        std::thread::sleep(Duration::from_millis(200));
    }
}

fn identity(tmp: &Path, name: &str) -> (PathBuf, String) {
    let dir = tmp.join(name);
    std::fs::create_dir_all(dir.join("cfg")).unwrap();
    let (ok, out, err) = vox(&dir, &["id"], None);
    assert!(ok, "vox id {name}: {err}");
    (dir, out.trim().to_owned())
}

/// The texts `vox room read` returns.
fn read(dir: &Path, room: &str) -> Vec<String> {
    let (ok, out, err) = vox(dir, &["room", "read", room], None);
    assert!(ok, "vox room read: {err}");
    out.lines()
        .filter_map(|l| l.splitn(3, ' ').nth(2).map(str::to_owned))
        .collect()
}

fn count(texts: &[String], prefix: &str) -> usize {
    texts.iter().filter(|t| t.starts_with(prefix)).count()
}

fn post(dir: &Path, room: &str, text: &str) {
    let (ok, _, err) = vox(dir, &["room", "post", room, text], None);
    assert!(ok, "vox room post {text:?}: {err}");
}

fn trust(dir: &Path, fp: &str, name: &str) {
    let (ok, _, err) = vox(dir, &["trust", "add", fp, "--name", name], None);
    assert!(ok, "vox trust add {name}: {err}");
}

/// `creator` makes a room; returns its short id as `vox room list` prints it.
fn create(creator: &Path) -> String {
    let (ok, _, err) = vox(
        creator,
        &["room", "create", "--name", "r"],
        Some(&format!("{ROOMPASS}\n")),
    );
    assert!(ok, "vox room create: {err}");
    let (_, listed, _) = vox(creator, &["room", "list"], None);
    listed
        .split_whitespace()
        .next()
        .expect("a room id")
        .to_owned()
}

fn join(creator: &Path, joiner: &Path, room: &str) {
    let (ok, link, err) = vox(creator, &["room", "invite", room], None);
    assert!(ok, "vox room invite: {err}");
    let (ok, _, err) = vox(
        joiner,
        &["room", "join", link.trim(), "--name", "r"],
        Some(&format!("{ROOMPASS}\n")),
    );
    assert!(ok, "vox room join: {err}");
}

/// `author` posts a probe until every one of `readers` shows one: from then on they read it.
fn until_readable(author: &Path, readers: &[&Path], room: &str) {
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        post(author, room, "probe");
        std::thread::sleep(Duration::from_millis(500));
        if readers.iter().all(|r| count(&read(r, room), "probe") > 0) {
            return;
        }
        assert!(Instant::now() < deadline, "a reader never read the author");
    }
}

/// From `since`, poll both directions at once until each has arrived or `limit` passes: how long
/// after `since` alice first read `to_alice` and bob first read `to_bob` (`None` = never).
fn arrivals(
    since: Instant,
    (alice, to_alice): (&Path, &str),
    (bob, to_bob): (&Path, &str),
    room: &str,
    limit: Duration,
) -> (Option<Duration>, Option<Duration>) {
    let (mut a, mut b) = (None, None);
    while (a.is_none() || b.is_none()) && since.elapsed() < limit {
        if a.is_none() && read(alice, room).iter().any(|x| x == to_alice) {
            a = Some(since.elapsed());
        }
        if b.is_none() && read(bob, room).iter().any(|x| x == to_bob) {
            b = Some(since.elapsed());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    (a, b)
}

#[test]
#[ignore = "real vox daemons and production Argon2id; CI runs it in release"]
fn a_member_that_restarts_finds_its_room_again_without_an_anchor() {
    watchdog::arm();
    let t = tempfile::tempdir().unwrap();
    let (alice, alice_fp) = identity(t.path(), "alice");
    let (bob, bob_fp) = identity(t.path(), "bob");
    let (alice_at, bob_at) = (free_port(), free_port());
    let mut alice_d = Some(daemon(
        &alice,
        "alice",
        &format!("{IDENTITY}\n"),
        &alice_at,
        &[],
    ));
    let _b = daemon(&bob, "bob", &format!("{IDENTITY}\n"), &bob_at, &[]);
    let room = create(&alice);
    join(&alice, &bob, &room);
    trust(&alice, &bob_fp, "bob");
    trust(&bob, &alice_fp, "alice");
    until_readable(&alice, &[&bob], &room);
    until_readable(&bob, &[&alice], &room);

    let mut results = Vec::new();
    for (case, listen) in [("same port", alice_at.clone()), ("new port", free_port())] {
        drop(alice_d.take()); // stopped by PID
        let away = format!("posted while alice was down ({case})");
        post(&bob, &room, &away);
        alice_d = Some(daemon(
            &alice,
            &format!("alice-{}", listen.replace([':', '.'], "-")),
            &format!("{IDENTITY}\n{ROOMPASS}\n"),
            &listen,
            &[],
        ));
        let back_at = Instant::now();
        let back = format!("alice is back ({case})");
        post(&alice, &room, &back);
        let (to_alice, to_bob) = arrivals(
            back_at,
            (&alice, &away),
            (&bob, &back),
            &room,
            Duration::from_secs(60),
        );
        println!(
            "restart on the {case} ({listen}), measured from alice answering: bob's message \
             reached alice after {to_alice:?}, alice's reached bob after {to_bob:?}"
        );
        results.push((case, to_alice, to_bob));
    }
    let converged = results
        .iter()
        .filter(|(_, a, b)| a.is_some_and(|a| a <= WITHIN) && b.is_some_and(|b| b <= WITHIN))
        .count();
    println!(
        "{converged}/{} restarts converged both ways within {WITHIN:?}",
        results.len()
    );
    assert_eq!(
        converged,
        results.len(),
        "a restarted member must find its room again, both ways, within {WITHIN:?} of being \
         back (None = never, in 60 s): {results:?}"
    );
}
