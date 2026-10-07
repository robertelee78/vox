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
//! - (c) **a pair whose peer books were written when Vox kept times in seconds** (#562). The
//!   fixture `fixtures/seconds-format-pair.tar.gz` is two members' data directories, alice and
//!   bob, made by `vox` at integrate 48b1c743 (peer book version 1, times in seconds): one room,
//!   both trusting each other, last reached directly with bob on 127.0.0.1:47613. This build
//!   brings bob back there and alice on a new port, with no anchor and nothing said nearby
//!   (`VOX_TEST_NO_NEARBY`, a `test-knobs` knob: on one computer, what a node says nearby finds
//!   the other within seconds too), so the books are the only way the two find each other. Each
//!   must read the other's new message within 10 s, and the posts from before still read.
//!   Mutation: a version-1 book refused — they never reconverge. A version-1 book's times read
//!   as milliseconds instead of seconds is not asserted: nothing a person sees shows a book's
//!   times (they only spare a rewrite of an address seen again within ten minutes, and choose
//!   whom a full book forgets). Bob's fixed port taken by another program at run time is
//!   APPARATUS (the daemon says it cannot bind), never PRODUCT.
//!
//! The 10 s bar also needs the survivor to stop using its connection to the dead process as soon
//! as the restarted one connects (`prd1/restart-probe` 582f18a). Without that, both directions
//! measured 29.4–30.1 s: the old connection held the room's sync until `SILENCE_IS_DEATH`.

#![cfg(unix)]

#[path = "support/ports.rs"]
mod ports;
#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/typed.rs"]
mod typed;

#[path = "support/test_knobs.rs"]
mod test_knobs;

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
    // A keyring change's passphrase is typed at a terminal, as a person types it (ADR-028 K-13).
    if typed::is_keyring_change(args) {
        let (ok, shown) = typed::keyring(&cmd);
        return (ok, shown.clone(), shown);
    }
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

/// Where the daemon at `dir` listens, from its own `vox status --json` (#410): a daemon starts on
/// port 0, and a restart that must come back on the address its peers know reads it here, never
/// from a port picked ahead.
fn listening(dir: &Path) -> String {
    let (_, status, _) = vox(dir, &["status", "--json"], None);
    ports::loopback_listen(&status)
        .unwrap_or_else(|| panic!("PRODUCT (staging): no loopback listen address in {status}"))
        .to_string()
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
        let said =
            std::fs::read_to_string(dir.join(format!("daemon-{tag}.err"))).unwrap_or_default();
        assert!(
            !ports::bind_refused(&said),
            "{}: {tag}'s daemon on {listen}:\n{said}",
            ports::APPARATUS_BIND
        );
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
        &["room", "create", "--passphrase-file", "-", "--name", "r"],
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
    let (ok, link, err) = vox(creator, &["room", "link", room], None);
    assert!(ok, "vox room link: {err}");
    let (ok, _, err) = vox(
        joiner,
        &["room", "join", "--passphrase-file", "-", link.trim()],
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
    let mut alice_d = Some(daemon(
        &alice,
        "alice",
        &format!("{IDENTITY}\n"),
        "127.0.0.1:0",
        &[],
    ));
    let alice_at = listening(&alice);
    let _b = daemon(&bob, "bob", &format!("{IDENTITY}\n"), "127.0.0.1:0", &[]);
    let room = create(&alice);
    join(&alice, &bob, &room);
    trust(&alice, &bob_fp, "bob");
    trust(&bob, &alice_fp, "alice");
    until_readable(&alice, &[&bob], &room);
    until_readable(&bob, &[&alice], &room);

    let mut results = Vec::new();
    // The new port is one alice's running daemon does not hold, so the case cannot fall back to
    // her old one, as a restart on port 0 can (the system hands a freed port out again). Another
    // program can take it before she binds it; her daemon then says so and the red is APPARATUS.
    let new_port = std::net::UdpSocket::bind("127.0.0.1:0")
        .and_then(|s| s.local_addr())
        .expect("APPARATUS: a free UDP port")
        .to_string();
    for (case, listen) in [("same port", alice_at.clone()), ("new port", new_port)] {
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

/// The room the pair fixture holds, as `vox` at integrate 48b1c743 made it.
const PAIR_ROOM: &str = "alr5dektwa2b6ti7ycp4wps6gwtknwvd5qhk2gnpk7je7avttdha";
/// Where bob listened when the fixture was made: the address alice's book holds for him.
const PAIR_BOB_AT: &str = "127.0.0.1:47613";

#[test]
#[ignore = "real vox daemons and production Argon2id; CI runs it in release"]
fn a_pair_whose_peer_books_were_kept_in_seconds_finds_each_other_again() {
    watchdog::arm();
    let t = tempfile::tempdir().expect("APPARATUS: no temp dir");
    let fixture = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/seconds-format-pair.tar.gz"
    );
    let unpacked = Command::new("tar")
        .args(["-xzf", fixture, "-C"])
        .arg(t.path())
        .status()
        .unwrap_or_else(|e| panic!("APPARATUS: cannot run tar: {e}"));
    assert!(
        unpacked.success(),
        "APPARATUS: tar could not unpack {fixture}"
    );
    let (alice, bob) = (t.path().join("alice"), t.path().join("bob"));
    test_knobs::require(&["VOX_TEST_NO_NEARBY"]);
    let unlock = format!("{IDENTITY}\n{ROOMPASS}\n");
    let unheard = [("VOX_TEST_NO_NEARBY", "1".to_owned())];
    let _b = daemon(&bob, "bob", &unlock, PAIR_BOB_AT, &unheard);
    let _a = daemon(&alice, "alice", &unlock, "127.0.0.1:0", &unheard);
    let back_at = Instant::now();
    for (dir, who) in [(&alice, "alice"), (&bob, "bob")] {
        let before = format!("{who} said while times were seconds");
        assert!(
            read(dir, PAIR_ROOM).contains(&before),
            "PRODUCT: {who}'s post from when times were seconds must still read on {who}'s node"
        );
    }
    let (to_alice, to_bob) = (
        "bob is back in milliseconds",
        "alice is back in milliseconds",
    );
    post(&bob, PAIR_ROOM, to_alice);
    post(&alice, PAIR_ROOM, to_bob);
    let (a, b) = arrivals(
        back_at,
        (&alice, to_alice),
        (&bob, to_bob),
        PAIR_ROOM,
        Duration::from_secs(60),
    );
    println!(
        "[proof] a pair from when times were seconds, back with no anchor: bob's message reached \
         alice after {a:?}, alice's reached bob after {b:?}"
    );
    assert!(
        a.is_some_and(|a| a <= WITHIN) && b.is_some_and(|b| b <= WITHIN),
        "PRODUCT: two members whose peer books were written when times were seconds must find each \
         other again with no anchor, both ways, within {WITHIN:?} (None = never, in 60 s): bob to \
         alice {a:?}, alice to bob {b:?}"
    );
}
