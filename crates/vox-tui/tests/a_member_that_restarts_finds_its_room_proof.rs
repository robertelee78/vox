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
//! Nothing is said nearby (`VOX_TEST_NO_NEARBY`, a `test-knobs` knob): on one computer, what a
//! node says nearby finds the other within seconds too, and the peer book is what is proved.
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
//!
//! - (d) **a member restored from an older backup writes nothing until that is resolved**
//!   (ADR-037 R5, #958). A node's own sequence in a room is its own durable fact, read from its
//!   local store; a peer that holds **more** of this node's own feed than the node does can only
//!   mean the node came back from an older copy of itself, and a write from there would sign a
//!   second entry at a place its members already hold (an equivocation). So: alice posts
//!   [`KEPT`] rows that bob reads, is stopped cleanly and her data directory copied; she comes
//!   back, posts [`LOST`] more rows that bob reads, and is stopped again; the copy is put back
//!   in her directory's place and she is started from it, on her port, with nothing said nearby.
//!   Within [`DETECT`] her daemon says so once:
//!   `this node's record of its own history in this room is behind what a member holds`. Her
//!   `vox room post` is then refused, twice, with that sentence; the daemon has said it once, not
//!   once per refusal; bob still reads every row she posted before and after the copy (nothing is
//!   reset, nothing is taken from anyone); and she still reads what bob posts now. The copy is
//!   taken with her daemon stopped (so it is a copy of a quiet store) and checked to have taken:
//!   her own read after the restore shows the kept rows and none of the lost ones, else
//!   APPARATUS. Mutation: the background detector removed (a peer's higher own head not compared
//!   with the local own feed) — her post is accepted and signed at a taken place; red on the
//!   refusal's assertion.

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
/// (d): rows alice posts before her data directory is copied, and after.
const KEPT: usize = 3;
const LOST: usize = 3;
/// (d): how long a node restored from an older copy has, from answering, to learn from a member
/// that its own history is behind and say so. A sync with bob happens within seconds of her
/// coming back (the 10 s bar above); the note follows the first such sync.
const DETECT: Duration = Duration::from_secs(60);
/// (d): how long a reopened room has to answer after its daemon does: a reopen prepares the room
/// before it is published, and that preparation waited on a governance refresh (measured: under
/// 60 s in one run of two, over it in the other, before ADR-037 R2 made the fold prompt).
const REOPENS_WITHIN: Duration = Duration::from_secs(120);
/// (d): what the daemon says once, and every refused write says, for a room whose own history is
/// behind what a member holds (ADR-037 R5, `Error::OwnHistoryBehind`).
const BEHIND: &str =
    "this node's record of its own history in this room is behind what a member holds";

/// A `vox daemon`, killed by its own PID when dropped.
struct Daemon(Child);

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

impl Daemon {
    /// Stop it the way a service manager does (SIGTERM, by its PID), and wait for it to leave, so
    /// its store is quiet; a daemon that does not leave in 20 s is killed by the drop.
    fn terminate(mut self) {
        let pid = self.0.id().to_string();
        let sent = Command::new("kill")
            .args(["-TERM", &pid])
            .status()
            .is_ok_and(|s| s.success());
        assert!(sent, "APPARATUS: `kill -TERM {pid}` did not take");
        let deadline = Instant::now() + Duration::from_secs(20);
        while Instant::now() < deadline {
            if matches!(self.0.try_wait(), Ok(Some(_))) {
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        eprintln!("[harness] the daemon did not leave within 20 s of SIGTERM; killing it");
    }
}

/// A stopped member's whole data directory, copied, each directory with its own permissions (a
/// node refuses a management directory that is not private): the backup (d) restores from.
fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to)
        .unwrap_or_else(|e| panic!("APPARATUS: cannot make {}: {e}", to.display()));
    let mode = std::fs::metadata(from)
        .unwrap_or_else(|e| panic!("APPARATUS: cannot stat {}: {e}", from.display()))
        .permissions();
    std::fs::set_permissions(to, mode)
        .unwrap_or_else(|e| panic!("APPARATUS: cannot set the mode of {}: {e}", to.display()));
    for e in std::fs::read_dir(from)
        .unwrap_or_else(|e| panic!("APPARATUS: cannot list {}: {e}", from.display()))
    {
        let e = e.expect("APPARATUS: cannot read a stopped profile's entry");
        let target = to.join(e.file_name());
        let kind = e
            .file_type()
            .expect("APPARATUS: cannot read a stopped profile entry's type");
        if kind.is_dir() {
            copy_dir(&e.path(), &target);
        } else if kind.is_file() {
            std::fs::copy(e.path(), &target).unwrap_or_else(|err| {
                panic!("APPARATUS: cannot copy {}: {err}", e.path().display())
            });
        }
        // A socket of the stopped process is not part of the profile.
    }
}

/// What the daemon tagged `tag` at `dir` has said on stderr so far.
fn daemon_said(dir: &Path, tag: &str) -> String {
    std::fs::read_to_string(dir.join(format!("daemon-{tag}.err")))
        .unwrap_or_else(|e| format!("(its stderr could not be read: {e})"))
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
    test_knobs::require(&["VOX_TEST_NO_NEARBY"]);
    let unheard = [("VOX_TEST_NO_NEARBY", "1".to_owned())];
    let t = tempfile::tempdir().unwrap();
    let (alice, alice_fp) = identity(t.path(), "alice");
    let (bob, bob_fp) = identity(t.path(), "bob");
    let mut alice_d = Some(daemon(
        &alice,
        "alice",
        &format!("{IDENTITY}\n"),
        "127.0.0.1:0",
        &unheard,
    ));
    let alice_at = listening(&alice);
    let _b = daemon(
        &bob,
        "bob",
        &format!("{IDENTITY}\n"),
        "127.0.0.1:0",
        &unheard,
    );
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
            &unheard,
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
        "PRODUCT: a restarted member must find its room again, both ways, within {WITHIN:?} of being \
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

/// How many of `rows` (`"<prefix> <i>"`, `i` in `1..=n`) the texts hold.
fn holds(texts: &[String], prefix: &str, n: usize) -> usize {
    (1..=n)
        .filter(|i| texts.iter().any(|t| t == &format!("{prefix} {i}")))
        .count()
}

/// Wait until `reader` reads every `"<prefix> <i>"` for `i` in `1..=n`, within `within`.
fn until_holds(reader: &Path, room: &str, prefix: &str, n: usize, within: Duration) -> bool {
    let deadline = Instant::now() + within;
    while Instant::now() < deadline {
        if holds(&read(reader, room), prefix, n) == n {
            return true;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    false
}

/// Wait until `dir`'s `vox room read` of `room` answers (a reopened room is prepared first),
/// within `within`.
fn room_answers(dir: &Path, room: &str, within: Duration) -> bool {
    let deadline = Instant::now() + within;
    while Instant::now() < deadline {
        if vox(dir, &["room", "read", room], None).0 {
            return true;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    false
}

/// Wait until `reader` reads the exact text, within `within`.
fn until_reads(reader: &Path, room: &str, text: &str, within: Duration) -> bool {
    let deadline = Instant::now() + within;
    while Instant::now() < deadline {
        if read(reader, room).iter().any(|t| t == text) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    false
}

/// (d) — see the module doc.
#[test]
#[ignore = "real vox daemons and production Argon2id; CI runs it in release"]
fn a_member_restored_from_an_older_backup_writes_nothing_until_resolved() {
    watchdog::arm();
    test_knobs::require(&["VOX_TEST_NO_NEARBY"]);
    let unheard = [("VOX_TEST_NO_NEARBY", "1".to_owned())];
    let t = tempfile::tempdir().expect("APPARATUS: no temp dir");
    let (alice, alice_fp) = identity(t.path(), "alice");
    let (bob, bob_fp) = identity(t.path(), "bob");
    let alice_d = daemon(
        &alice,
        "alice",
        &format!("{IDENTITY}\n"),
        "127.0.0.1:0",
        &unheard,
    );
    let alice_at = listening(&alice);
    let _b = daemon(
        &bob,
        "bob",
        &format!("{IDENTITY}\n"),
        "127.0.0.1:0",
        &unheard,
    );
    let room = create(&alice);
    join(&alice, &bob, &room);
    trust(&alice, &bob_fp, "bob");
    trust(&bob, &alice_fp, "alice");
    until_readable(&alice, &[&bob], &room);
    until_readable(&bob, &[&alice], &room);

    // ---- her record before the copy: KEPT rows, read by bob ----
    for i in 1..=KEPT {
        post(&alice, &room, &format!("kept {i}"));
    }
    assert!(
        until_holds(&bob, &room, "kept", KEPT, Duration::from_secs(60)),
        "PRODUCT (staging): bob never read alice's {KEPT} kept rows: he holds {:?}",
        read(&bob, &room)
    );
    alice_d.terminate();
    let backup = t.path().join("alice-backup");
    copy_dir(&alice, &backup);
    println!("[proof] alice's data directory copied after {KEPT} rows, with her daemon stopped");

    // ---- she goes on: LOST rows, read by bob; then stopped and restored from the copy ----
    let alice_d = daemon(
        &alice,
        "alice-2",
        &format!("{IDENTITY}\n{ROOMPASS}\n"),
        &alice_at,
        &unheard,
    );
    assert!(
        room_answers(&alice, &room, REOPENS_WITHIN),
        "PRODUCT (staging): alice's reopened room did not answer `vox room read` within {REOPENS_WITHIN:?} of \
         her restart: {}\nher daemon said:\n{}",
        vox(&alice, &["room", "read", &room], None).2,
        daemon_said(&alice, "alice-2")
    );
    for i in 1..=LOST {
        post(&alice, &room, &format!("lost {i}"));
    }
    assert!(
        until_holds(&bob, &room, "lost", LOST, Duration::from_secs(60)),
        "PRODUCT (staging): bob never read alice's {LOST} rows posted after the copy: he holds {:?}",
        read(&bob, &room)
    );
    alice_d.terminate();
    std::fs::remove_dir_all(&alice)
        .unwrap_or_else(|e| panic!("APPARATUS: cannot remove {}: {e}", alice.display()));
    copy_dir(&backup, &alice);
    let tag = "alice-restored";
    let _alice_d = daemon(
        &alice,
        tag,
        &format!("{IDENTITY}\n{ROOMPASS}\n"),
        &alice_at,
        &unheard,
    );
    assert!(
        room_answers(&alice, &room, REOPENS_WITHIN),
        "PRODUCT (staging): alice's room, reopened from the copy, did not answer `vox room read` \
         within {REOPENS_WITHIN:?} of her restart: {}\nher daemon said:\n{}",
        vox(&alice, &["room", "read", &room], None).2,
        daemon_said(&alice, tag)
    );
    let back_at = Instant::now();
    // The restore took: she holds the kept rows and none of the lost ones.
    let hers = read(&alice, &room);
    assert!(
        holds(&hers, "kept", KEPT) == KEPT && holds(&hers, "lost", LOST) == 0,
        "APPARATUS: the restore did not take: alice, started from the copy, reads {:?}",
        hers
    );

    // ---- (1) her daemon learns from bob that her own history is behind, and says so ----
    let noted = loop {
        let said = daemon_said(&alice, tag);
        if said.contains(BEHIND) {
            break back_at.elapsed();
        }
        if back_at.elapsed() > DETECT {
            let (ok, out, err) = vox(&alice, &["room", "post", &room, "after the restore"], None);
            panic!(
                "PRODUCT: {DETECT:?} after coming back from an older copy of herself, with bob \
                 holding {LOST} rows of her own feed that she does not, alice's daemon never said \
                 {BEHIND:?} (ADR-037 R5); her `vox room post` then {}: {out}{err}\n\
                 alice's daemon said:\n{said}\nbob's daemon said:\n{}",
                if ok { "was accepted" } else { "was refused" },
                daemon_said(&bob, "bob")
            );
        }
        std::thread::sleep(Duration::from_millis(250));
    };
    println!(
        "[proof] (1) alice's daemon said her own history is behind {noted:?} after she answered"
    );

    // ---- (2) every write in that room is refused with the sentence, (3) the daemon said it once ----
    for attempt in 1..=2 {
        let (ok, out, err) = vox(
            &alice,
            &[
                "room",
                "post",
                &room,
                &format!("after the restore {attempt}"),
            ],
            None,
        );
        let shown = format!("{out}{err}");
        assert!(
            !ok && shown.contains(BEHIND),
            "PRODUCT: post {attempt} by a node whose own history is behind what a member holds \
             must be refused saying {BEHIND:?}; `vox room post` {}: {shown}",
            if ok {
                "was accepted"
            } else {
                "was refused otherwise"
            }
        );
        println!(
            "[proof] (2) alice's post {attempt} refused: {}",
            shown.trim()
        );
    }
    std::thread::sleep(Duration::from_secs(2));
    let said = daemon_said(&alice, tag);
    let times = said.lines().filter(|l| l.contains(BEHIND)).count();
    assert_eq!(
        times, 1,
        "PRODUCT: the daemon must say {BEHIND:?} once, not once per refusal or never; it said it \
         {times} time(s):\n{said}"
    );

    // ---- (4) nothing is reset: bob holds every row she posted, she holds the kept ones ----
    let bobs = read(&bob, &room);
    assert!(
        holds(&bobs, "kept", KEPT) == KEPT && holds(&bobs, "lost", LOST) == LOST,
        "PRODUCT: after alice came back from an older copy, bob must still read every row she \
         posted before ({KEPT} kept) and after it ({LOST} lost); he reads {bobs:?}"
    );
    let hers = read(&alice, &room);
    assert!(
        holds(&hers, "kept", KEPT) == KEPT,
        "PRODUCT: alice must still read her own {KEPT} kept rows; she reads {hers:?}"
    );
    assert!(
        !hers.iter().any(|t| t.starts_with("after the restore")),
        "PRODUCT: a refused post of alice's is in her own room: {hers:?}"
    );

    // ---- (5) she still reads what bob posts now ----
    let from_bob = "bob, after alice's restore";
    post(&bob, &room, from_bob);
    let posted = Instant::now();
    assert!(
        until_reads(&alice, &room, from_bob, Duration::from_secs(60)),
        "PRODUCT: alice, writing nothing because her own history is behind, must still read what \
         bob posts; within 60 s she did not read {from_bob:?}: {:?}",
        read(&alice, &room)
    );
    println!(
        "[proof] (5) alice read bob's new post {:?} after it was posted, while writing nothing",
        posted.elapsed()
    );
}
