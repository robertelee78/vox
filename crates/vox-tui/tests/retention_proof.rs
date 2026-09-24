//! ADR-023 M23.1 / PRD-001 R6–R10 — retention, driven through the **shipped `vox` binary**.
//!
//! History is kept forever by default. A room's admin can make it disappear after a while
//! (`vox room retention`), a node can keep less than its room (the `retention` file in its config
//! directory), the shorter wins, and shortening applies to what is already stored. An expired
//! message leaves nothing visible; its signed skeleton stays so sync and fork detection keep
//! working. This is look and feel, not a security property.
//!
//! Real seconds, small durations, no faked clocks: the waits below are the durations themselves.
//!
//! **Proof 3 (retroactive):** 40 messages, a pause, 60 more; the admin sets the room to 30 s.
//! On both members `vox room read` shows exactly the 60, their stores hold 60 plaintext cache rows
//! and every skeleton, a restart still opens the room, and then the 60 go too.
//!
//! **Proof 4 (shortest wins) and a late arrival:** the room keeps a week, one member's node keeps
//! a minute. That member's view empties at a minute while the other keeps everything. Then, with
//! that node down, more is posted; it comes back after they are older than its minute, syncs them,
//! and **never shows them** — polled tightly the whole way, so a render-then-prune would be seen.
//!
//! Mutations (each run, each red): the sweep disabled; a reload that refuses a pruned entry; the
//! node's own retention ignored; the arrival check removed.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use vox_core::atrest::store::SegmentKind;

const VOX: &str = env!("CARGO_BIN_EXE_vox");
const IDENTITY: &str = "an identity passphrase";
const ROOMPASS: &str = "the room passphrase";

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
    let out = child.wait_with_output().expect("wait");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn daemon(dir: &Path, tag: &str, stdin_lines: &str) -> Daemon {
    let out = std::fs::File::create(dir.join(format!("daemon-{tag}.out"))).unwrap();
    let err = std::fs::File::create(dir.join(format!("daemon-{tag}.err"))).unwrap();
    let mut child = Command::new(VOX)
        .args(["daemon", "--listen", "127.0.0.1:0"])
        .env("VOX_DATA_DIR", dir)
        .env("VOX_CONFIG_DIR", dir.join("cfg"))
        .env_remove("VOX_ROOM")
        .stdin(Stdio::piped())
        .stdout(Stdio::from(out))
        .stderr(Stdio::from(err))
        .spawn()
        .expect("spawn vox daemon");
    let mut pipe = child.stdin.take().expect("daemon stdin");
    pipe.write_all(stdin_lines.as_bytes()).unwrap();
    drop(pipe);
    Daemon(child)
}

/// `vox room list` once the daemon's socket answers.
fn attached(dir: &Path, tag: &str) -> String {
    let deadline = Instant::now() + Duration::from_secs(90);
    let mut last = String::new();
    while Instant::now() < deadline {
        let (ok, out, err) = vox(dir, &["room", "list"], None);
        if ok {
            return out;
        }
        last = err;
        std::thread::sleep(Duration::from_millis(200));
    }
    panic!(
        "{tag}'s daemon never answered: {last}\nits stderr: {}",
        std::fs::read_to_string(dir.join(format!("daemon-{tag}.err"))).unwrap_or_default()
    );
}

/// The texts `vox room read` returns.
fn read(dir: &Path, room: &str) -> Vec<String> {
    let (ok, out, err) = vox(dir, &["room", "read", room], None);
    assert!(ok, "vox room read: {err}");
    // `<entry-hash> <author-prefix> <text>`
    out.lines()
        .filter_map(|l| l.splitn(3, ' ').nth(2).map(str::to_owned))
        .collect()
}

fn count(texts: &[String], prefix: &str) -> usize {
    texts.iter().filter(|t| t.starts_with(prefix)).count()
}

/// Poll `vox room read` until `done`, or panic naming what it last saw.
fn until(dir: &Path, room: &str, what: &str, secs: u64, done: impl Fn(&[String]) -> bool) {
    let deadline = Instant::now() + Duration::from_secs(secs);
    let mut last = Vec::new();
    while Instant::now() < deadline {
        last = read(dir, room);
        if done(&last) {
            return;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    panic!(
        "timed out waiting for {what}; `room read` shows {} rows",
        last.len()
    );
}

fn post(dir: &Path, room: &str, text: &str) {
    let (ok, _, err) = vox(dir, &["room", "post", room, text], None);
    assert!(ok, "vox room post {text:?}: {err}");
}

/// Two identities that trust each other, as fresh profiles.
fn pair(tmp: &Path) -> (PathBuf, PathBuf) {
    let a = tmp.join("a");
    let b = tmp.join("b");
    for d in [&a, &b] {
        std::fs::create_dir_all(d.join("cfg")).unwrap();
    }
    let mut fps = Vec::new();
    for dir in [&a, &b] {
        let (ok, out, err) = vox(dir, &["id"], None);
        assert!(ok, "vox id: {err}");
        fps.push(out.trim().to_owned());
    }
    for (dir, fp) in [(&a, &fps[1]), (&b, &fps[0])] {
        let (ok, _, err) = vox(dir, &["trust", "add", fp, "--name", "peer"], None);
        assert!(ok, "vox trust add: {err}");
    }
    (a, b)
}

/// `creator` makes a room, `joiner` joins it; returns the room id as `vox` prints it.
fn room(creator: &Path, joiner: &Path) -> String {
    let (ok, _, err) = vox(
        creator,
        &["room", "create", "--name", "r"],
        Some(&format!("{ROOMPASS}\n")),
    );
    assert!(ok, "vox room create: {err}");
    let room = attached(creator, "creator")
        .split_whitespace()
        .next()
        .expect("a room id")
        .to_owned();
    let (ok, link, err) = vox(creator, &["room", "invite", &room], None);
    assert!(ok, "vox room invite: {err}");
    let (ok, _, err) = vox(
        joiner,
        &["room", "join", link.trim(), "--name", "r"],
        Some(&format!("{ROOMPASS}\n")),
    );
    assert!(ok, "vox room join: {err}");
    // What a newcomer can read starts when the creator's key reaches it (history per grant is
    // ADR-023 decision 5, not built), so wait for that before anything is counted: the creator
    // posts a probe until the joiner shows one.
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        post(creator, &room, "probe");
        std::thread::sleep(Duration::from_millis(500));
        if count(&read(joiner, &room), "probe") > 0 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the joiner never read the creator"
        );
    }
    room
}

/// `(plaintext cache rows, log pages)` in a stopped node's store.
fn store_counts(dir: &Path) -> (usize, usize) {
    let paths = vox_core::node::paths::Paths::resolve("default", Some(dir), Some(&dir.join("cfg")))
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    let profile = loop {
        match vox_core::node::profile::Profile::open(paths.clone()) {
            Ok(p) => break p,
            Err(_) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(200)),
            Err(e) => panic!("the store did not open: {e:?}"),
        }
    };
    let store = profile.store();
    let cid = store.channels().unwrap()[0];
    (
        store
            .segments(&cid, SegmentKind::PlaintextCache)
            .unwrap()
            .len(),
        store.segments(&cid, SegmentKind::LogDb).unwrap().len(),
    )
}

#[test]
#[ignore = "real vox daemons and real seconds (about two minutes); CI runs it in release"]
fn shortening_a_rooms_retention_removes_older_messages_on_every_member() {
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();
    let (alice, bob) = pair(tmp.path());
    let alice_d = daemon(&alice, "alice", &format!("{IDENTITY}\n"));
    attached(&alice, "alice");
    let bob_d = daemon(&bob, "bob", &format!("{IDENTITY}\n"));
    attached(&bob, "bob");
    let room = room(&alice, &bob);

    // ---- 40 messages, then a pause longer than the retention to come ------------------------
    for i in 1..=40 {
        post(&alice, &room, &format!("old {i}"));
    }
    until(&bob, &room, "bob to read the 40", 60, |t| {
        count(t, "old ") == 40
    });
    let old_done = Instant::now();
    std::thread::sleep(Duration::from_secs(45));

    // ---- 60 more, then 30 s retention: the 40 are 45 s old, the 60 a few seconds ------------
    for i in 1..=60 {
        post(&alice, &room, &format!("new {i}"));
    }
    until(&bob, &room, "bob to read all 100", 60, |t| {
        count(t, "old ") + count(t, "new ") == 100
    });
    let (ok, out, err) = vox(&alice, &["room", "retention", &room, "30"], None);
    assert!(ok, "vox room retention: {err}");
    println!("{}", out.trim());
    let set_at = Instant::now();

    for (dir, who) in [(&alice, "alice"), (&bob, "bob")] {
        until(dir, &room, &format!("{who} to show only the 60"), 20, |t| {
            count(t, "old ") == 0 && count(t, "new ") == 60 && count(t, "probe") == 0
        });
        println!(
            "{who}: `room read` shows 60 of 100 ({} s after the retention was set; the 40 were \
             {} s old)",
            set_at.elapsed().as_secs(),
            old_done.elapsed().as_secs()
        );
    }
    // Both stopped before the 60 reach 30 s, so the stores are read at exactly this state.
    drop(alice_d);
    drop(bob_d);
    let (a_cache, a_log) = store_counts(&alice);
    let (b_cache, b_log) = store_counts(&bob);
    println!(
        "stores {} s after: alice {a_cache} cache rows / {a_log} log pages, bob {b_cache} / {b_log}",
        set_at.elapsed().as_secs()
    );
    assert_eq!(
        (a_cache, b_cache),
        (60, 60),
        "the plaintext cache holds only the 60"
    );
    assert!(
        a_log >= 100 && b_log >= 100,
        "every skeleton is kept: alice {a_log}, bob {b_log} log pages for 100 messages"
    );

    // ---- a restart still opens the room, and the 60 then go too ------------------------------
    let _alice_d = daemon(&alice, "alice-2", &format!("{IDENTITY}\n{ROOMPASS}\n"));
    let listed = attached(&alice, "alice");
    println!("after the restart: `room list` says {listed:?}");
    assert!(
        !listed.contains("[closed]"),
        "a room holding pruned entries must reopen: {listed:?}\nalice's daemon said: {}",
        std::fs::read_to_string(alice.join("daemon-alice-2.err")).unwrap_or_default()
    );
    until(
        &alice,
        &room,
        "the 60 to expire as well",
        60,
        <[String]>::is_empty,
    );
    println!(
        "{} s after the retention was set, alice shows 0",
        set_at.elapsed().as_secs()
    );
}

#[test]
#[ignore = "real vox daemons and real minutes (about three); CI runs it in release"]
fn a_node_keeps_less_than_its_room_and_never_shows_what_arrives_expired() {
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();
    let (bob, alice) = pair(tmp.path());
    // Alice's node keeps a minute, whatever the room says.
    std::fs::write(alice.join("cfg").join("retention"), "default 60\n").unwrap();
    let bob_d = daemon(&bob, "bob", &format!("{IDENTITY}\n"));
    attached(&bob, "bob");
    let alice_d = daemon(&alice, "alice", &format!("{IDENTITY}\n"));
    attached(&alice, "alice");
    let room = room(&bob, &alice);
    let (ok, out, err) = vox(&bob, &["room", "retention", &room, "1w"], None);
    assert!(ok, "vox room retention 1w: {err}");
    println!("{}", out.trim());

    // ---- proof 4: the node prunes at its minute; the other member keeps the week ----------
    for i in 1..=10 {
        post(&bob, &room, &format!("early {i}"));
    }
    let posted = Instant::now();
    until(&alice, &room, "alice to read the 10", 60, |t| {
        count(t, "early ") == 10
    });
    until(&alice, &room, "alice's minute to pass", 90, |t| {
        count(t, "early ") == 0
    });
    let gone = posted.elapsed().as_secs();
    let bob_keeps = count(&read(&bob, &room), "early ");
    println!("alice shows 0 of 10 after {gone} s; bob (a week) still shows {bob_keeps}");
    assert!(gone >= 55, "alice pruned at {gone} s, before her minute");
    assert_eq!(
        bob_keeps, 10,
        "the room keeps a week: bob must still show all 10"
    );

    // ---- a late arrival of what is already expired here never shows ---------------------
    drop(alice_d);
    for i in 1..=5 {
        post(&bob, &room, &format!("late {i}"));
    }
    std::thread::sleep(Duration::from_secs(65));
    let _alice_d = daemon(&alice, "alice-2", &format!("{IDENTITY}\n{ROOMPASS}\n"));
    attached(&alice, "alice");
    post(&bob, &room, "fresh");
    // `fresh` follows the five in bob's feed, so once alice shows it she holds all of them.
    // Polled as tightly as the CLI allows, so a render that a later sweep took back is seen.
    let deadline = Instant::now() + Duration::from_secs(90);
    let (mut polls, mut late_seen) = (0usize, 0usize);
    let mut fresh = false;
    while Instant::now() < deadline && !fresh {
        let t = read(&alice, &room);
        polls += 1;
        late_seen = late_seen.max(count(&t, "late "));
        fresh = t.iter().any(|x| x == "fresh");
    }
    println!(
        "alice: `fresh` shown {fresh}; the 5 late ones shown at most {late_seen} times over \
         {polls} reads"
    );
    assert!(fresh, "alice never caught up with bob's feed");
    assert_eq!(
        late_seen, 0,
        "a message that arrives already expired must never be shown"
    );
    drop(bob_d);
}
