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
//! **Proof 3 (retroactive), and a node keeping more follows the room:** 40 messages, a pause, 60
//! more; the admin sets the room to 30 s. bob's node keeps **a week** (the `retention` file in its
//! config), longer than the room; a node may keep less than its room, never more (PRD-001 R9). On
//! both members `vox room read` shows exactly the 60 (on bob too, though his node would keep a
//! week), a restart still opens the room, and then the 60 go too.
//!
//! **Proof 4 (shortest wins) and a late arrival:** the room keeps a week, one member's node keeps
//! a minute. That member's view empties at a minute while the other keeps everything. Then, with
//! that node down, more is posted; it comes back after they are older than its minute, syncs them,
//! and **never shows them** — polled tightly the whole way, so a render-then-prune would be seen.
//!
//! **A red names its side.** A claim's assertion is PRODUCT and quotes what `vox` showed. A `vox`
//! command that fails, or a node that does not get there, while the scene is set (an identity, a
//! trust, a daemon, a room, a join, a post, a first read) is the product failing: PRODUCT
//! (staging); each wait says which it is. The test's own processes, files, ports, runtime and
//! its subscriber on alice's socket are APPARATUS.
//!
//! **Proof 5 (a late member, V210-138):** the room keeps 30 s; ten messages expire on both
//! members, so every copy of them left is a skeleton. A third member then joins: it must read the
//! author's next post within [`LATE_BOUND`] of its join, show none of the ten, and show nothing as
//! not received yet — it waits on no body that no member can supply. Its feed of the author starts
//! at those skeletons, so a node that sets a skeleton aside never gets past them. The other side
//! of V210-138, a body stripped from a live entry still owed and asked for, is
//! `a_hostile_entry_does_not_stop_a_room_proof`'s stripped arm.
//!
//! **ADR-028 F-5, in proof 4:** each member shares a file and each node pulls the other's. At
//! alice's minute her copy of bob's share is deleted, and her own share is no longer served, so
//! bob, who keeps its announcement a week, is told the offer is gone; his copy stays.
//!
//! **In proof 3, the same second (#441):** alice posts and, in the same second, changes the room's
//! retention; `vox room read --json --notices` gives the change after the post, its time in
//! milliseconds and no earlier than the post's.
//!
//! Mutations (each run, each red): a governance entry claiming its whole second (red: the change's
//! time is before the post's); a notice placed before the row it follows (red: the change read
//! before the post); the sweep disabled; a reload that refuses a pruned entry; the
//! node's own retention ignored; the node's retention winning whenever it is set (so a node
//! keeping more than its room keeps more); the arrival check removed; a payload-less entry set
//! aside as v0.2.10 did (Withheld, still owed), which turns proof 5 red; a pulled copy kept past
//! its message (red: alice's copy is still there).

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/attach.rs"]
mod attach;
#[path = "support/ports.rs"]
mod ports;
#[path = "support/typed.rs"]
mod typed;

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const VOX: &str = env!("CARGO_BIN_EXE_vox");
const IDENTITY: &str = "an identity passphrase";
const ROOMPASS: &str = "the room passphrase";
/// How long after its join a late member may take to read the author's next post (proof 5).
const LATE_BOUND: Duration = Duration::from_secs(60);

/// A `vox daemon`, killed by its own PID when dropped.
struct Daemon(Child);

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn vox(dir: &Path, args: &[&str], stdin: Option<&str>) -> (bool, String, String) {
    vox_with(dir, args, stdin, Some(IDENTITY))
}

/// `vox args` with `VOX_IDENTITY_PASSPHRASE` set to `identity`, or unset, and no terminal.
fn vox_with(
    dir: &Path,
    args: &[&str],
    stdin: Option<&str>,
    identity: Option<&str>,
) -> (bool, String, String) {
    let mut cmd = Command::new(VOX);
    match identity {
        Some(p) => cmd.env("VOX_IDENTITY_PASSPHRASE", p),
        None => cmd.env_remove("VOX_IDENTITY_PASSPHRASE"),
    };
    cmd.args(args)
        .env("VOX_DATA_DIR", dir)
        .env("VOX_CONFIG_DIR", dir.join("cfg"))
        .env_remove("VOX_ROOM")
        .env_remove("VOX_NODE")
        .env_remove("VOX_SESSION")
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
    let mut child = cmd.spawn().expect("APPARATUS: spawn vox");
    if let Some(text) = stdin {
        child
            .stdin
            .as_mut()
            .expect("APPARATUS: vox's stdin")
            .write_all(text.as_bytes())
            .expect("APPARATUS: write to vox's stdin");
        drop(child.stdin.take());
    }
    let out = child.wait_with_output().expect("APPARATUS: wait for vox");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn daemon(dir: &Path, tag: &str, stdin_lines: &str) -> Daemon {
    daemon_on(dir, tag, stdin_lines, "127.0.0.1:0")
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

/// [`daemon`] listening on `listen`.
fn daemon_on(dir: &Path, tag: &str, stdin_lines: &str, listen: &str) -> Daemon {
    let out = std::fs::File::create(dir.join(format!("daemon-{tag}.out")))
        .expect("APPARATUS: the daemon's output file");
    let err = std::fs::File::create(dir.join(format!("daemon-{tag}.err")))
        .expect("APPARATUS: the daemon's output file");
    let mut child = Command::new(VOX)
        .args(["daemon", "--listen", listen])
        .env("VOX_DATA_DIR", dir)
        .env("VOX_CONFIG_DIR", dir.join("cfg"))
        .env_remove("VOX_ROOM")
        .env_remove("VOX_NODE")
        .env_remove("VOX_SESSION")
        .stdin(Stdio::piped())
        .stdout(Stdio::from(out))
        .stderr(Stdio::from(err))
        .spawn()
        .expect("APPARATUS: spawn vox daemon");
    let mut pipe = child.stdin.take().expect("APPARATUS: the daemon's stdin");
    pipe.write_all(stdin_lines.as_bytes())
        .expect("APPARATUS: write the daemon's passphrases");
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
        // A daemon that could not bind where the proof put it measured nothing (#410).
        let said: String = std::fs::read_dir(dir)
            .into_iter()
            .flatten()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().ends_with(".err"))
            .filter_map(|e| std::fs::read_to_string(e.path()).ok())
            .collect();
        assert!(
            !ports::bind_refused(&said),
            "{}: {tag}'s daemon:\n{said}",
            ports::APPARATUS_BIND
        );
        last = err;
        std::thread::sleep(Duration::from_millis(200));
    }
    panic!(
        "PRODUCT (staging): {tag}'s daemon never answered: {last}\nits stderr: {}",
        std::fs::read_to_string(dir.join(format!("daemon-{tag}.err"))).unwrap_or_default()
    );
}

/// The texts `vox room read` returns.
fn read(dir: &Path, room: &str) -> Vec<String> {
    let (ok, out, err) = vox(dir, &["room", "read", room], None);
    assert!(ok, "PRODUCT: vox room read: {err}");
    // `<entry-hash> <author-prefix> <text>`
    out.lines()
        .filter_map(|l| l.splitn(3, ' ').nth(2).map(str::to_owned))
        .collect()
}

/// `vox room read --json --notices`: each row and each notice, in the order printed.
fn read_with_notices(dir: &Path, room: &str) -> Vec<serde_json::Value> {
    let (ok, out, err) = vox(dir, &["room", "read", room, "--json", "--notices"], None);
    assert!(ok, "PRODUCT: vox room read --json --notices: {err}");
    out.lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect()
}

/// The wall clock, milliseconds since the Unix epoch.
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

fn count(texts: &[String], prefix: &str) -> usize {
    texts.iter().filter(|t| t.starts_with(prefix)).count()
}

/// Poll `vox room read` until `done`, or panic naming what it last saw. `what` starts with its
/// side: `PRODUCT:` for a claim, `PRODUCT (staging):` for the scene.
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
        "{what} — not within {secs} s; `vox room read` shows {} rows: {last:?}",
        last.len()
    );
}

/// What a stream of `vox status --json` reads on one node showed while it synced: how many reads
/// listed a room, and the first room listed **without** its retention, keys held, frozen members
/// or refusals below a checkpoint. A sync session holds a room's lock while it runs; a status read
/// must answer for the room anyway, never with a `null` (#58).
struct StatusWatch {
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    handle: std::thread::JoinHandle<(usize, Option<String>)>,
}

impl StatusWatch {
    fn start(dir: &Path) -> Self {
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (dir, flag) = (dir.to_path_buf(), std::sync::Arc::clone(&stop));
        let handle = std::thread::spawn(move || {
            let (mut listed, mut first_null) = (0usize, None);
            while !flag.load(std::sync::atomic::Ordering::Relaxed) && first_null.is_none() {
                let (ok, out, _) = vox(&dir, &["status", "--json"], None);
                let Some(v) = ok
                    .then(|| serde_json::from_str::<serde_json::Value>(&out).ok())
                    .flatten()
                else {
                    continue;
                };
                for room in v["rooms"].as_array().into_iter().flatten() {
                    listed += 1;
                    let whole = room["retention"].is_u64()
                        && room["key_generations"].is_u64()
                        && room["frozen"].is_array()
                        && room["refused_below_checkpoint"].is_u64();
                    if !whole {
                        first_null = Some(room.to_string());
                    }
                }
            }
            (listed, first_null)
        });
        Self { stop, handle }
    }

    fn finish(self) -> (usize, Option<String>) {
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
        self.handle
            .join()
            .expect("APPARATUS: the status watcher thread panicked")
    }
}

/// Where the node at `dir` puts what it pulls from `room` (ADR-028 F-4): `nodes/<node>/files/
/// <room>/`, named by the room's whole id, which `vox room link` carries.
fn files_of(dir: &Path, room: &str) -> PathBuf {
    let (ok, out, err) = vox(dir, &["room", "link", room], None);
    assert!(ok, "PRODUCT (staging): vox room link: {err}");
    let id = out
        .trim()
        .strip_prefix("vox://")
        .and_then(|l| l.split(['?', '/', '@']).next())
        .filter(|id| id.starts_with(room))
        .unwrap_or_else(|| panic!("PRODUCT (staging): no room id in {out:?}"))
        .to_owned();
    dir.join("nodes").join("default").join("files").join(id)
}

/// Poll until `done` holds, for at most `secs`; whether it did.
fn within(secs: u64, done: impl Fn() -> bool) -> bool {
    let deadline = Instant::now() + Duration::from_secs(secs);
    while Instant::now() < deadline {
        if done() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    done()
}

fn post(dir: &Path, room: &str, text: &str) {
    let (ok, _, err) = vox(dir, &["room", "post", room, text], None);
    assert!(ok, "PRODUCT (staging): vox room post {text:?}: {err}");
}

/// Two identities that trust each other, as fresh profiles.
fn pair(tmp: &Path) -> (PathBuf, PathBuf) {
    let a = tmp.join("a");
    let b = tmp.join("b");
    for d in [&a, &b] {
        std::fs::create_dir_all(d.join("cfg")).expect("APPARATUS: a profile directory");
    }
    let mut fps = Vec::new();
    for dir in [&a, &b] {
        let (ok, out, err) = vox(dir, &["id"], None);
        assert!(ok, "PRODUCT (staging): vox id: {err}");
        fps.push(out.trim().to_owned());
    }
    for (dir, fp) in [(&a, &fps[1]), (&b, &fps[0])] {
        let (ok, _, err) = attach::Root::at(dir, IDENTITY).ensure("default", || {
            vox(dir, &["trust", "add", fp, "--name", "peer"], None)
        });
        assert!(ok, "PRODUCT (staging): vox trust add: {err}");
    }
    (a, b)
}

/// `creator` makes a room, `joiner` joins it; returns the room id as `vox` prints it.
fn room(creator: &Path, joiner: &Path) -> String {
    let (ok, _, err) = vox(
        creator,
        &["room", "create", "--passphrase-file", "-", "--name", "r"],
        Some(&format!("{ROOMPASS}\n")),
    );
    assert!(ok, "PRODUCT (staging): vox room create: {err}");
    let room = attached(creator, "creator")
        .split_whitespace()
        .next()
        .expect("PRODUCT (staging): a room id in `vox room list`")
        .to_owned();
    let (ok, link, err) = vox(creator, &["room", "link", &room], None);
    assert!(ok, "PRODUCT (staging): vox room link: {err}");
    let (ok, _, err) = vox(
        joiner,
        &["room", "join", "--passphrase-file", "-", link.trim()],
        Some(&format!("{ROOMPASS}\n")),
    );
    assert!(ok, "PRODUCT (staging): vox room join: {err}");
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
            "PRODUCT (staging): the joiner never read the creator's probe within 90 s"
        );
    }
    room
}

#[test]
#[ignore = "real vox daemons and real seconds (about two minutes); CI runs it in release"]
fn shortening_a_rooms_retention_removes_older_messages_on_every_member() {
    watchdog::arm();
    let tmp = tempfile::tempdir().expect("APPARATUS: a temporary directory");
    let (alice, bob) = pair(tmp.path());
    // bob's node keeps a week: longer than the room will. A node may keep less than its room,
    // never more, so bob must still follow the room's 30 s below (PRD-001 R9).
    std::fs::write(bob.join("cfg").join("retention"), "default 1w\n")
        .expect("APPARATUS: bob's node retention file");
    let alice_d = daemon(&alice, "alice", &format!("{IDENTITY}\n"));
    attached(&alice, "alice");
    let bob_d = daemon(&bob, "bob", &format!("{IDENTITY}\n"));
    attached(&bob, "bob");
    let room = room(&alice, &bob);

    // ---- 40 messages, then a pause longer than the retention to come ------------------------
    for i in 1..=40 {
        post(&alice, &room, &format!("old {i}"));
    }
    until(
        &bob,
        &room,
        "PRODUCT (staging): bob to read the 40",
        60,
        |t| count(t, "old ") == 40,
    );
    let old_done = Instant::now();
    std::thread::sleep(Duration::from_secs(45));

    // ---- 60 more, then 30 s retention: the 40 are 45 s old, the 60 a few seconds ------------
    // bob's `vox status --json`, read over and over while these 60 sync to him: every read that
    // lists the room must name its retention and the rest, sessions or not (#58).
    let watch = StatusWatch::start(&bob);
    for i in 1..=60 {
        post(&alice, &room, &format!("new {i}"));
    }
    until(
        &bob,
        &room,
        "PRODUCT (staging): bob to read all 100",
        60,
        |t| count(t, "old ") + count(t, "new ") == 100,
    );
    let (listed, first_null) = watch.finish();
    println!(
        "bob's `vox status --json` while the 60 synced: {listed} room readings; first blank: \
         {first_null:?}"
    );
    assert!(
        first_null.is_none(),
        "PRODUCT: bob's `vox status --json`, read while the room synced, listed the room with a \
         blank (null) retention, keys held, frozen members or refusals: {}",
        first_null.unwrap_or_default()
    );
    assert!(
        listed > 0,
        "PRODUCT (staging): bob's `vox status --json` never listed the room while it synced"
    );
    // **A retention change asks for no passphrase** (ADR-028 K-11, #555): with no passphrase
    // source set and no terminal, a member who is not an admin is told the room's is not theirs
    // to change, and the creator's change is made.
    let (ok, out, err) = vox_with(&bob, &["room", "retention", &room, "forever"], None, None);
    println!("bob, no passphrase anywhere: {}", out.trim());
    assert!(
        ok && out.contains("only its creator or an admin changes that"),
        "PRODUCT: bob, not an admin, asking with no passphrase source must be told only the \
         creator or an admin changes the room's retention (ADR-028 K-11: no passphrase is \
         asked for); succeeded {ok}, said:\n{out}{err}"
    );
    // **A retention change made just after a post, in the same second, is shown after it, with a
    // time in milliseconds** (the decider, 2026-10-07: all time in milliseconds; #441). Each try
    // starts just after a second turns, so the post and the change land in one second; a try
    // that straddles a second is retried, and three that all do are APPARATUS.
    let mut same = None;
    for (i, ttl) in ["32", "31", "33"].into_iter().enumerate() {
        let into = now_ms() % 1_000;
        std::thread::sleep(Duration::from_millis(1_000 - into + 20));
        let text = format!("same-second {i}");
        post(&alice, &room, &text);
        let (ok, out, err) = vox_with(&alice, &["room", "retention", &room, ttl], None, None);
        assert!(
            ok,
            "PRODUCT (staging): alice's `vox room retention {ttl}`: {out}{err}"
        );
        let rows = read_with_notices(&alice, &room);
        let at = |pick: &dyn Fn(&serde_json::Value) -> bool| {
            rows.iter()
                .enumerate()
                .filter(|(_, r)| pick(r))
                .last()
                .map(|(i, r)| (i, r["created_millis"].as_u64().unwrap_or(0)))
        };
        let posted = at(&|r| r["text"].as_str() == Some(text.as_str()));
        let changed = at(&|r| {
            r["schema"] == "vox.room.notice/1"
                && r["notice"]
                    .as_str()
                    .is_some_and(|n| n.contains("set the room's retention"))
        });
        let (Some(posted), Some(changed)) = (posted, changed) else {
            panic!(
                "PRODUCT: `vox room read --json --notices` must give alice's post {text:?} and                  her retention change; it gave:\n{rows:#?}"
            );
        };
        if posted.1 / 1_000 == changed.1 / 1_000 {
            same = Some((rows, text, posted, changed));
            break;
        }
    }
    let Some((rows, text, posted, changed)) = same else {
        panic!(
            "APPARATUS (precondition unmet): in three tries alice's post and her retention change              never landed in the same second"
        );
    };
    println!(
        "same second: {text:?} at {} ms (row {}), the retention change at {} ms (row {})",
        posted.1, posted.0, changed.1, changed.0
    );
    assert!(
        changed.0 > posted.0 && changed.1 >= posted.1,
        "PRODUCT: a retention change made just after a post, in the same second, must be read \
         after it, with a time in milliseconds no earlier than the post's: the post {text:?} is \
         row {} at {} ms, the change row {} at {} ms:\n{rows:#?}",
        posted.0,
        posted.1,
        changed.0,
        changed.1
    );
    let (ok, out, err) = vox_with(&alice, &["room", "retention", &room, "30"], None, None);
    assert!(
        ok,
        "PRODUCT: the creator's `vox room retention 30`, with no passphrase source and no \
         terminal, must be made: a retention change asks for no passphrase (ADR-028 K-11): \
         {out}{err}"
    );
    println!("{}", out.trim());
    let set_at = Instant::now();

    for (dir, who) in [(&alice, "alice"), (&bob, "bob")] {
        let what = if who == "bob" {
            "PRODUCT: bob, whose node would keep a week, must still follow the room's 30 s and show \
             only the 60 newer"
                .to_owned()
        } else {
            format!("PRODUCT: {who} must show only the 60 newer once the room keeps 30 s")
        };
        until(dir, &room, &what, 20, |t| {
            count(t, "old ") == 0 && count(t, "new ") == 60 && count(t, "probe") == 0
        });
        println!(
            "{who}: `room read` shows 60 of 100 ({} s after the retention was set; the 40 were \
             {} s old)",
            set_at.elapsed().as_secs(),
            old_done.elapsed().as_secs()
        );
    }
    // Both stopped before the 60 reach 30 s, so the restart below reopens a room that holds
    // pruned entries next to live ones.
    drop(alice_d);
    drop(bob_d);

    // ---- a restart still opens the room, and the 60 then go too ------------------------------
    let _alice_d = daemon(&alice, "alice-2", &format!("{IDENTITY}\n{ROOMPASS}\n"));
    let listed = attached(&alice, "alice");
    println!("after the restart: `room list` says {listed:?}");
    assert!(
        !listed.contains("[closed]"),
        "PRODUCT: a room holding pruned entries must reopen: {listed:?}\nalice's daemon said: {}",
        std::fs::read_to_string(alice.join("daemon-alice-2.err")).unwrap_or_default()
    );
    until(
        &alice,
        &room,
        "PRODUCT: the 60 must expire as well once they pass 30 s",
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
    let tmp = tempfile::tempdir().expect("APPARATUS: a temporary directory");
    let (bob, alice) = pair(tmp.path());
    // Alice's node keeps a minute, whatever the room says.
    std::fs::write(alice.join("cfg").join("retention"), "default 60\n")
        .expect("APPARATUS: alice's node retention file");
    // Each on a port of its own choosing, kept so both can be restarted on it below and still find
    // each other.
    let bob_d = daemon(&bob, "bob", &format!("{IDENTITY}\n"));
    attached(&bob, "bob");
    let bob_at = listening(&bob);
    let alice_d = daemon(&alice, "alice", &format!("{IDENTITY}\n"));
    attached(&alice, "alice");
    let alice_at = listening(&alice);
    let room = room(&bob, &alice);
    let (ok, out, err) = vox(&bob, &["room", "retention", &room, "1w"], None);
    assert!(ok, "PRODUCT (staging): vox room retention 1w: {err}");
    println!("{}", out.trim());

    // ---- F-5: a share ends with its message, on the node that keeps a minute ---------------
    // Each shares a file with the room, and each node pulls the other's by itself (F-3).
    let mut shared = Vec::new();
    for (dir, who) in [(&bob, "bob"), (&alice, "alice")] {
        let file = tmp.path().join(format!("from-{who}.txt"));
        std::fs::write(&file, format!("{who}'s file, for the room"))
            .expect("APPARATUS: the file to share");
        let (ok, out, err) = vox(dir, &["share", &room, file.to_str().unwrap()], None);
        assert!(ok, "PRODUCT (staging): {who}'s vox share: {out}{err}");
        shared.push(file);
    }
    let shared_at = Instant::now();
    let alice_copy = files_of(&alice, &room).join("from-bob.txt");
    let bob_copy = files_of(&bob, &room).join("from-alice.txt");
    assert!(
        within(60, || alice_copy.exists() && bob_copy.exists()),
        "PRODUCT (staging): each node must pull the other's share by itself within 60 s: alice's \
         copy {} exists {}, bob's {} exists {}",
        alice_copy.display(),
        alice_copy.exists(),
        bob_copy.display(),
        bob_copy.exists()
    );

    // ---- proof 4: the node prunes at its minute; the other member keeps the week ----------
    for i in 1..=10 {
        post(&bob, &room, &format!("early {i}"));
    }
    let posted = Instant::now();
    until(
        &alice,
        &room,
        "PRODUCT (staging): alice to read the 10",
        60,
        |t| count(t, "early ") == 10,
    );
    until(
        &alice,
        &room,
        "PRODUCT: alice's node keeps a minute, so the 10 must leave her view at her minute",
        90,
        |t| count(t, "early ") == 0,
    );
    let gone = posted.elapsed().as_secs();
    let bob_keeps = count(&read(&bob, &room), "early ");
    println!("alice shows 0 of 10 after {gone} s; bob (a week) still shows {bob_keeps}");
    assert!(
        gone >= 55,
        "PRODUCT: alice pruned at {gone} s, before her minute"
    );
    assert_eq!(
        bob_keeps, 10,
        "PRODUCT: the room keeps a week: bob must still show all 10"
    );

    // **F-5 on the node that keeps a minute**: its copy of bob's share goes with the message, and
    // the share it made stops being served, so bob, whose node keeps the announcement a week, is
    // told the offer is gone. bob's own copy of it stays: his message has not expired.
    let copy_gone = within(20, || !alice_copy.exists());
    let copy_age = shared_at.elapsed().as_secs();
    let stopped = within(20, || {
        let (_, out, _) = vox(&alice, &["share", "list", &room], None);
        !out.contains("from-alice.txt")
    });
    let elsewhere = tmp.path().join("bob-get");
    let (get_ok, get_out, get_err) = vox(
        &bob,
        &[
            "room",
            "get",
            &room,
            "from-alice.txt",
            "--dir",
            elsewhere.to_str().unwrap(),
        ],
        None,
    );
    let get_said = format!("{get_out}{get_err}");
    println!(
        "F-5: alice's copy of bob's share gone {copy_gone} ({copy_age} s after it was shared); \
         alice stopped serving hers {stopped}; bob's get of it (ok {get_ok}): {}; bob's own copy \
         still there {}",
        get_said.trim(),
        bob_copy.exists()
    );
    assert!(
        copy_gone,
        "PRODUCT: alice's node keeps a minute, so its pulled copy of bob's share must be deleted \
         with the message: {} is still there {copy_age} s after it was shared",
        alice_copy.display()
    );
    assert!(
        !get_ok && get_said.contains("the offer of from-alice.txt is gone"),
        "PRODUCT: alice's share expired on her node, so she must stop serving it and bob's pull \
         must be told the offer is gone (alice's share list dropped it: {stopped}); bob's \
         `vox room get` said (ok {get_ok}): {}",
        get_said.trim()
    );
    assert!(
        bob_copy.exists(),
        "PRODUCT: bob's node keeps the room's week, so his copy of alice's share must stay: {} is \
         gone",
        bob_copy.display()
    );

    // ---- a late arrival of what is already expired here never shows ---------------------
    //
    // Measured on alice's own event stream, not only by polling `vox room read`: a render the
    // next sweep takes back is visible to a poll for under a second, which a poll can miss, but
    // the node announces every row a sync renders (`Synced { rendered }`) and that cannot be
    // taken back. So bob is down while alice comes back, the test subscribes to alice's
    // control socket, and only then does bob return and deliver.
    drop(alice_d);
    for i in 1..=5 {
        post(&bob, &room, &format!("late {i}"));
    }
    drop(bob_d);
    std::thread::sleep(Duration::from_secs(65));
    let _alice_d = daemon_on(
        &alice,
        "alice-2",
        &format!("{IDENTITY}\n{ROOMPASS}\n"),
        &alice_at,
    );
    attached(&alice, "alice");
    // **The node's own retention is in force from the moment the room opens**, before any tick
    // or session can reach it: the first reading `vox status` can give is already 60 s. Left
    // to the sweep, a room a session got to first was judged by the room's week alone.
    let first = {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            // The room may still be reopening, which lists no room yet; once it is listed it must
            // name its retention, also while a session holds it (#58).
            let (ok, out, err) = vox(&alice, &["status", "--json"], None);
            assert!(ok, "PRODUCT: alice's `vox status --json` failed: {err}");
            let v: serde_json::Value = serde_json::from_str(&out).unwrap_or_else(|e| {
                panic!("PRODUCT: alice's `vox status --json` did not parse ({e}): {out}")
            });
            if let Some(room) = v["rooms"].get(0) {
                break room["retention"].as_u64().unwrap_or_else(|| {
                    panic!(
                        "PRODUCT: alice's `vox status --json` lists her reopened room with no \
                         retention: {room}"
                    )
                });
            }
            assert!(
                Instant::now() < deadline,
                "PRODUCT (staging): alice's `vox status --json` listed no room within 30 s of her \
                 restart"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    };
    println!("alice reopened: the first retention her status reports is {first} s");
    assert_eq!(
        first, 60,
        "PRODUCT: a reopened room must carry the node's own retention from the start, not the \
         room's"
    );
    let sock = vox_core::node::paths::Paths::resolve(
        "default",
        Some(alice.as_path()),
        Some(&alice.join("cfg")),
    )
    .expect("APPARATUS: alice's profile paths");
    let rendered = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    {
        let rendered = std::sync::Arc::clone(&rendered);
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("APPARATUS: the subscriber's runtime");
            rt.block_on(async move {
                let mut client = attach::paths_client(&sock).await.unwrap_or_else(|e| {
                    panic!("PRODUCT (staging): alice's node refused the subscriber: {e}")
                });
                client.subscribe().await.unwrap_or_else(|e| {
                    panic!("PRODUCT (staging): alice's node refused the event subscription: {e}")
                });
                let _ = ready_tx.send(());
                while let Ok(Some(frame)) = client.next().await {
                    if let vox_core::node::ipc::Frame::Event(
                        vox_core::node::api::NodeEvent::Synced { rendered: n, .. },
                    ) = frame
                    {
                        rendered.fetch_add(n, std::sync::atomic::Ordering::SeqCst);
                    }
                }
            });
        });
    }
    ready_rx
        .recv_timeout(Duration::from_secs(30))
        .expect("PRODUCT (staging): the subscription to alice's events was not confirmed in 30 s");
    let _bob_d = daemon_on(&bob, "bob-2", &format!("{IDENTITY}\n{ROOMPASS}\n"), &bob_at);
    attached(&bob, "bob");
    post(&bob, &room, "fresh");
    // `fresh` follows the five in bob's feed, so once alice shows it she holds all of them.
    let deadline = Instant::now() + Duration::from_secs(90);
    let (mut polls, mut late_seen) = (0usize, 0usize);
    let mut fresh = false;
    while Instant::now() < deadline && !fresh {
        let t = read(&alice, &room);
        polls += 1;
        late_seen = late_seen.max(count(&t, "late "));
        fresh = t.iter().any(|x| x == "fresh");
    }
    std::thread::sleep(Duration::from_secs(2)); // let the last event land
    let announced = rendered.load(std::sync::atomic::Ordering::SeqCst);
    println!(
        "alice: `fresh` shown {fresh}; the 5 late ones shown at most {late_seen} times over \
         {polls} reads; rows her syncs announced as rendered: {announced} (only `fresh` may be)"
    );
    assert!(
        fresh,
        "PRODUCT (staging): alice never showed bob's `fresh` within 90 s, so she never caught up \
         with his feed"
    );
    assert_eq!(
        late_seen, 0,
        "PRODUCT: a message that arrives already expired must never be shown"
    );
    assert_eq!(
        announced, 1,
        "PRODUCT: a message that arrives already expired must never be rendered: alice's syncs \
         rendered {announced} rows where only `fresh` was live"
    );
}

#[test]
#[ignore = "real vox daemons and real seconds (about two minutes); CI runs it in release"]
fn a_member_who_joins_after_messages_expired_catches_up() {
    watchdog::arm();
    let tmp = tempfile::tempdir().expect("APPARATUS: a temporary directory");
    let (alice, bob) = pair(tmp.path());
    let _alice_d = daemon(&alice, "alice", &format!("{IDENTITY}\n"));
    attached(&alice, "alice");
    let _bob_d = daemon(&bob, "bob", &format!("{IDENTITY}\n"));
    attached(&bob, "bob");
    let room = room(&alice, &bob);
    let (ok, out, err) = vox(&alice, &["room", "retention", &room, "30"], None);
    assert!(ok, "PRODUCT (staging): vox room retention 30: {err}");
    println!("{}", out.trim());

    // ---- ten messages expire on both members: what is left of them anywhere is a skeleton ----
    for i in 1..=10 {
        post(&alice, &room, &format!("old {i}"));
    }
    until(
        &bob,
        &room,
        "PRODUCT (staging): bob to read the 10",
        60,
        |t| count(t, "old ") == 10,
    );
    let posted = Instant::now();
    for (dir, who) in [(&alice, "alice"), (&bob, "bob")] {
        until(
            dir,
            &room,
            &format!("PRODUCT (staging): {who} to expire the 10"),
            90,
            |t| count(t, "old ") == 0,
        );
    }
    println!(
        "the 10 expired on alice and bob {} s after they were posted",
        posted.elapsed().as_secs()
    );

    // ---- carol joins late ----------------------------------------------------------------
    let carol = tmp.path().join("c");
    std::fs::create_dir_all(carol.join("cfg")).expect("APPARATUS: carol's profile directory");
    let fp = |dir: &Path| {
        let (ok, out, err) = vox(dir, &["id"], None);
        assert!(ok, "PRODUCT (staging): vox id: {err}");
        out.trim().to_owned()
    };
    let (alice_fp, carol_fp) = (fp(&alice), fp(&carol));
    // A one-shot verb acts on an attached node (ADR-026 L-2): carol's daemon first.
    let _carol_d = daemon(&carol, "carol", &format!("{IDENTITY}\n"));
    attached(&carol, "carol");
    for (dir, other, name) in [(&alice, &carol_fp, "carol"), (&carol, &alice_fp, "alice")] {
        let (ok, _, err) = vox(dir, &["trust", "add", other, "--name", name], None);
        assert!(ok, "PRODUCT (staging): vox trust add {name}: {err}");
    }
    let (ok, link, err) = vox(&alice, &["room", "link", &room], None);
    assert!(ok, "PRODUCT (staging): vox room link: {err}");
    let (ok, _, err) = vox(
        &carol,
        &["room", "join", "--passphrase-file", "-", link.trim()],
        Some(&format!("{ROOMPASS}\n")),
    );
    assert!(ok, "PRODUCT (staging): carol's late join failed: {err}");
    let joined = Instant::now();

    // ---- she reaches the author's next post, past the skeletons --------------------------
    // Alice posts until carol reads one: what a newcomer can read starts when the author's key
    // reaches her, and each post follows the ten in alice's feed.
    let mut n = 0;
    let caught_up = loop {
        n += 1;
        post(&alice, &room, &format!("fresh {n}"));
        std::thread::sleep(Duration::from_millis(500));
        if count(&read(&carol, &room), "fresh ") > 0 {
            break Some(joined.elapsed());
        }
        if joined.elapsed() > LATE_BOUND {
            break None;
        }
    };
    let shown = read(&carol, &room);
    let owed = shown
        .iter()
        .filter(|t| t.as_str() == vox_core::node::api::NOT_RECEIVED_YET)
        .count();
    println!(
        "carol, joined after the 10 expired: reads alice's next post at {caught_up:?} after her \
         join ({n} posted); shows {} of the 10, and {owed} rows as not received yet",
        count(&shown, "old ")
    );
    assert!(
        caught_up.is_some(),
        "PRODUCT: carol never read alice's next post within {LATE_BOUND:?} of joining: a member \
         who joins after messages expired is held at their skeletons. She shows {shown:?}\n\
         carol's daemon said: {}",
        std::fs::read_to_string(carol.join("daemon-carol.err")).unwrap_or_default()
    );
    assert_eq!(
        count(&shown, "old "),
        0,
        "PRODUCT: carol shows messages that expired before she joined"
    );
    assert_eq!(
        owed, 0,
        "PRODUCT: carol shows {owed} expired messages as not received yet: she waits on bodies no \
         member can supply"
    );
}

#[path = "support/optional_proof.rs"]
mod optional_proof;
optional_proof::not_run!(private_session_steps_store_one_body_and_reopen_after_rotation);

#[cfg(feature = "optional-proofs")]
#[path = "../../vox-core/tests/support/raw_sync.rs"]
mod private_raw_sync;

/// The store measurement is of rows actually written by the binary, not a codec
/// benchmark. The same bodies must still be read through the CLI after restarting.
#[cfg(feature = "optional-proofs")]
#[test]
#[ignore = "real private Session authors, driver, restarts and store measurements"]
fn private_session_steps_store_one_body_and_reopen_after_rotation() {
    use redb::{ReadableDatabase, ReadableTable, TableDefinition};
    use vox_core::node::ipc::{Frame, IpcClient, NodeSocket, Request};
    use vox_core::node::paths::{NodeName, Paths};

    watchdog::arm();
    let tmp = tempfile::tempdir().expect("APPARATUS: scratch roots");
    let (a, b) = pair(tmp.path());
    let mut author = Some(daemon(&a, "author", &format!("{IDENTITY}\n")));
    let mut driver = Some(daemon(&b, "driver", &format!("{IDENTITY}\n")));
    attached(&a, "author");
    attached(&b, "driver");
    let (_, author_fp, _) = vox(&a, &["id"], None);
    let (_, driver_fp, _) = vox(&b, &["id"], None);
    let author_fp = author_fp.trim();
    let driver_fp = driver_fp.trim();
    let (ok, out, err) = vox(
        &a,
        &["trust", "add", driver_fp, "--name", "driver", "--drive"],
        None,
    );
    assert!(ok, "PRODUCT (staging): drive grant: {out}{err}");
    let room = room(&a, &b);
    let author_at = listening(&a);
    let driver_at = listening(&b);
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("APPARATUS: runtime");
    let paths = |dir: &Path| {
        Paths::resolve("default", Some(dir), Some(&dir.join("cfg")))
            .expect("APPARATUS: profile paths")
    };
    let request = |dir: &Path, request: Request| {
        let began = Instant::now();
        loop {
            let mut client = rt
                .block_on(IpcClient::open_at(&NodeSocket::one_shot(
                    paths(dir).account().socket(),
                    NodeName::parse("default").unwrap(),
                )))
                .expect("APPARATUS: connect binary socket");
            let frame = rt
                .block_on(client.request(&request))
                .expect("APPARATUS: request binary");
            if !matches!(&frame, Frame::Error { reason }
                if reason.contains("refresh") || reason.contains("permissions are still")
                    || reason.contains("preparing"))
            {
                break frame;
            }
            assert!(
                began.elapsed() < Duration::from_secs(180),
                "APPARATUS: Session publication did not settle: {frame:?}"
            );
            std::thread::sleep(Duration::from_millis(100));
        }
    };
    let Frame::Rooms { rooms } = request(&a, Request::Rooms { after: None }) else {
        panic!("APPARATUS: room listing response");
    };
    let id = rooms.first().expect("APPARATUS: created room").0;
    let session = "rg13-one-body";
    let opening = serde_json::json!({"v":1,"type":"session","from":session,
        "body":"","at":{"session_name":"One body"},"data":{"session":{"harness":"proof"}}})
    .to_string();
    assert!(
        matches!(
            request(
                &a,
                Request::Post {
                    channel_id: id,
                    text: opening,
                    card: false
                }
            ),
            Frame::Ok
        ),
        "PRODUCT (staging): Session opening was not saved"
    );
    let authored = std::cell::RefCell::new(Vec::new());
    let append = |seq: usize, size: usize| {
        let text = format!("ONE-BODY-{seq}-{}", "x".repeat(size));
        let body =
            serde_json::json!({"v":1,"session":session,"kind":"reply","seq":seq,"text":text})
                .to_string();
        let frame = request(
            &a,
            Request::AppendSession {
                channel_id: id,
                session_id: session.into(),
                body: body.clone(),
            },
        );
        assert!(
            matches!(frame, Frame::Appended { .. }),
            "PRODUCT: binary refused step {seq}: {frame:?}"
        );
        if let Frame::Appended { entry } = &frame {
            authored.borrow_mut().push(*entry);
        }
        (body.len(), text)
    };
    let replies = |dir: &Path| {
        let (ok, out, err) = vox(
            dir,
            &["room", "session", &room, session, "--raw", "--json"],
            None,
        );
        if !ok {
            return Err(format!("{out}{err}"));
        }
        Ok(out
            .lines()
            .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
            .filter_map(|row| {
                row["body"]
                    .as_str()
                    .and_then(|body| serde_json::from_str::<serde_json::Value>(body).ok())
            })
            .filter(|body| body["kind"] == "reply")
            .filter_map(|body| body["text"].as_str().map(str::to_owned))
            .collect::<Vec<_>>())
    };
    let wait_replies = |dir: &Path, expected: &[String]| {
        let began = Instant::now();
        loop {
            let shown = replies(dir);
            if shown.as_ref().is_ok_and(|shown| shown == expected) {
                break;
            }
            assert!(
                began.elapsed() < Duration::from_secs(180),
                "PRODUCT: binary did not show the complete Session page: {shown:?}"
            );
            std::thread::sleep(Duration::from_millis(250));
        }
    };
    let store_rows = |tag: &str| {
        let copy = tmp.path().join(format!("{tag}.redb"));
        std::fs::copy(paths(&a).store_file(), &copy).expect("APPARATUS: copy stopped store");
        let db = redb::Database::open(&copy).expect("APPARATUS: open copied store");
        let transaction = db.begin_read().expect("APPARATUS: store snapshot");
        let table = transaction
            .open_table(TableDefinition::<([u8; 32], u8, u64), &[u8]>::new(
                "segments",
            ))
            .expect("APPARATUS: product segment table");
        table
            .iter()
            .expect("APPARATUS: segment rows")
            .map(|row| row.expect("APPARATUS: segment row"))
            .filter_map(|(key, value)| {
                let (room, kind, position) = key.value();
                (room == id && kind == 10).then_some((position, value.value().len()))
            })
            .collect::<std::collections::BTreeMap<_, _>>()
    };
    let (_, warm) = append(0, 64);
    let mut expected = vec![warm];
    wait_replies(&a, &expected);
    wait_replies(&b, &expected);
    drop(author.take());
    let mut previous = store_rows("warm");
    let mut costs = Vec::new();
    for (seq, size) in [(1, 1024), (2, 2048), (3, 3072)] {
        author = Some(daemon_on(
            &a,
            &format!("author-{seq}"),
            &format!("{IDENTITY}\n{ROOMPASS}\n"),
            &author_at,
        ));
        attached(&a, "restarted author");
        wait_replies(&a, &expected);
        let (body, text) = append(seq, size);
        expected.push(text);
        wait_replies(&a, &expected);
        wait_replies(&b, &expected);
        drop(author.take());
        let current = store_rows(&format!("step-{seq}"));
        let added = current
            .iter()
            .filter(|(id, _)| !previous.contains_key(id))
            .collect::<Vec<_>>();
        assert_eq!(
            added.len(),
            1,
            "PRODUCT: one append wrote {} private rows; before={previous:?}, after={current:?}",
            added.len()
        );
        assert!(previous.iter().all(|(id,size)| current.get(id) == Some(size)),
            "PRODUCT: appending rewrote an earlier private row: before={previous:?}, after={current:?}");
        costs.push((body, *added[0].1));
        previous = current;
    }
    eprintln!("PRODUCT STORE RECEIPT: (body bytes, sealed row bytes)={costs:?}");
    // Check the slope first so the base's RED names the reproduced duplicate body.
    for pair in costs.windows(2) {
        assert_eq!(
            pair[1].1 - pair[0].1,
            pair[1].0 - pair[0].0,
            "PRODUCT: stored step grew by {} bytes for {} body bytes: {costs:?}",
            pair[1].1 - pair[0].1,
            pair[1].0 - pair[0].0
        );
    }
    for (body, stored) in costs {
        assert!(
            stored < body + 4500,
            "PRODUCT: step still pays for two 3373-byte signatures: body={body}, stored={stored}"
        );
    }
    author = Some(daemon_on(
        &a,
        "author-final",
        &format!("{IDENTITY}\n{ROOMPASS}\n"),
        &author_at,
    ));
    attached(&a, "author-final");
    wait_replies(&a, &expected);
    drop(driver.take());
    driver = Some(daemon_on(
        &b,
        "driver-restart",
        &format!("{IDENTITY}\n{ROOMPASS}\n"),
        &driver_at,
    ));
    attached(&b, "driver-restart");
    wait_replies(&b, &expected);
    for dir in [&a, &b] {
        let mut pages = Vec::new();
        let mut before = None;
        loop {
            let frame = request(
                dir,
                Request::SessionPage {
                    channel_id: id,
                    which: vox_core::node::drive::SessionFilter::Session(session.into()),
                    before,
                    limit: 2,
                },
            );
            let Frame::SessionPage { rows, older, .. } = frame else {
                panic!("PRODUCT: binary refused an older Session page: {frame:?}");
            };
            assert!(
                !rows.is_empty(),
                "PRODUCT: binary returned an empty Session page with rows owed"
            );
            before = rows.first().map(|row| row.entry_hash);
            pages.push(
                rows.into_iter()
                    .filter_map(|row| {
                        let body: serde_json::Value = serde_json::from_str(&row.body).ok()?;
                        (body["kind"] == "reply").then(|| body["text"].as_str().unwrap().to_owned())
                    })
                    .collect::<Vec<_>>(),
            );
            if older == 0 {
                break;
            }
        }
        assert!(
            pages.len() > 1,
            "APPARATUS: older-page boundary was not reached"
        );
        let shown = pages.into_iter().rev().flatten().collect::<Vec<_>>();
        assert_eq!(
            shown, expected,
            "PRODUCT: complete older pages differ after restart"
        );
    }

    // An actual member's stopped profile supplies the apparatus identity and the
    // exact next ciphertexts. Only the running recipient decides acceptance.
    drop(driver.take());
    let pending = (4..9).map(|seq| append(seq, 256).1).collect::<Vec<_>>();
    drop(author.take());
    {
        use vox_core::atrest::idfactor::SignatureIdentityFactor;
        use vox_core::atrest::store::{open_segment, SegmentKind};
        use vox_core::cbor::{Decoder, Encoder};
        use vox_core::group::message::MessageHeader;
        use vox_core::node::profile::Profile;
        use vox_core::transport::framing::{read_frame, write_frame};
        use vox_core::transport::quic::VoxEndpoint;
        use vox_core::transport::streams::{accept_typed, StreamKind};

        let mut profile = Profile::open(paths(&a)).expect("APPARATUS: stopped author profile");
        profile
            .unlock(IDENTITY.as_bytes())
            .expect("APPARATUS: unlock stopped author");
        let signer = profile.signer_arc().expect("APPARATUS: author identity");
        let sek = profile
            .store()
            .get_sek_wrap(&id)
            .unwrap()
            .unwrap()
            .unwrap_sek(
                &SignatureIdentityFactor::new(&*signer),
                &id,
                ROOMPASS.as_bytes(),
            )
            .expect("APPARATUS: author room key");
        let mut wires = profile
            .store()
            .segments(&id, SegmentKind::PrivateSession)
            .unwrap()
            .into_iter()
            .map(|(position, sealed)| {
                let bytes = open_segment(&sek, SegmentKind::PrivateSession, position, &sealed)
                    .expect("APPARATUS: accepted author row opens");
                let mut d = Decoder::new(&bytes);
                d.array().unwrap();
                d.uint().unwrap();
                (position, d.bytes().unwrap().to_vec())
            })
            .collect::<Vec<_>>();
        wires.sort_by_key(|(position, _)| *position);
        let wires = wires
            .into_iter()
            .rev()
            .take(5)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .map(|(_, wire)| wire)
            .collect::<Vec<_>>();
        assert_eq!(wires.len(), 5, "APPARATUS: five withheld steps");
        driver = Some(daemon_on(
            &b,
            "tamper-driver",
            &format!("{IDENTITY}\n{ROOMPASS}\n"),
            &driver_at,
        ));
        attached(&b, "tamper-driver");
        let victim_at = listening(&b)
            .parse()
            .expect("APPARATUS: driver listen address");
        let (_, fingerprint, _) = vox(&b, &["id"], None);
        let victim = vox_core::node::link::b32_decode(fingerprint.trim(), "driver identity")
            .expect("APPARATUS: driver fingerprint");
        let attack_rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("APPARATUS: wire peer runtime");
        let endpoint = attack_rt.block_on(async {
            VoxEndpoint::bind(signer, "127.0.0.1:0".parse().unwrap())
                .expect("APPARATUS: authenticated wire peer")
        });
        let conn = std::sync::Arc::new(
            attack_rt
                .block_on(endpoint.connect(victim_at, victim, now_ms()))
                .expect("APPARATUS: connect author wire peer"),
        );
        let (asked, asks) = std::sync::mpsc::channel();
        let (responses, mut response_rx) = tokio::sync::mpsc::unbounded_channel::<(u64, Vec<u8>)>();
        let serving = attack_rt.spawn(async move {
            while let Ok((kind, send, mut recv)) = accept_typed(&conn).await {
                if kind == StreamKind::Session {
                    let bytes = read_frame(&mut recv, 4096).await.unwrap().unwrap();
                    let mut d = Decoder::new(&bytes);
                    assert_eq!(d.array().unwrap(), 6, "APPARATUS: Session ask");
                    assert_eq!(d.uint().unwrap(), 2, "APPARATUS: Session ask version");
                    d.bytes().unwrap();
                    d.uint().unwrap();
                    let incarnation = d.bytes().unwrap().to_vec();
                    let after = d.uint().unwrap();
                    // No archive fixture or invented cursor: every verdict is on
                    // an ordinary live pull from this authenticated real member.
                    assert_eq!(d.array().unwrap(), 1, "APPARATUS: live query");
                    assert_eq!(d.uint().unwrap(), 0, "APPARATUS: live query kind");
                    d.finish().unwrap();
                    asked.send((incarnation, after)).unwrap();
                    let Some((position, wire)) = response_rx.recv().await else {
                        break;
                    };
                    let mut e = Encoder::new();
                    e.array(6)
                        .uint(2)
                        .bytes(&[42; 32])
                        .uint(position)
                        .uint(0)
                        .array(1)
                        .array(2)
                        .uint(position)
                        .bytes(&wire)
                        .array(0);
                    let mut send = send;
                    write_frame(&mut send, &e.finish()).await.unwrap();
                    send.finish().unwrap();
                } else {
                    // The room's existing public sync continues independently.
                    tokio::spawn(async move {
                        let Ok((_room, _epoch)) =
                            vox_core::node::syncstream::read_sync_request(&mut recv).await
                        else {
                            return;
                        };
                        let transport = vox_core::node::syncstream::accept_sync(
                            tokio::runtime::Handle::current(),
                            send,
                            recv,
                        );
                        let _ = tokio::task::spawn_blocking(move || {
                            private_raw_sync::session(
                                transport,
                                &private_raw_sync::Ask::Everything,
                                None,
                            )
                        })
                        .await;
                    });
                }
            }
        });
        let mut position = 0;
        let _ = asks
            .recv_timeout(Duration::from_secs(90))
            .expect("APPARATUS: recipient did not ask authenticated peer");
        for (arm, (wire, text)) in ["root-signature", "header", "room", "author", "ciphertext"]
            .into_iter()
            .zip(wires.into_iter().zip(pending))
        {
            let mut d = Decoder::new(&wire);
            assert_eq!(d.array().unwrap(), 4, "APPARATUS: private envelope");
            let version = d.uint().unwrap();
            assert_eq!(
                version, 3,
                "PRODUCT: new steps did not use one-signature envelope"
            );
            let mut room_bytes = d.bytes().unwrap().to_vec();
            let message = d.bytes().unwrap();
            let mut signature = d.bytes().unwrap().to_vec();
            d.finish().unwrap();
            let mut m = Decoder::new(message);
            assert_eq!(
                m.array().unwrap(),
                2,
                "PRODUCT: private envelope retained inner signature"
            );
            let mut header = MessageHeader::from_canonical_body(m.bytes().unwrap()).unwrap();
            let mut ciphertext = m.bytes().unwrap().to_vec();
            m.finish().unwrap();
            match arm {
                "header" => header.iteration += 1,
                "room" => room_bytes[0] ^= 1,
                "author" => header.author_id = victim,
                "ciphertext" => ciphertext[0] ^= 1,
                "root-signature" => signature[0] ^= 1,
                _ => unreachable!(),
            }
            let mut m = Encoder::new();
            m.array(2)
                .bytes(&header.canonical_body())
                .bytes(&ciphertext);
            let mut e = Encoder::new();
            e.array(4)
                .uint(version)
                .bytes(&room_bytes)
                .bytes(&m.finish())
                .bytes(&signature);
            position += 1;
            responses.send((position, e.finish())).unwrap();
            let (incarnation, after) = asks
                .recv_timeout(Duration::from_secs(90))
                .expect("APPARATUS: recipient did not finish its tampered-page decision");
            assert_eq!(
                (incarnation, after),
                (vec![42; 32], position),
                "APPARATUS: recipient has not decided the supplied tampered row"
            );
            assert!(
                !replies(&b).unwrap_or_default().contains(&text),
                "PRODUCT: recipient showed the {arm}-tampered step: {:?}",
                replies(&b)
            );
            position += 1;
            responses.send((position, wire)).unwrap();
            expected.push(text);
            wait_replies(&b, &expected);
            eprintln!(
                "PRODUCT TAMPER RECEIPT: {arm} refused; original same-iteration step read whole"
            );
            let _ = asks
                .recv_timeout(Duration::from_secs(90))
                .expect("APPARATUS: recipient did not request next live page");
        }
        drop(responses);
        serving.abort();
        drop((endpoint, attack_rt, profile));
    }
    author = Some(daemon_on(
        &a,
        "after-tamper",
        &format!("{IDENTITY}\n{ROOMPASS}\n"),
        &author_at,
    ));
    attached(&a, "after-tamper");
    wait_replies(&a, &expected);
    let (ok, out, err) = vox(&a, &["trust", "read", driver_fp], None);
    assert!(ok, "PRODUCT (staging): drive withdrawal: {out}{err}");
    let (_, post_rotation) = append(9, 1024);
    expected.push(post_rotation);
    wait_replies(&a, &expected);
    drop(author.take());
    author = Some(daemon_on(
        &a,
        "past-generation",
        &format!("{IDENTITY}\n{ROOMPASS}\n"),
        &author_at,
    ));
    attached(&a, "past-generation");
    wait_replies(&a, &expected);
    drop(author.take());
    {
        use vox_core::atrest::idfactor::SignatureIdentityFactor;
        use vox_core::atrest::store::{open_segment, seal_segment, SegmentKind};
        use vox_core::cbor::{Decoder, Encoder};
        use vox_core::node::profile::Profile;
        let mut profile = Profile::open(paths(&a)).expect("APPARATUS: stopped corruption target");
        profile.unlock(IDENTITY.as_bytes()).unwrap();
        let signer = profile.signer_arc().unwrap();
        let sek = profile
            .store()
            .get_sek_wrap(&id)
            .unwrap()
            .unwrap()
            .unwrap_sek(
                &SignatureIdentityFactor::new(&*signer),
                &id,
                ROOMPASS.as_bytes(),
            )
            .unwrap();
        let (position, sealed) = profile
            .store()
            .segments(&id, SegmentKind::PrivateSession)
            .unwrap()
            .into_iter()
            .find(|(position, sealed)| {
                let bytes =
                    open_segment(&sek, SegmentKind::PrivateSession, *position, sealed).unwrap();
                let mut d = Decoder::new(&bytes);
                d.array().unwrap();
                d.uint().unwrap();
                vox_core::hash::sha256(d.bytes().unwrap()) == authored.borrow()[1]
            })
            .expect("APPARATUS: step chosen for damaged opener");
        let bytes = open_segment(&sek, SegmentKind::PrivateSession, position, &sealed).unwrap();
        let mut d = Decoder::new(&bytes);
        assert_eq!(
            (d.array().unwrap(), d.uint().unwrap()),
            (8, 3),
            "PRODUCT: new stored row has no versioned opener"
        );
        let wire = d.bytes().unwrap();
        let metadata = d.bytes().unwrap();
        let seen = d.uint().unwrap();
        let instance = d.bytes().unwrap();
        let arrival = d.uint().unwrap();
        let identity = d.bytes().unwrap();
        let mut key = d.bytes().unwrap().to_vec();
        d.finish().unwrap();
        key[0] ^= 1;
        let mut e = Encoder::new();
        e.array(8)
            .uint(3)
            .bytes(wire)
            .bytes(metadata)
            .uint(seen)
            .bytes(instance)
            .uint(arrival)
            .bytes(identity)
            .bytes(&key);
        let damaged =
            seal_segment(&sek, SegmentKind::PrivateSession, position, &e.finish()).unwrap();
        profile
            .store()
            .put_segment(&id, SegmentKind::PrivateSession, position, &damaged)
            .unwrap();
    }
    author = Some(daemon_on(
        &a,
        "damaged-opener",
        &format!("{IDENTITY}\n{ROOMPASS}\n"),
        &author_at,
    ));
    attached(&a, "damaged-opener");
    let began = Instant::now();
    loop {
        let shown = vox(&a, &["room", "session", &room, session, "--json"], None);
        if shown.0 && shown.1.contains("could not be opened") && shown.1.contains("ONE-BODY-9-") {
            break;
        }
        assert!(
            began.elapsed() < Duration::from_secs(180),
            "PRODUCT: unreadable step hid the rest of its page instead of saying why: {shown:?}"
        );
        std::thread::sleep(Duration::from_millis(250));
    }
    post(&a, &room, "AFTER-DRIVE-WITHDRAWAL");
    until(
        &b,
        &room,
        "PRODUCT: read-only member still receives chat",
        90,
        |texts| texts.iter().any(|s| s == "AFTER-DRIVE-WITHDRAWAL"),
    );
    let listing = vox(&b, &["room", "sessions", &room, "--json"], None);
    assert!(
        !listing
            .1
            .lines()
            .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
            .any(|row| row["id"] == session && row["can_drive"] == true)
            && replies(&b).is_err(),
        "PRODUCT: read-only member still reads the withdrawn Session: {listing:?}; {:?}",
        replies(&b)
    );
    let own_session = "rg13-driver-own";
    let opening = serde_json::json!({"v":1,"type":"session","from":own_session,
        "body":"","at":{"session_name":"Driver own"},"data":{"session":{"harness":"proof"}}})
    .to_string();
    assert!(
        matches!(
            request(
                &b,
                Request::Post {
                    channel_id: id,
                    text: opening,
                    card: false
                }
            ),
            Frame::Ok
        ),
        "PRODUCT (staging): driver's own Session did not open"
    );
    let own_body = serde_json::json!({"v":1,"session":own_session,"kind":"reply","seq":1,
        "text":"DRIVER-OWN-SURVIVES-REMOVAL"})
    .to_string();
    assert!(
        matches!(
            request(
                &b,
                Request::AppendSession {
                    channel_id: id,
                    session_id: own_session.into(),
                    body: own_body
                }
            ),
            Frame::Appended { .. }
        ),
        "PRODUCT (staging): driver's own append failed"
    );
    let (ok, out, err) = vox(&b, &["trust", "remove", author_fp], None);
    assert!(
        ok,
        "PRODUCT (staging): removing author trust failed: {out}{err}"
    );
    drop(driver.take());
    driver = Some(daemon_on(
        &b,
        "removed-author",
        &format!("{IDENTITY}\n{ROOMPASS}\n"),
        &driver_at,
    ));
    attached(&b, "removed-author");
    let began = Instant::now();
    loop {
        let shown = vox(&b, &["room", "session", &room, own_session, "--json"], None);
        if shown.0 && shown.1.contains("DRIVER-OWN-SURVIVES-REMOVAL") {
            break;
        }
        assert!(
            began.elapsed() < Duration::from_secs(180),
            "PRODUCT: deleting another author's receiver broke own Session pages: {shown:?}"
        );
        std::thread::sleep(Duration::from_millis(250));
    }
    assert!(
        replies(&b).is_err(),
        "PRODUCT: removed author's Session became readable"
    );
    let retained_authored = || {
        use vox_core::atrest::idfactor::SignatureIdentityFactor;
        use vox_core::atrest::store::{open_segment, SegmentKind};
        use vox_core::cbor::Decoder;
        use vox_core::node::profile::Profile;
        let mut profile = Profile::open(paths(&b)).expect("APPARATUS: stopped driver profile");
        profile
            .unlock(IDENTITY.as_bytes())
            .expect("APPARATUS: driver unlock");
        let signer = profile.signer_arc().unwrap();
        let sek = profile
            .store()
            .get_sek_wrap(&id)
            .unwrap()
            .unwrap()
            .unwrap_sek(
                &SignatureIdentityFactor::new(&*signer),
                &id,
                ROOMPASS.as_bytes(),
            )
            .unwrap();
        profile
            .store()
            .segments(&id, SegmentKind::PrivateSession)
            .unwrap()
            .into_iter()
            .filter(|(position, sealed)| {
                let bytes =
                    open_segment(&sek, SegmentKind::PrivateSession, *position, sealed).unwrap();
                let mut d = Decoder::new(&bytes);
                d.array().unwrap();
                d.uint().unwrap();
                authored
                    .borrow()
                    .contains(&vox_core::hash::sha256(d.bytes().unwrap()))
            })
            .count()
    };
    drop(driver.take());
    assert!(
        retained_authored() > 0,
        "APPARATUS: removal did not leave retained rows to exercise their expiry"
    );
    let mut child = Command::new(VOX)
        .args(["daemon", "--listen", &driver_at])
        .env("VOX_DATA_DIR", &b)
        .env("VOX_CONFIG_DIR", b.join("cfg"))
        .env(
            "VOX_TEST_CLOCK_STEP_MS",
            (8 * 86_400_000u64 + 1).to_string(),
        )
        .env_remove("VOX_NODE")
        .env_remove("VOX_ROOM")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(std::fs::File::create(b.join("expiry.err")).unwrap())
        .spawn()
        .unwrap();
    writeln!(child.stdin.take().unwrap(), "{IDENTITY}\n{ROOMPASS}").unwrap();
    driver = Some(Daemon(child));
    attached(&b, "expiry");
    let began = Instant::now();
    loop {
        let shown = vox(&b, &["room", "session", &room, own_session, "--json"], None);
        if shown.0 && !shown.1.contains("DRIVER-OWN-SURVIVES-REMOVAL") {
            break;
        }
        assert!(
            began.elapsed() < Duration::from_secs(180),
            "PRODUCT: expired own activity did not disappear: {shown:?}"
        );
        std::thread::sleep(Duration::from_millis(250));
    }
    drop(driver.take());
    assert_eq!(
        retained_authored(),
        0,
        "PRODUCT: removed author's expired rows and their in-row openers remain on this node"
    );
    drop((author, driver));
}
