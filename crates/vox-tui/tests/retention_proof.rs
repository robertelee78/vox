//! ADR-023 M23.1 / PRD-001 R6–R10 — retention, driven through the **shipped `vox` binary**.
//!
//! History is kept forever by default. A room's admin can make it disappear after a while
//! (`vox room retention`), a node can keep less than its room (the `retention` file in its config
//! directory), the shorter wins, and shortening applies to what is already stored. An expired
//! message leaves nothing visible; its signed skeleton stays so sync and fork detection keep
//! working. This is look and feel, not a security property.
//!
//! Message-retention journeys use real durations. The RG-13 Session-step journey uses the
//! test-only clock to observe days of retention without waiting days.
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

#[cfg(feature = "test-knobs")]
#[path = "support/test_knobs.rs"]
mod test_knobs;

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
        .env("VOX_TEST_KEYCHAIN", attach::keychain(dir))
        .env("VOX_PROXY", "127.0.0.1:0")
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
        .env("VOX_TEST_KEYCHAIN", attach::keychain(dir))
        .env("VOX_PROXY", "127.0.0.1:0")
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
optional_proof::not_run!(
    fetching_keeps_serving_proofs_out_of_the_store,
    opening_a_room_reclaims_old_serving_proofs_across_interruption,
    a_session_change_rewrites_only_that_session,
    an_existing_session_index_keeps_its_listing_when_upgraded,
    private_session_steps_store_one_body_and_reopen_after_rotation,
);

#[cfg(feature = "optional-proofs")]
mod proof_rows {
    use super::*;
    use vox_core::atrest::idfactor::SignatureIdentityFactor;
    use vox_core::atrest::sek::Sek;
    use vox_core::atrest::store::{open_segment, seal_segment, SegmentKind};
    use vox_core::cbor::{Decoder, Encoder, Value};
    use vox_core::hash::{sha256, Digest32};
    use vox_core::log::history::{Descriptor, SignedHead, TreeBinding};
    use vox_core::node::paths::Paths;
    use vox_core::node::profile::Profile;
    use vox_core::node::store::Store;

    const PROOF_CACHE_CLEANED: u64 = 30;

    fn encode_binding(binding: TreeBinding, e: &mut Encoder) {
        e.array(4)
            .uint(2)
            .bytes(&binding.room)
            .uint(binding.scope as u64)
            .bytes(&binding.author);
    }
    fn decode_binding(d: &mut Decoder<'_>) -> vox_core::Result<TreeBinding> {
        assert_eq!(d.array().unwrap(), 4, "APPARATUS: binding arity");
        assert_eq!(d.uint().unwrap(), 2, "APPARATUS: binding version");
        Ok(TreeBinding {
            room: d.bytes()?.try_into().unwrap(),
            scope: vox_core::log::history::LogScope::decode(d.uint()?)?,
            author: d.bytes()?.try_into().unwrap(),
        })
    }

    fn post(dir: &Path, room: &str, text: &str) {
        let deadline = Instant::now() + Duration::from_secs(120);
        loop {
            let (ok, _, err) = vox(dir, &["room", "post", room, text], None);
            if ok {
                return;
            }
            assert!(
                err.contains("that room is preparing its saved history"),
                "PRODUCT (staging): post {text}: {err}"
            );
            assert!(
                Instant::now() < deadline,
                "APPARATUS: reopened poster never finished preparation: {err}"
            );
            std::thread::sleep(Duration::from_millis(200));
        }
    }

    fn array(value: &Value) -> &[Value] {
        let Value::Array(value) = value else {
            panic!("APPARATUS: expected a canonical array: {value:?}");
        };
        value
    }
    fn array_mut(value: &mut Value) -> &mut Vec<Value> {
        let Value::Array(value) = value else {
            panic!("APPARATUS: expected a canonical array");
        };
        value
    }
    fn number(value: &Value) -> u64 {
        let Value::Uint(value) = value else {
            panic!("APPARATUS: expected an integer: {value:?}");
        };
        *value
    }
    fn bytes(value: &Value) -> &[u8] {
        let Value::Bytes(value) = value else {
            panic!("APPARATUS: expected bytes: {value:?}");
        };
        value
    }
    fn profile(dir: &Path) -> Profile {
        let paths = Paths::resolve("default", Some(dir), Some(&dir.join("cfg")))
            .expect("APPARATUS: scratch profile paths");
        let mut profile = Profile::open(paths).expect("APPARATUS: stopped scratch profile");
        profile
            .unlock(IDENTITY.as_bytes())
            .expect("APPARATUS: unlock stopped scratch profile");
        profile
    }
    fn sek(profile: &Profile, room: &Digest32) -> Sek {
        let signer = profile.signer().expect("APPARATUS: scratch signer");
        profile
            .store()
            .get_sek_wrap(room)
            .unwrap()
            .expect("APPARATUS: scratch room key")
            .unwrap_sek(
                &SignatureIdentityFactor::new(signer),
                room,
                ROOMPASS.as_bytes(),
            )
            .expect("APPARATUS: unwrap scratch room key")
    }
    fn wire(store: &Store, sek: &Sek, room: &Digest32, id: u64) -> zeroize::Zeroizing<Vec<u8>> {
        let segment = store
            .get_segment(room, SegmentKind::EntryIndex, id)
            .unwrap()
            .expect("APPARATUS: indexed record exists");
        open_segment(sek, SegmentKind::EntryIndex, id, &segment).unwrap()
    }
    fn decoded(store: &Store, sek: &Sek, room: &Digest32, id: u64) -> Value {
        Value::from_canonical_slice(&wire(store, sek, room, id))
            .expect("APPARATUS: canonical stored record")
    }
    fn tree(
        store: &Store,
        sek: &Sek,
        room: &Digest32,
        root: u64,
        pages: &mut Vec<u64>,
        rows: &mut Vec<Value>,
    ) {
        if root == 0 {
            return;
        }
        pages.push(root);
        let page = decoded(store, sek, room, root);
        let page = array(&page);
        assert_eq!(page.len(), 3, "APPARATUS: index page shape");
        assert_eq!(number(&page[0]), 1, "APPARATUS: index page version");
        match number(&page[1]) {
            0 => rows.extend_from_slice(array(&page[2])),
            1 => {
                for row in array(&page[2]) {
                    tree(store, sek, room, number(&array(row)[1]), pages, rows);
                }
            }
            other => panic!("APPARATUS: unexpected object-tree page kind {other}"),
        }
    }
    fn roots(directory: &Value) -> &[Value] {
        let active = array(&array(directory)[1]);
        assert_eq!(active.len(), 16, "APPARATUS: current root layout");
        let sparse = array(&active[15]);
        assert_eq!(sparse.len(), 25, "APPARATUS: current sparse layout");
        sparse
    }
    fn full_room(dir: &Path, short: &str) -> Digest32 {
        let (ok, said, err) = vox(dir, &["status", "--json"], None);
        assert!(ok, "PRODUCT (staging): status: {err}");
        let status: serde_json::Value = serde_json::from_str(&said).unwrap();
        let id = status["rooms"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|room| room["id"].as_str())
            .find(|id| id.starts_with(short))
            .unwrap_or_else(|| panic!("PRODUCT (staging): room missing in {said}"));
        vox_core::node::link::b32_decode(id, "proof room").unwrap()
    }
    fn copy_tree(from: &Path, to: &Path) {
        std::fs::create_dir_all(to).unwrap();
        for entry in std::fs::read_dir(from).unwrap() {
            let entry = entry.unwrap();
            let kind = entry.file_type().unwrap();
            if kind.is_dir() {
                copy_tree(&entry.path(), &to.join(entry.file_name()));
            } else if kind.is_file() {
                std::fs::copy(entry.path(), to.join(entry.file_name())).unwrap();
            }
        }
    }
    // Inspect a stopped COPY, decoding the object-index kind and its entire old value, not a
    // ciphertext-length histogram. Every other typed object remains separately counted.
    fn counts(dir: &Path, room: &Digest32) -> std::collections::BTreeMap<u8, usize> {
        let copy = tempfile::tempdir().unwrap();
        copy_tree(dir, copy.path());
        let profile = profile(copy.path());
        let sek = sek(&profile, room);
        let directory = decoded(profile.store(), &sek, room, 0);
        let mut objects = Vec::new();
        tree(
            profile.store(),
            &sek,
            room,
            number(&roots(&directory)[0]),
            &mut Vec::new(),
            &mut objects,
        );
        let mut counts = std::collections::BTreeMap::new();
        for row in objects {
            let row = array(&row);
            let key = bytes(&row[0]);
            assert_eq!(key.len(), 64, "APPARATUS: object key width");
            let kind = key[32];
            *counts.entry(kind).or_default() += 1;
            if kind != 9 {
                continue;
            }
            let at = array(&row[1]);
            assert_eq!(at.len(), 2, "APPARATUS: object locator shape");
            assert_eq!(number(&at[0]), 1, "APPARATUS: numeric object locator");
            let value = decoded(profile.store(), &sek, room, number(&at[1]));
            let wire = value.to_canonical_vec().unwrap();
            let mut d = Decoder::new(&wire);
            assert_eq!(d.array().unwrap(), 5, "APPARATUS: ProofRange shape");
            assert_eq!(d.uint().unwrap(), 1, "APPARATUS: ProofRange version");
            let head: Digest32 = d.bytes().unwrap().try_into().unwrap();
            let binding = decode_binding(&mut d).unwrap();
            assert_eq!(binding.room, *room, "APPARATUS: ProofRange room");
            let start = d.uint().unwrap();
            let descriptor = Descriptor::decode(&mut d).unwrap();
            d.finish().unwrap();
            let mut e = Encoder::new();
            e.array(5).bytes(b"vox/proof-serving-range/v1").bytes(&head);
            encode_binding(binding, &mut e);
            e.uint(start).uint(descriptor.leaves);
            assert_eq!(
                &key[..32],
                sha256(&e.finish()),
                "APPARATUS: exact cache key"
            );
        }
        let file_bytes = std::fs::metadata(profile.paths().store_file())
            .unwrap()
            .len();
        eprintln!(
            "STOPPED-STORE {dir:?}: file bytes {file_bytes}; decoded object kinds {counts:?}"
        );
        counts
    }
    fn no_rows(dir: &Path, room: &Digest32) {
        let count = counts(dir, room).get(&9).copied().unwrap_or(0);
        assert_eq!(
            count, 0,
            "PRODUCT: fetching left {count} decoded ProofRange rows in the real room store"
        );
    }
    // Test-side old-store/eviction apparatus. It rewrites only the named derived tree, keeping
    // every other directory field and every signed entry, header, witness and receipt intact.
    #[allow(clippy::too_many_arguments)] // Exact stopped-store transaction inputs, not product API.
    fn replace_tree(
        store: &Store,
        sek: &Sek,
        room: &Digest32,
        sparse_slot: usize,
        mut directory: Value,
        pages: &[u64],
        mut rows: Vec<Value>,
        records: Vec<(u64, Value)>,
    ) {
        rows.sort_by(|a, b| bytes(&array(a)[0]).cmp(bytes(&array(b)[0])));
        let mut next = number(&array(&directory)[3]);
        let mut new_pages = Vec::new();
        let mut level = Vec::new();
        for chunk in rows.chunks(64) {
            let id = next;
            next += 1;
            new_pages.push((
                id,
                Value::Array(vec![
                    Value::Uint(1),
                    Value::Uint(0),
                    Value::Array(chunk.to_vec()),
                ]),
            ));
            level.push(Value::Array(vec![
                array(chunk.last().unwrap())[0].clone(),
                Value::Uint(id),
            ]));
        }
        while level.len() > 1 {
            let mut parent = Vec::new();
            for chunk in level.chunks(64) {
                let id = next;
                next += 1;
                new_pages.push((
                    id,
                    Value::Array(vec![
                        Value::Uint(1),
                        Value::Uint(1),
                        Value::Array(chunk.to_vec()),
                    ]),
                ));
                parent.push(Value::Array(vec![
                    array(chunk.last().unwrap())[0].clone(),
                    Value::Uint(id),
                ]));
            }
            level = parent;
        }
        let root = level.first().map_or(0, |row| number(&array(row)[1]));
        let active = &mut array_mut(&mut directory)[1];
        array_mut(&mut array_mut(active)[15])[sparse_slot] = Value::Uint(root);
        array_mut(&mut directory)[3] = Value::Uint(next);
        let revision = number(&array(&directory)[5]);
        array_mut(&mut directory)[5] = Value::Uint(revision + 1);
        let mut batch = store.batch().unwrap();
        for id in pages {
            batch
                .delete_segment(room, SegmentKind::EntryIndex, *id)
                .unwrap();
        }
        for (id, value) in records
            .into_iter()
            .chain(new_pages)
            .chain(std::iter::once((0, directory)))
        {
            let plain = value.to_canonical_vec().unwrap();
            let sealed = seal_segment(sek, SegmentKind::EntryIndex, id, &plain).unwrap();
            batch
                .put_segment(room, SegmentKind::EntryIndex, id, &sealed)
                .unwrap();
        }
        batch.commit().unwrap();
    }
    fn seed_old_rows(dir: &Path, room: &Digest32) -> usize {
        let profile = profile(dir);
        // This fixture represents a pre-conversion room, not a new cache writer.
        profile
            .store()
            .delete_segment(room, SegmentKind::KeyMaterial, PROOF_CACHE_CLEANED)
            .unwrap();
        let sek = sek(&profile, room);
        let mut directory = decoded(profile.store(), &sek, room, 0);
        let mut pages = Vec::new();
        let mut objects = Vec::new();
        tree(
            profile.store(),
            &sek,
            room,
            number(&roots(&directory)[0]),
            &mut pages,
            &mut objects,
        );
        let existing = objects
            .iter()
            .filter(|row| bytes(&array(row)[0])[32] == 9)
            .count();
        if existing > 32 {
            return existing;
        }
        objects.retain(|row| bytes(&array(row)[0])[32] != 9);
        let mut records = Vec::new();
        let mut next = number(&array(&directory)[3]);
        let mut ranges = Vec::new();
        tree(
            profile.store(),
            &sek,
            room,
            number(&roots(&directory)[5]),
            &mut Vec::new(),
            &mut ranges,
        );
        let mut seeded = std::collections::BTreeSet::new();
        for row in objects.clone() {
            let row = array(&row);
            if bytes(&row[0])[32] != 1 {
                continue;
            }
            let head_wire = wire(profile.store(), &sek, room, number(&array(&row[1])[1]));
            let head = SignedHead::from_wire(&head_wire).unwrap();
            if head.root.leaves == 0 {
                continue;
            }
            let mut descriptors = vec![(1, head.root)];
            for range in &ranges {
                let row = array(range);
                let key = bytes(&row[0]);
                if key[..32] != head.binding.author || key[48] != head.binding.scope as u8 {
                    continue;
                }
                let start = u64::from_be_bytes(key[32..40].try_into().unwrap());
                let leaves = u64::from_be_bytes(key[40..48].try_into().unwrap());
                if leaves != 1 || start > head.root.leaves {
                    continue;
                }
                let range_wire = wire(profile.store(), &sek, room, number(&array(&row[1])[1]));
                let mut d = Decoder::new(&range_wire);
                let descriptor = Descriptor::decode(&mut d).unwrap();
                d.finish().unwrap();
                descriptors.push((start, descriptor));
            }
            for (start, descriptor) in descriptors {
                let mut key = Encoder::new();
                key.array(5)
                    .bytes(b"vox/proof-serving-range/v1")
                    .bytes(&head.id());
                encode_binding(head.binding, &mut key);
                key.uint(start).uint(descriptor.leaves);
                let digest = sha256(&key.finish());
                if !seeded.insert(digest) {
                    continue;
                }
                let mut object = digest.to_vec();
                object.push(9);
                object.resize(64, 0);
                let mut value = Encoder::new();
                value.array(5).uint(1).bytes(&head.id());
                encode_binding(head.binding, &mut value);
                value.uint(start);
                descriptor.encode(&mut value);
                records.push((next, Value::from_canonical_slice(&value.finish()).unwrap()));
                objects.push(Value::Array(vec![
                    Value::Bytes(object),
                    Value::Array(vec![Value::Uint(1), Value::Uint(next)]),
                ]));
                next += 1;
            }
        }
        let count = records.len();
        assert!(count > 32, "APPARATUS: seed spans multiple cleanup batches");
        array_mut(&mut directory)[3] = Value::Uint(next);
        replace_tree(
            profile.store(),
            &sek,
            room,
            0,
            directory,
            &pages,
            objects,
            records,
        );
        count
    }
    fn evict_nonprefix_ranges(dir: &Path, room: &Digest32) {
        let profile = profile(dir);
        let sek = sek(&profile, room);
        let directory = decoded(profile.store(), &sek, room, 0);
        let mut pages = Vec::new();
        let mut ranges = Vec::new();
        tree(
            profile.store(),
            &sek,
            room,
            number(&roots(&directory)[5]),
            &mut pages,
            &mut ranges,
        );
        let before = ranges.len();
        // Prefix ranges are acceptance witnesses and stay. Only redundant non-prefix serving
        // subtrees are evicted, so a cache miss must use committed source-header reconstruction.
        ranges.retain(|row| {
            let key = bytes(&array(row)[0]);
            u64::from_be_bytes(key[32..40].try_into().unwrap()) == 1
        });
        assert!(
            before > ranges.len(),
            "APPARATUS: non-prefix ranges existed"
        );
        eprintln!(
            "EVICTED {} redundant non-prefix ranges",
            before - ranges.len()
        );
        replace_tree(
            profile.store(),
            &sek,
            room,
            5,
            directory,
            &pages,
            ranges,
            Vec::new(),
        );
    }
    fn all_texts(dir: &Path, room: &str) -> Vec<String> {
        let mut before: Option<String> = None;
        let mut texts = Vec::new();
        let ready_deadline = Instant::now() + Duration::from_secs(120);
        loop {
            let mut args = vec!["room", "read", room, "--json", "--limit", "32"];
            if let Some(cursor) = before.as_deref() {
                args.extend(["--before", cursor]);
            }
            let (ok, said, err) = vox(dir, &args, None);
            if !ok && err.contains("that room is preparing its saved history") {
                assert!(
                    Instant::now() < ready_deadline,
                    "APPARATUS: reopened room did not finish preparation: {err}"
                );
                std::thread::sleep(Duration::from_millis(200));
                continue;
            }
            if !ok && err.contains("the room changed while reading; refresh and retry") {
                before = None;
                texts.clear();
                continue;
            }
            assert!(ok, "PRODUCT: historical paging: {err}");
            let rows: Vec<serde_json::Value> = said
                .lines()
                .filter(|line| !line.is_empty())
                .map(|line| serde_json::from_str(line).expect("APPARATUS: JSON room row"))
                .collect();
            if rows.is_empty() {
                break;
            }
            let next = rows[0]["entry_hash"]
                .as_str()
                .expect("PRODUCT: page has a cursor")
                .to_owned();
            assert_ne!(
                before.as_ref(),
                Some(&next),
                "PRODUCT: paging repeated its cursor"
            );
            before = Some(next);
            texts.extend(
                rows.iter()
                    .filter_map(|row| row["text"].as_str().map(str::to_owned)),
            );
            if rows.len() < 32 {
                break;
            }
        }
        texts
    }
    fn await_count(dir: &Path, room: &str, total: usize) {
        let seen = std::cell::Cell::new(0);
        assert!(
            within(120, || {
                seen.set(count(&all_texts(dir, room), "PROOF-CACHE-"));
                seen.get() == total
            }),
            "PRODUCT: receiver shows {}/{total} acknowledged messages",
            seen.get()
        );
    }
    fn all_messages(dir: &Path, room: &str, total: usize) {
        let seen = count(&all_texts(dir, room), "PROOF-CACHE-");
        assert_eq!(
            seen, total,
            "PRODUCT: paging back returned {seen}/{total} acknowledged messages"
        );
    }
    fn held_daemon(dir: &Path, tag: &str, listen: &str, variable: &str, hold: &Path) -> Daemon {
        let mut child = Command::new(VOX)
            .args(["daemon", "--listen", listen])
            .env("VOX_DATA_DIR", dir)
            .env("VOX_CONFIG_DIR", dir.join("cfg"))
            .env("VOX_TEST_KEYCHAIN", attach::keychain(dir))
            .env("VOX_PROXY", "127.0.0.1:0")
            .env(variable, hold)
            .stdin(Stdio::piped())
            .stdout(std::fs::File::create(dir.join(format!("daemon-{tag}.out"))).unwrap())
            .stderr(std::fs::File::create(dir.join(format!("daemon-{tag}.err"))).unwrap())
            .spawn()
            .unwrap();
        writeln!(child.stdin.take().unwrap(), "{IDENTITY}").unwrap();
        Daemon(child)
    }
    fn fresh() -> (
        tempfile::TempDir,
        PathBuf,
        PathBuf,
        Daemon,
        Daemon,
        String,
        Digest32,
    ) {
        let tmp = tempfile::tempdir().unwrap();
        let (a, b) = pair(tmp.path());
        let ad = daemon(&a, "a", &format!("{IDENTITY}\n"));
        let bd = daemon(&b, "b", &format!("{IDENTITY}\n"));
        attached(&a, "a");
        attached(&b, "b");
        let room = room(&a, &b);
        let id = full_room(&a, &room);
        (tmp, a, b, ad, bd, room, id)
    }
    pub(super) fn fetch() {
        let (_tmp, a, b, ad, bd, room, id) = fresh();
        for i in 0..100 {
            post(&a, &room, &format!("PROOF-CACHE-{i:04}"));
            if i % 10 == 9 {
                await_count(&b, &room, i + 1);
            }
        }
        let alisten = listening(&a);
        let blisten = listening(&b);
        drop(ad);
        drop(bd);
        no_rows(&a, &id);
        no_rows(&b, &id);
        let ad = daemon_on(&a, "a-post", &format!("{IDENTITY}\n"), &alisten);
        attached(&a, "a-post");
        for i in 100..140 {
            post(&a, &room, &format!("PROOF-CACHE-{i:04}"));
        }
        drop(ad);
        evict_nonprefix_ranges(&a, &id);
        let ad = daemon_on(&a, "a-restart", &format!("{IDENTITY}\n"), &alisten);
        attached(&a, "a-restart");
        for attempt in 0..2 {
            let hold = b.join(format!("fetch-{attempt}.hold"));
            std::fs::write(&hold, b"abandon verified fetch before bodies").unwrap();
            let bd = held_daemon(
                &b,
                &format!("b-abandon-{attempt}"),
                &blisten,
                "VOX_TEST_HOLD_VERIFIED_FETCH",
                &hold,
            );
            assert!(
                within(120, || hold.with_extension("verified").exists()),
                "APPARATUS: no completed fetch proof was available to abandon"
            );
            let held = count(&all_texts(&b, &room), "PROOF-CACHE-");
            assert!(
                held < 140,
                "APPARATUS: fetch abandonment was staged after all message bodies arrived"
            );
            eprintln!("ABANDONED verified fetch: receiver shows {held}/140 message bodies");
            drop(bd);
            std::fs::remove_file(hold).unwrap();
            no_rows(&b, &id);
        }
        let bd = daemon_on(&b, "b-restart", &format!("{IDENTITY}\n"), &blisten);
        attached(&b, "b-restart");
        await_count(&b, &room, 140);
        all_messages(&a, &room, 140);
        all_messages(&b, &room, 140);
        drop(ad);
        drop(bd);
        no_rows(&a, &id);
        no_rows(&b, &id);
    }
    pub(super) fn cleanup() {
        let (_tmp, a, b, ad, bd, room, id) = fresh();
        for i in 0..80 {
            post(&a, &room, &format!("PROOF-CACHE-{i:04}"));
        }
        await_count(&b, &room, 80);
        let alisten = listening(&a);
        let blisten = listening(&b);
        drop(ad);
        drop(bd);
        seed_old_rows(&a, &id);
        let before = counts(&a, &id);
        assert!(before.get(&9).copied().unwrap_or(0) > 32);
        let ad = daemon_on(&a, "a-clean", &format!("{IDENTITY}\n"), &alisten);
        attached(&a, "a-clean");
        all_messages(&a, &room, 80);
        drop(ad);
        no_rows(&a, &id);
        let after = counts(&a, &id);
        for (kind, count) in before.iter().filter(|(kind, _)| **kind != 9 && **kind != 4) {
            assert!(
                after.get(kind).copied().unwrap_or(0) >= *count,
                "PRODUCT: cleanup deleted non-cache object kind {kind}: {before:?} -> {after:?}"
            );
        }
        // Keep the product's completed-conversion marker, if it has one. Planting old rows
        // after it makes a rescan observable: a completed room must leave these canaries alone.
        let completed_marker = profile(&a)
            .store()
            .get_segment(&id, SegmentKind::KeyMaterial, PROOF_CACHE_CLEANED)
            .unwrap();
        let canaries = seed_old_rows(&a, &id);
        if let Some(marker) = completed_marker {
            profile(&a)
                .store()
                .put_segment(&id, SegmentKind::KeyMaterial, PROOF_CACHE_CLEANED, &marker)
                .unwrap();
        }
        let ad = daemon_on(&a, "a-second-open", &format!("{IDENTITY}\n"), &alisten);
        attached(&a, "a-second-open");
        all_messages(&a, &room, 80);
        drop(ad);
        let retained = counts(&a, &id).get(&9).copied().unwrap_or(0);
        assert_eq!(retained, canaries,
            "PRODUCT: a completed room rescanned its old-proof object tree on second open: {retained}/{canaries} canaries remain");
        eprintln!("SECOND OPEN: retained {retained} store canaries; no cleanup scan");
        let seeded = seed_old_rows(&a, &id);
        let hold = a.join("proof-cleanup.hold");
        std::fs::write(&hold, b"hold after one committed batch").unwrap();
        let ad = held_daemon(
            &a,
            "a-interrupt",
            &alisten,
            "VOX_TEST_HOLD_PROOF_CACHE_CLEANUP",
            &hold,
        );
        assert!(
            within(120, || hold.with_extension("committed").exists()),
            "APPARATUS: room-open cleanup never reached a committed cache batch"
        );
        drop(ad);
        let interrupted = counts(&a, &id).get(&9).copied().unwrap_or(0);
        assert!(interrupted > 0 && interrupted < seeded,
            "PRODUCT: interrupted cleanup committed no bounded progress: {interrupted}/{seeded} rows remain");
        std::fs::remove_file(hold).unwrap();
        let ad = daemon_on(&a, "a-final", &format!("{IDENTITY}\n"), &alisten);
        let bd = daemon_on(&b, "b-final", &format!("{IDENTITY}\n"), &blisten);
        attached(&a, "a-final");
        attached(&b, "b-final");
        all_messages(&a, &room, 80);
        all_messages(&b, &room, 80);
        drop(ad);
        drop(bd);
        no_rows(&a, &id);
    }
}

#[cfg(feature = "optional-proofs")]
#[test]
#[ignore = "real pair, changing signed heads, store inspection and restart paging"]
fn fetching_keeps_serving_proofs_out_of_the_store() {
    proof_rows::fetch();
}

#[cfg(feature = "optional-proofs")]
#[test]
#[ignore = "real pair and interrupted bounded old-store cleanup"]
fn opening_a_room_reclaims_old_serving_proofs_across_interruption() {
    proof_rows::cleanup();
}

/// RG-13: implicit steps last two days; signed admin choices and lifecycle survive.
///
/// The repeat check compares total public entries with a sibling that made one choice,
/// not StepPolicy entries: the product lists no per-kind log. Both fixtures' lifecycle,
/// activity and ordinary post are read back before comparison, then checked after reopens.
#[cfg(feature = "test-knobs")]
#[test]
#[ignore = "real binary, private Session records and test-knobs clock; run in release"]
fn session_steps_expire_after_two_days_unless_the_admin_chose_otherwise() {
    use vox_core::node::ipc::{Frame, IpcClient, NodeSocket, Request};
    use vox_core::node::paths::{NodeName, Paths};
    watchdog::arm();
    test_knobs::require(&["VOX_TEST_CLOCK_STEP_MS"]);
    let scratch = tempfile::tempdir().expect("APPARATUS: retention profile");
    let dir = scratch.path();
    std::fs::create_dir_all(dir.join("cfg")).expect("APPARATUS: retention config");
    let keychain = attach::keychain(dir);
    let command = || {
        let mut cmd = Command::new(VOX);
        cmd.env("VOX_DATA_DIR", dir)
            .env("VOX_CONFIG_DIR", dir.join("cfg"))
            .env("VOX_TEST_KEYCHAIN", &keychain)
            .env("VOX_PROXY", "127.0.0.1:0")
            .env("VOX_IDENTITY_PASSPHRASE", IDENTITY)
            .env_remove("VOX_NODE")
            .env_remove("VOX_ROOM");
        cmd
    };
    let run = |args: &[&str], input: Option<&str>| {
        let mut child = command()
            .args(args)
            .stdin(if input.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("APPARATUS: retention CLI");
        if let Some(input) = input {
            child
                .stdin
                .take()
                .unwrap()
                .write_all(input.as_bytes())
                .unwrap();
        }
        let out = child
            .wait_with_output()
            .expect("APPARATUS: retention CLI output");
        (
            out.status.success(),
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    };
    let (ok, out, err) = run(&["id"], None);
    assert!(ok, "APPARATUS: protected node: {out}{err}");
    let launch = |offset: u64| {
        let log = std::fs::File::create(dir.join(format!("clock-{offset}.log"))).unwrap();
        let mut child = command()
            .args(["daemon", "--listen", "127.0.0.1:0"])
            .env("VOX_TEST_CLOCK_STEP_MS", offset.to_string())
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(log)
            .spawn()
            .expect("APPARATUS: retention daemon");
        writeln!(child.stdin.take().unwrap(), "{IDENTITY}").unwrap();
        let daemon = Daemon(child);
        let began = Instant::now();
        loop {
            let (ok, out, err) = run(&["status", "--json"], None);
            if ok
                && serde_json::from_str::<serde_json::Value>(&out)
                    .is_ok_and(|v| v["status"] == "Ready")
            {
                break;
            }
            assert!(
                began.elapsed() < Duration::from_secs(60),
                "APPARATUS: clock-stepped daemon not Ready: {out}{err}"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
        daemon
    };
    let mut daemon = launch(0);
    let paths = Paths::resolve("default", Some(dir), Some(&dir.join("cfg"))).unwrap();
    let socket = NodeSocket::one_shot(
        paths.account().socket(),
        NodeName::parse("default").unwrap(),
    );
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let request = |request: Request| {
        let mut client = rt
            .block_on(IpcClient::open_at(&socket))
            .expect("APPARATUS: room IPC");
        let began = Instant::now();
        loop {
            let reply = rt
                .block_on(client.request(&request))
                .expect("APPARATUS: room IPC reply");
            if !matches!(&reply, Frame::Error { reason } if
                reason.contains("permissions are still being read") ||
                reason.contains("room governance is refreshing"))
            {
                return reply;
            }
            assert!(
                began.elapsed() < Duration::from_secs(120),
                "APPARATUS: policy staging never became ready: {reply:?}"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    };
    let read_session = |room: &str| {
        let began = Instant::now();
        loop {
            let (ok, listed, err) = run(&["room", "sessions", room, "--json"], None);
            if !ok {
                assert!(
                    err.contains("room is preparing its saved history")
                        && began.elapsed() < Duration::from_secs(120),
                    "APPARATUS: Session listing never became available: {listed}{err}"
                );
                std::thread::sleep(Duration::from_millis(50));
                continue;
            }
            if listed.contains("ttl-session") {
                let (ok, shown, err) =
                    run(&["room", "session", room, "ttl-session", "--json"], None);
                if ok {
                    return (listed, shown);
                }
                assert!(
                    err.contains("Sessions changed") || err.contains("refresh the listing"),
                    "APPARATUS: Session read refused, not expiry: {shown}{err}"
                );
            }
            assert!(
                began.elapsed() < Duration::from_secs(120),
                "APPARATUS: Session projection did not publish: {listed}{err}"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    };
    let mut rooms = Vec::new();
    let mut policy_failures = Vec::new();
    for (name, seconds) in [
        ("default", None),
        ("seven", Some(604800)),
        ("short", Some(86400)),
        ("forever", Some(0)),
        ("equal", Some(172800)),
    ] {
        let (ok, out, err) = run(
            &["room", "create", "--name", name, "--passphrase-file", "-"],
            Some("retention room passphrase\n"),
        );
        assert!(ok, "APPARATUS: create {name}: {out}{err}");
        let Frame::Rooms { rooms: listed } = request(Request::Rooms { after: None }) else {
            panic!("APPARATUS: rooms did not return a listing");
        };
        let cid = listed
            .iter()
            .find(|(_, label, ..)| label == name)
            .unwrap()
            .0;
        let room = vox_core::node::link::b32_encode(&cid);
        let governance_revision = || {
            let (ok, out, err) = run(&["status", "--json"], None);
            assert!(ok, "APPARATUS: status around admin choice: {out}{err}");
            let status: serde_json::Value = serde_json::from_str(&out).unwrap();
            status["rooms"]
                .as_array()
                .unwrap()
                .iter()
                .find(|r| r["id"] == room)
                .and_then(|r| r["governance_revision"].as_u64())
                .expect("APPARATUS: policy room not published")
        };
        // Background room controls share the log; only governance records this admin choice.
        let before = (name == "equal").then(governance_revision);
        if let Some(seconds) = seconds {
            let seconds = seconds.to_string();
            let (ok, out, err) = run(&["room", "retention", &room, "--steps", &seconds], None);
            assert!(ok, "APPARATUS: explicit {name} step policy: {out}{err}");
            println!("SEEN: vox room retention {name} --steps {seconds}: {out}{err}");
        }
        if let Some(before) = before {
            let after_first = governance_revision();
            println!("SEEN: first default-equal choice governance revision: before={before}; after={after_first}");
            if after_first != before + 1 {
                policy_failures.push(format!("first explicit default-equal choice must advance governance revision once: before={before}; after={after_first}"));
            }
            let (ok, out, err) = run(&["room", "retention", &room, "--steps", "172800"], None);
            assert!(ok, "APPARATUS: repeat default-equal choice: {out}{err}");
            let after_repeat = governance_revision();
            println!("SEEN: repeated default-equal choice governance revision: before={after_first}; after={after_repeat}; {out}{err}");
        }
        let lifecycle = serde_json::json!({"v":1,"type":"session","from":"ttl-session",
            "body":"","at":{"session_name":"TTL-LIFECYCLE"},
            "data":{"session":{"harness":"rg13-retention"}}})
        .to_string();
        let activity = serde_json::json!({"v":1,"session":"ttl-session","kind":"reply",
            "seq":1,"text":"TTL-ACTIVITY"})
        .to_string();
        for body in [lifecycle, activity] {
            let result = request(Request::AppendSession {
                channel_id: cid,
                session_id: "ttl-session".to_owned(),
                body,
            });
            assert!(
                matches!(result, Frame::Appended { .. }),
                "APPARATUS: real private Session append: {result:?}"
            );
        }
        assert!(
            matches!(
                request(Request::Post {
                    channel_id: cid,
                    text: "ORDINARY-FOREVER".to_owned(),
                    card: false
                }),
                Frame::Ok
            ),
            "APPARATUS: ordinary message control"
        );
        let began = Instant::now();
        loop {
            let (listed, shown) = read_session(&room);
            let (ok, ordinary, err) = run(&["room", "read", &room, "--json"], None);
            if listed.contains("TTL-LIFECYCLE")
                && shown.contains("TTL-ACTIVITY")
                && ok
                && ordinary.contains("ORDINARY-FOREVER")
            {
                break;
            }
            assert!(
                began.elapsed() < Duration::from_secs(120),
                "APPARATUS: activities/lifecycle/ordinary post were not initially readable: {listed}{shown}{ordinary}{err}"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
        rooms.push((name, room));
    }
    let repeat_entry_failure = |stage: &str| {
        let deadline = Instant::now() + Duration::from_secs(120);
        loop {
            let (ok, out, err) = run(&["status", "--json"], None);
            assert!(
                ok,
                "APPARATUS: status comparing repeated choice: {out}{err}"
            );
            let status: serde_json::Value =
                serde_json::from_str(&out).expect("APPARATUS: comparison status JSON");
            let reports = status["rooms"]
                .as_array()
                .expect("APPARATUS: comparison status rooms");
            let count = |name: &str| {
                reports
                    .iter()
                    .find(|room| room["name"] == name)
                    .and_then(|room| room["log_entries"].as_u64())
                    .expect("APPARATUS: comparison room not published")
            };
            let equal = count("equal");
            let seven = count("seven");
            if equal == seven {
                println!(
                    "SEEN: {stage} repeat public log comparison: equal={equal}; seven={seven}"
                );
                return None;
            }
            if Instant::now() >= deadline {
                println!(
                    "SEEN: {stage} repeat public log comparison: equal={equal}; seven={seven}"
                );
                return Some(format!(
                    "PRODUCT: repeating the signed step choice must leave equal's public log count equal to sibling seven (one choice), at {stage}: equal log_entries={equal}; seven log_entries={seven}"
                ));
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    };
    let mut failures = policy_failures;
    if let Some(failure) = repeat_entry_failure("initial readback") {
        failures.push(failure);
    }
    for offset in [86_400_001, 172_800_001] {
        drop(daemon);
        daemon = launch(offset);
        for (name, room) in &rooms {
            let (listed, shown) = read_session(room);
            // A room can finish reopening after the first daemon Ready report.
            let (ok, status, err) = run(&["status", "--json"], None);
            assert!(
                ok,
                "APPARATUS: status after the room's Session listing: {status}{err}"
            );
            let status: serde_json::Value = serde_json::from_str(&status).unwrap();
            let expected_activity = *name == "seven"
                || *name == "forever"
                || ((*name == "default" || *name == "equal") && offset < 172_800_001);
            if shown.contains("TTL-ACTIVITY") != expected_activity {
                failures.push(format!(
                    "{name} at +{offset}ms activity expected={expected_activity}: {shown}"
                ));
            }
            if !listed.contains("TTL-LIFECYCLE") {
                failures.push(format!("{name} lost lifecycle: {listed}"));
            }
            let report = status["rooms"]
                .as_array()
                .unwrap()
                .iter()
                .find(|r| r["id"] == *room)
                .expect("PRODUCT: status omitted a retained room");
            let ttl = match *name {
                "default" | "equal" => 172800,
                "seven" => 604800,
                "short" => 86400,
                _ => 0,
            };
            if report["step_retention"] != ttl || report["retention"] != 0 {
                failures.push(format!(
                    "{name} status step TTL must be {ttl}, messages forever: {report}"
                ));
            }
            let (ok, ordinary, err) = run(&["room", "read", room, "--json"], None);
            assert!(ok, "APPARATUS: ordinary message read: {ordinary}{err}");
            if !ordinary.contains("ORDINARY-FOREVER") {
                failures.push(format!("{name} changed ordinary retention: {ordinary}"));
            }
            eprintln!(
                "OBSERVATION +{offset}ms {name}: activity={} lifecycle={} status={report}",
                shown.contains("TTL-ACTIVITY"),
                listed.contains("TTL-LIFECYCLE")
            );
        }
        if let Some(failure) = repeat_entry_failure(&format!("+{offset}ms reopen")) {
            failures.push(failure);
        }
    }
    if std::env::var_os("VOX_MUTANT_STEPS_EXPLICIT_EQUAL_IGNORED").is_some() {
        let log =
            std::fs::read_to_string(dir.join("clock-0.log")).expect("APPARATUS: mutant daemon log");
        assert!(
            log.contains("SEEN: steps.explicit_equal_ignored engaged"),
            "APPARATUS: equal-choice mutant never engaged: {log}"
        );
        eprintln!("{log}");
    }
    assert!(
        failures.is_empty(),
        "PRODUCT: Session-step retention failed:\n{}",
        failures.join("\n")
    );
}

/// Commands in the small-row proofs never borrow a harness session or the login Keychain.
fn small_row_command(root: &Path, argv: &[&str], input: Option<&str>) -> (bool, String) {
    let mut cmd = Command::new(VOX);
    cmd.args(argv)
        .env("VOX_DATA_DIR", root)
        .env("VOX_CONFIG_DIR", root.join("cfg"))
        .env("VOX_TEST_KEYCHAIN", attach::keychain(root))
        .env("VOX_IDENTITY_PASSPHRASE", IDENTITY)
        .env("VOX_PROXY", "127.0.0.1:0")
        .env_remove("VOX_NODE")
        .env_remove("VOX_ROOM")
        .env_remove("VOX_SESSION")
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(mutant) = std::env::var_os("VOX_MUTANT_SMALL_ROWS") {
        cmd.env("VOX_TEST_FX28_MUTANT", mutant);
    }
    for (name, _) in std::env::vars_os() {
        if ["TMUX", "CLAUDE", "CODEX", "OPENCODE", "OMP", "PI_"]
            .iter()
            .any(|prefix| name.to_string_lossy().starts_with(prefix))
        {
            cmd.env_remove(name);
        }
    }
    let mut child = cmd.spawn().expect("APPARATUS: spawn scratch vox");
    if let Some(input) = input {
        child
            .stdin
            .take()
            .unwrap()
            .write_all(input.as_bytes())
            .expect("APPARATUS: scratch vox stdin");
    }
    let out = child
        .wait_with_output()
        .expect("APPARATUS: wait for scratch vox");
    (
        out.status.success(),
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    )
}

fn small_row_daemon(root: &Path, marker: Option<&Path>) -> Daemon {
    let mut cmd = Command::new(VOX);
    cmd.args(["daemon", "--listen", "127.0.0.1:0"])
        .env("VOX_DATA_DIR", root)
        .env("VOX_CONFIG_DIR", root.join("cfg"))
        .env("VOX_TEST_KEYCHAIN", attach::keychain(root))
        .env(
            "VOX_TEST_SMALL_ROWS_FAIL_FILE",
            root.join("fail-small-row-move"),
        )
        .env("VOX_PROXY", "127.0.0.1:0")
        .env_remove("VOX_NODE")
        .env_remove("VOX_ROOM")
        .env_remove("VOX_SESSION")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(std::fs::File::create(root.join("small-rows-daemon.err")).unwrap());
    if let Some(marker) = marker {
        cmd.env("VOX_TEST_SMALL_ROWS_COMMITTED", marker);
    } else {
        cmd.env_remove("VOX_TEST_SMALL_ROWS_COMMITTED");
    }
    if let Some(mutant) = std::env::var_os("VOX_MUTANT_SMALL_ROWS") {
        eprintln!(
            "APPARATUS: child mutant selected: {}",
            mutant.to_string_lossy()
        );
        cmd.env("VOX_TEST_FX28_MUTANT", mutant);
    }
    for (name, _) in std::env::vars_os() {
        if ["TMUX", "CLAUDE", "CODEX", "OPENCODE", "OMP", "PI_"]
            .iter()
            .any(|prefix| name.to_string_lossy().starts_with(prefix))
        {
            cmd.env_remove(name);
        }
    }
    let mut child = cmd.spawn().expect("APPARATUS: spawn scratch daemon");
    writeln!(child.stdin.take().unwrap(), "{IDENTITY}").expect("APPARATUS: daemon unlock");
    Daemon(child)
}

fn small_row_ready(root: &Path) {
    let last = std::cell::RefCell::new(String::new());
    assert!(
        within(240, || {
            let (ok, said) = small_row_command(root, &["room", "list"], None);
            *last.borrow_mut() = said;
            ok
        }),
        "PRODUCT (staging): scratch daemon did not open: {}",
        last.borrow()
    );
}

fn copy_small_row_profile(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).expect("APPARATUS: copy profile directory");
    for entry in std::fs::read_dir(from).expect("APPARATUS: read stopped profile") {
        let entry = entry.unwrap();
        if entry.file_name() == ".daemon" || entry.file_name() == "proof.keychain-db" {
            continue;
        }
        let kind = entry.file_type().unwrap();
        let target = to.join(entry.file_name());
        if kind.is_dir() {
            copy_small_row_profile(&entry.path(), &target);
        } else if kind.is_file() {
            std::fs::copy(entry.path(), target).expect("APPARATUS: copy stopped profile file");
        }
    }
}

#[derive(Debug, Default)]
struct SmallRowLeaves {
    rows: usize,
    small: usize,
    small_bytes: usize,
    small_only_leaf_bytes: usize,
    single_small: usize,
}

/// Read the committed physical tree, not file length or redb's cached estimates.
fn small_row_leaves(path: &Path) -> SmallRowLeaves {
    let bytes = std::fs::read(path).expect("APPARATUS: read stopped store");
    assert_eq!(
        &bytes[..9],
        b"redb\x1a\x0a\xa9\x0d\x0a",
        "APPARATUS: redb header"
    );
    fn n(bytes: &[u8], at: usize, width: usize) -> u64 {
        let mut out = [0; 8];
        out[..width].copy_from_slice(
            bytes
                .get(at..at + width)
                .expect("APPARATUS: physical offset"),
        );
        u64::from_le_bytes(out)
    }
    type Leaf<'a> = (usize, Vec<&'a [u8]>, Vec<&'a [u8]>);
    fn leaves(bytes: &[u8], root: u64, key_width: Option<usize>) -> Vec<Leaf<'_>> {
        let base = n(bytes, 12, 4) as usize;
        let header = n(bytes, 16, 4) as usize;
        let region_pages = n(bytes, 20, 4) as usize;
        let mut stack = vec![root];
        let mut seen = std::collections::BTreeSet::new();
        let mut result = Vec::new();
        while let Some(page) = stack.pop() {
            assert!(seen.insert(page), "APPARATUS: duplicate physical page");
            let order = (page >> 59) as usize;
            let size = base << order;
            let index = page as usize & (0xfffff >> order);
            let region = (page >> 20) as usize & 0xfffff;
            let start =
                base + region * (header + region_pages) * base + header * base + index * size;
            let page = bytes
                .get(start..start + size)
                .expect("APPARATUS: page allocation");
            let count = n(page, 2, 2) as usize;
            if page[0] == 2 {
                let children = 8 + 16 * (count + 1);
                stack.extend((0..=count).map(|i| n(page, children + 8 * i, 8)));
                continue;
            }
            assert!(page[0] == 1 && count > 0, "APPARATUS: leaf type/count");
            let key_start = 4 + if key_width.is_none() { 4 * count } else { 0 } + 4 * count;
            let key_ends: Vec<_> = (0..count)
                .map(|i| {
                    key_width.map_or_else(
                        || n(page, 4 + 4 * i, 4) as usize,
                        |width| key_start + width * (i + 1),
                    )
                })
                .collect();
            let value_offsets = 4 + if key_width.is_none() { 4 * count } else { 0 };
            let value_ends: Vec<_> = (0..count)
                .map(|i| n(page, value_offsets + 4 * i, 4) as usize)
                .collect();
            assert!(
                key_start <= key_ends[count - 1]
                    && key_ends[count - 1] <= value_ends[count - 1]
                    && value_ends[count - 1] <= size,
                "APPARATUS: leaf offsets"
            );
            let keys = (0..count)
                .map(|i| &page[if i == 0 { key_start } else { key_ends[i - 1] }..key_ends[i]])
                .collect();
            let values = (0..count)
                .map(|i| {
                    &page[if i == 0 {
                        key_ends[count - 1]
                    } else {
                        value_ends[i - 1]
                    }..value_ends[i]]
                })
                .collect();
            result.push((size, keys, values));
        }
        result
    }
    let slot = 64 + 128 * usize::from(bytes[9] & 1);
    let root = n(&bytes, slot + 8, 8);
    let definitions: std::collections::BTreeMap<_, _> = leaves(&bytes, root, None)
        .into_iter()
        .flat_map(|(_, keys, values)| keys.into_iter().zip(values))
        .collect();
    let mut result = SmallRowLeaves::default();
    for name in [b"segments".as_slice(), b"small_segments".as_slice()] {
        let Some(definition) = definitions.get(name) else {
            continue;
        };
        if definition[9] == 0 {
            continue;
        }
        assert_eq!(n(definition, 43, 4), 41, "APPARATUS: SegmentKey width");
        let mut rows = 0;
        for (size, keys, values) in leaves(&bytes, n(definition, 10, 8), Some(41)) {
            rows += keys.len();
            let small = values.iter().filter(|value| value.len() <= 1024).count();
            result.small += small;
            result.small_bytes += values
                .iter()
                .filter(|value| value.len() <= 1024)
                .map(|value| value.len())
                .sum::<usize>();
            if small == values.len() {
                result.small_only_leaf_bytes += size;
            }
            if small == 1 && keys.len() == 1 {
                result.single_small += 1;
            }
        }
        assert_eq!(
            rows as u64,
            n(definition, 1, 8),
            "APPARATUS: committed table row count"
        );
        result.rows += rows;
    }
    result
}

fn assert_small_rows_share(path: &Path) {
    let layout = small_row_leaves(path);
    eprintln!("PHYSICAL SMALL ROWS {layout:?}");
    assert!(
        layout.small >= 80,
        "APPARATUS: insufficient small rows: {layout:?}"
    );
    assert!(
        layout.single_small * 8 < layout.small
            && layout.small_only_leaf_bytes <= layout.small_bytes * 4 + 4 * 4096,
        "PRODUCT: tiny live values still pay whole leaves: {layout:?}"
    );
}

fn small_row_paths(root: &Path) -> vox_core::node::paths::Paths {
    vox_core::node::paths::Account::of(Some(root), Some(&root.join("cfg")))
        .expect("APPARATUS: scratch account paths")
        .node_paths_as_they_are(&vox_core::node::paths::NodeName::parse("default").unwrap())
}

/// Decode only root-reachable authenticated locator and ranked-render pages on a copy.
fn small_row_index_pages(root: &Path, room: &[u8; 32]) -> Vec<(u64, usize, usize, bool)> {
    use vox_core::atrest::{
        idfactor::SignatureIdentityFactor,
        store::{open_segment, SegmentKind},
    };
    use vox_core::cbor::Value;
    let mut profile = vox_core::node::profile::Profile::open(small_row_paths(root))
        .expect("APPARATUS: open copied profile");
    profile
        .unlock(IDENTITY.as_bytes())
        .expect("APPARATUS: unlock copied profile");
    let signer = profile.signer().unwrap();
    let store = profile.store();
    let sek = store
        .get_sek_wrap(room)
        .unwrap()
        .unwrap()
        .unwrap_sek(
            &SignatureIdentityFactor::new(signer),
            room,
            ROOMPASS.as_bytes(),
        )
        .unwrap();
    let mut pages = std::collections::BTreeMap::new();
    store
        .visit_segments(room, SegmentKind::EntryIndex, |id, sealed| {
            let plain = open_segment(&sek, SegmentKind::EntryIndex, id, &sealed)?;
            if let Ok(value) = Value::from_canonical_slice(&plain) {
                pages.insert(id, (plain.len(), value));
            }
            Ok(())
        })
        .expect("APPARATUS: decode copied index pages");
    let array = |value: &Value| match value {
        Value::Array(items) => items.clone(),
        other => panic!("APPARATUS: expected CBOR array, saw {other:?}"),
    };
    let uint = |value: &Value| match value {
        Value::Uint(n) => *n,
        other => panic!("APPARATUS: expected CBOR uint, saw {other:?}"),
    };
    let directory = array(&pages.get(&0).expect("APPARATUS: index directory").1);
    let active = array(&directory[1]);
    let mut stack: Vec<_> = active[..6].iter().map(|id| (uint(id), false)).collect();
    stack.extend(array(&active[6]).iter().map(|id| (uint(id), true)));
    let mut seen = std::collections::BTreeSet::new();
    let mut result = Vec::new();
    while let Some((id, ranked)) = stack.pop() {
        if id == 0 || !seen.insert(id) {
            continue;
        }
        let (len, value) = pages.get(&id).expect("APPARATUS: reachable index page");
        let page = array(value);
        assert_eq!(page.len(), 3, "APPARATUS: index page fields");
        assert_eq!(uint(&page[0]), 1, "APPARATUS: page codec version");
        let kind = uint(&page[1]);
        let rows = array(&page[2]);
        assert!(
            !rows.is_empty() && rows.len() <= 128,
            "APPARATUS: page read bound"
        );
        if kind != 0 {
            assert!(kind == 1 || kind == 2, "APPARATUS: page kind");
            for row in &rows {
                stack.push((uint(&array(row)[1]), ranked));
            }
        } else {
            let filter = vox_core::hash::sha256_concat(&[b"render-type\0", b"legacy128-proof"]);
            for row in &rows {
                let row = array(row);
                if let Value::Bytes(key) = &row[0] {
                    if key.starts_with(&filter) {
                        let target = array(&row[1]);
                        assert_eq!(target.len(), 2, "APPARATUS: filter root value");
                        assert_eq!(uint(&target[0]), 1, "APPARATUS: numeric filter root");
                        stack.push((uint(&target[1]), true));
                    }
                }
            }
        }
        result.push((id, *len, rows.len(), ranked));
    }
    result
}

fn small_row_all_messages(root: &Path, room: &str) -> String {
    let mut before = None;
    let mut result = String::new();
    let mut cursors = std::collections::BTreeSet::new();
    loop {
        let mut args = vec!["room", "read", room, "--json", "--limit", "100"];
        if let Some(before) = before.as_deref() {
            args.extend(["--before", before]);
        }
        let started = Instant::now();
        let shown = loop {
            let (ok, shown) = small_row_command(root, &args, None);
            if ok {
                break shown;
            }
            assert!(
                shown.contains("preparing its saved history")
                    && started.elapsed() < Duration::from_secs(240),
                "PRODUCT (staging): room read refused: {shown}"
            );
            std::thread::sleep(Duration::from_millis(100));
        };
        let rows: Vec<serde_json::Value> = shown
            .lines()
            .filter_map(|line| serde_json::from_str(line).ok())
            .filter(|row: &serde_json::Value| row.get("entry_hash").is_some())
            .collect();
        if rows.is_empty() {
            break;
        }
        let cursor = rows[0]["entry_hash"]
            .as_str()
            .expect("APPARATUS: row hash")
            .to_owned();
        assert!(
            cursors.insert(cursor.clone()),
            "PRODUCT: room paging repeated {cursor}"
        );
        result.push_str(&shown);
        before = Some(cursor);
    }
    result
}

fn small_row_seed(root: &Path, count: usize) -> ([u8; 32], String) {
    let (ok, said) = small_row_command(root, &["id"], None);
    assert!(ok, "PRODUCT (staging): identity: {said}");
    let (ok, said) = small_row_command(
        root,
        &[
            "room",
            "create",
            "--passphrase-file",
            "-",
            "--name",
            "packing",
        ],
        Some(&format!("{ROOMPASS}\n")),
    );
    assert!(ok, "PRODUCT (staging): room create: {said}");
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let mut client = rt
        .block_on(attach::node_client(root, "default"))
        .expect("APPARATUS: scratch IPC");
    use vox_core::node::ipc::{Frame, Request};
    let Frame::Rooms { rooms } = rt
        .block_on(client.request(&Request::Rooms { after: None }))
        .unwrap()
    else {
        panic!("APPARATUS: room listing response");
    };
    let cid = rooms
        .iter()
        .find(|(_, name, ..)| name == "packing")
        .expect("APPARATUS: created room")
        .0;
    for i in 0..count {
        let text = serde_json::json!({"v":1,"type":"session","from":format!("packed-{i:04}"),"body":format!("PACKED-ROW-{i:04}-{}", "x".repeat(256)), "at":{"session_name":format!("Packed {i:04}")},"data":{"session":{"harness":"small rows proof"}}}).to_string();
        let result = rt
            .block_on(client.request(&Request::Post {
                channel_id: cid,
                text,
                card: false,
            }))
            .unwrap();
        assert!(
            matches!(result, Frame::Ok),
            "PRODUCT (staging): append {i}: {result:?}"
        );
        let text = format!("PACKED-ROW-{i:04}-{}", "x".repeat(256));
        let result = rt
            .block_on(client.request(&Request::Post {
                channel_id: cid,
                text,
                card: false,
            }))
            .unwrap();
        assert!(
            matches!(result, Frame::Ok),
            "PRODUCT (staging): visible append {i}: {result:?}"
        );
    }
    (cid, vox_core::node::link::b32_encode(&cid))
}

#[test]
#[ignore = "real binary, physical stopped-store layout and restart; run in release"]
fn tiny_rows_share_leaves_beside_large_values() {
    watchdog::arm();
    let tmp = tempfile::tempdir().expect("APPARATUS: scratch profile");
    let root = tmp.path().join("node");
    std::fs::create_dir_all(root.join("cfg")).unwrap();
    let (ok, said) = small_row_command(&root, &["id"], None);
    assert!(ok, "PRODUCT (staging): id: {said}");
    let running = small_row_daemon(&root, None);
    small_row_ready(&root);
    let (_, room) = small_row_seed(&root, 160);
    let shown = small_row_all_messages(&root, &room);
    for i in 0..160 {
        assert!(
            shown.contains(&format!("PACKED-ROW-{i:04}-")),
            "PRODUCT: acknowledged row {i} missing before restart"
        );
    }
    drop(running);
    if let Some(fixture) = std::env::var_os("VOX_PROOF_OLD_STORE") {
        copy_small_row_profile(&root, Path::new(&fixture));
        std::fs::write(Path::new(&fixture).join("proof-room"), &room).unwrap();
    }
    assert_small_rows_share(&small_row_paths(&root).store_file());
    let running = small_row_daemon(&root, None);
    small_row_ready(&root);
    let shown = small_row_all_messages(&root, &room);
    for i in 0..160 {
        assert!(
            shown.contains(&format!("PACKED-ROW-{i:04}-")),
            "PRODUCT: acknowledged row {i} missing after restart"
        );
    }
    let (ok, said) = small_row_command(
        &root,
        &[
            "room",
            "create",
            "--passphrase-file",
            "-",
            "--name",
            "erase-only-this",
        ],
        Some(&format!("{ROOMPASS}\n")),
    );
    assert!(ok, "PRODUCT (staging): extra room: {said}");
    for verb in ["end", "leave"] {
        let (ok, said) = small_row_command(&root, &["room", verb, "erase-only-this"], None);
        assert!(ok, "PRODUCT: {verb} extra room: {said}");
    }
    let shown = small_row_all_messages(&root, &room);
    for i in 0..160 {
        assert!(
            shown.contains(&format!("PACKED-ROW-{i:04}-")),
            "PRODUCT: store rewrite erased another room's small row{i}"
        );
    }
    drop(running);
    let running = small_row_daemon(&root, None);
    small_row_ready(&root);
    let shown = small_row_all_messages(&root, &room);
    for i in 0..160 {
        assert!(
            shown.contains(&format!("PACKED-ROW-{i:04}-")),
            "PRODUCT: row{i} missing after other-room erasure and restart"
        );
    }
    drop(running);
}

#[test]
#[ignore = "real binary locator writes and authenticated stopped-store pages; run in release"]
fn locator_pages_fit_one_physical_page() {
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("node");
    std::fs::create_dir_all(root.join("cfg")).unwrap();
    let (ok, said) = small_row_command(&root, &["id"], None);
    assert!(ok, "PRODUCT (staging): id: {said}");
    let running = small_row_daemon(&root, None);
    small_row_ready(&root);
    let (cid, room) = small_row_seed(&root, 0);
    small_row_custom_posts(&root, &cid, 0..128);
    let shown = small_row_all_messages(&root, &room);
    for i in 0..128 {
        assert!(
            shown.contains(&format!("LEGACY-LOCATOR-{i:04}")),
            "PRODUCT: acknowledged custom row {i} missing"
        );
    }
    drop(running);
    if let Some(fixture) = std::env::var_os("VOX_PROOF_OLD_LOCATORS") {
        copy_small_row_profile(&root, Path::new(&fixture));
        std::fs::write(Path::new(&fixture).join("proof-room"), &room).unwrap();
    }
    let inspection = tmp.path().join("inspection");
    copy_small_row_profile(&root, &inspection);
    let pages = small_row_index_pages(&inspection, &cid);
    assert!(
        pages.iter().any(|(_, _, _, ranked)| *ranked)
            && pages.iter().any(|(_, _, _, ranked)| !ranked),
        "APPARATUS: both locator and ranked-render trees must be staged"
    );
    eprintln!("ACTIVE LOCATOR PAGES {pages:?}");
    assert!(pages.iter().all(|(_, bytes, _, _)| *bytes <= 4013),
        "PRODUCT: a locator page needs more than one 4096-byte leaf after sealing/key overhead: {pages:?}");
}

#[test]
#[ignore = "real binary interrupted old-store move; needs VOX_PROOF_OLD_STORE fixture"]
fn old_small_rows_move_atomically_when_their_room_opens() {
    watchdog::arm();
    let fixture = PathBuf::from(
        std::env::var_os("VOX_PROOF_OLD_STORE")
            .expect("APPARATUS: supply stopped baseline fixture VOX_PROOF_OLD_STORE"),
    );
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("old");
    copy_small_row_profile(&fixture, &root);
    let room = std::fs::read_to_string(root.join("proof-room")).unwrap();
    let store_file = small_row_paths(&root).store_file();
    let layout = small_row_leaves(&store_file);
    assert!(
        layout.single_small >= 80,
        "APPARATUS: no stranded old rows: {layout:?}"
    );
    let before = small_row_snapshot(&store_file);
    let identity_copy = tmp.path().join("identity");
    copy_small_row_profile(&root, &identity_copy);
    let mut identity =
        vox_core::node::profile::Profile::open(small_row_paths(&identity_copy)).unwrap();
    identity.unlock(IDENTITY.as_bytes()).unwrap();
    let creator = vox_core::node::link::b32_encode(&identity.fingerprint());
    drop(identity);
    let marker = tmp.path().join("move-committed");
    let mut running = small_row_daemon(&root, Some(&marker));
    let reached = within(240, || {
        if marker.exists() {
            return true;
        }
        let (ok, _) = small_row_command(&root, &["room", "read", &room, "--limit", "1"], None);
        ok
    });
    assert!(
        reached,
        "APPARATUS: old room did not reach its move/open boundary"
    );
    let interrupted = marker.exists();
    running
        .0
        .kill()
        .expect("APPARATUS: SIGKILL owned moving daemon");
    running.0.wait().unwrap();
    drop(running);
    assert_small_row_integrity(&before, &small_row_snapshot(&store_file));
    if !interrupted {
        assert_small_rows_share(&store_file);
        panic!("PRODUCT: old room opened without packing its small rows");
    }
    std::fs::remove_file(marker).unwrap();
    for restart in 0..2 {
        let running = small_row_daemon(&root, None);
        small_row_ready(&root);
        let shown = small_row_all_messages(&root, &room);
        for i in 0..160 {
            assert!(
                shown.contains(&format!("PACKED-ROW-{i:04}-")),
                "PRODUCT: acknowledged post{i} lost after interruption/restart{restart}"
            );
        }
        // EntryIndex is derived and restarts retire old pages; the complete reads above
        // establish that its rebuilt locator and render trees still serve every saved post.
        let sessions;
        let started = Instant::now();
        loop {
            let (ok, said) = small_row_command(&root, &["room", "sessions", &room, "--json"], None);
            if ok && (0..160).all(|i| said.contains(&format!("Packed {i:04}"))) {
                sessions = said;
                break;
            }
            assert!(
                started.elapsed() < Duration::from_secs(240),
                "PRODUCT: SessionIndex did not retain the160 acknowledged Session openings: {said}"
            );
            std::thread::sleep(Duration::from_millis(100));
        }
        assert!(!sessions.is_empty(), "PRODUCT: room's Sessions disappeared");
        // SessionIndex is derived and rebuilds after legacy Session restoration; the listing
        // must preserve every acknowledged Session name even though page IDs change.
        let (ok, roster) = small_row_command(&root, &["room", "roster", &room], None);
        assert!(
            ok && roster.lines().any(|line| line == creator),
            "PRODUCT: GovernanceIndex lost the room's creator/member: {roster}"
        );
        let (ok, admins) = small_row_command(&root, &["room", "admin", "list", &room], None);
        assert!(
            ok && admins.contains(&format!("{creator}  (creator)")),
            "PRODUCT: GovernanceIndex changed the creator's room permissions: {admins}"
        );
        // GovernanceIndex is derived and refreshes its authenticated catalog on restart;
        // roster and admin reads above must retain the original creator's permissions.
        drop(running);
        assert_small_row_integrity(&before, &small_row_snapshot(&store_file));
        assert_small_rows_share(&store_file);
    }
}

type SmallRowKey = ([u8; 32], u8, u64);
struct SmallRowSnapshot {
    rows: std::collections::BTreeMap<SmallRowKey, Vec<u8>>,
    duplicate: Vec<SmallRowKey>,
}

fn small_row_snapshot(store: &Path) -> SmallRowSnapshot {
    use redb::{ReadableDatabase, ReadableTable, TableDefinition};
    let tmp = tempfile::tempdir().unwrap();
    let copy = tmp.path().join("stopped.redb");
    std::fs::copy(store, &copy).unwrap();
    let db = redb::Database::open(copy).expect("PRODUCT: interrupted store could not repair");
    let txn = db.begin_read().unwrap();
    let mut rows = std::collections::BTreeMap::new();
    let mut duplicate = Vec::new();
    for name in ["segments", "small_segments"] {
        match txn.open_table(TableDefinition::<SmallRowKey, &[u8]>::new(name)) {
            Ok(table) => {
                for row in table.iter().unwrap() {
                    let (key, value) = row.expect("PRODUCT: stopped store has an unreadable row");
                    if rows.insert(key.value(), value.value().to_vec()).is_some() {
                        duplicate.push(key.value());
                    }
                }
            }
            Err(redb::TableError::TableDoesNotExist(_)) => {}
            Err(error) => panic!("PRODUCT: stopped store table could not be read: {error}"),
        }
    }
    SmallRowSnapshot { rows, duplicate }
}

fn assert_small_row_integrity(before: &SmallRowSnapshot, after: &SmallRowSnapshot) {
    assert!(
        after.duplicate.is_empty(),
        "PRODUCT: moved logical rows are duplicated across tables: {:?}",
        after.duplicate
    );
    for kind in [2, 3] {
        let old: std::collections::BTreeMap<_, _> = before
            .rows
            .iter()
            .filter(|(key, _)| key.1 == kind)
            .collect();
        let new: std::collections::BTreeMap<_, _> =
            after.rows.iter().filter(|(key, _)| key.1 == kind).collect();
        assert!(
            !old.is_empty(),
            "APPARATUS: no stable small rows of kind{kind}"
        );
        assert_eq!(
            old, new,
            "PRODUCT: moved stable kind{kind} changed keys or sealed bytes"
        );
    }
    for (key, _) in before
        .rows
        .iter()
        .filter(|(key, _)| !matches!(key.1, 2 | 3 | 11 | 12 | 14 | 15))
    {
        assert!(
            after.rows.contains_key(key),
            "PRODUCT: stored kind{} key was lost during the move: {key:?}",
            key.1
        );
    }
    // ProvisionalLog is an unpublished staging spool discarded once accepted or orphaned;
    // it is not a saved user record, so its row count is not stable across room preparation.
    // EntryIndex, SessionIndex and GovernanceIndex are derived; their user reads are checked
    // separately in the journey instead of requiring their retired page IDs to survive.
}

fn small_row_custom_posts(root: &Path, cid: &[u8; 32], rows: std::ops::Range<usize>) {
    use vox_core::node::ipc::{Frame, Request};
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let mut client = rt.block_on(attach::node_client(root, "default")).unwrap();
    for i in rows {
        let text = serde_json::json!({"v":1,"type":"legacy128-proof","from":"locator-author","body":format!("LEGACY-LOCATOR-{i:04}"),"at":{},"data":{}}).to_string();
        let response = rt
            .block_on(client.request(&Request::Post {
                channel_id: *cid,
                text,
                card: false,
            }))
            .unwrap();
        assert!(
            matches!(response, Frame::Ok),
            "PRODUCT (staging): custom post{i}: {response:?}"
        );
    }
}

#[test]
#[ignore = "real binary old 128-item pages; needs VOX_PROOF_OLD_LOCATORS baseline fixture"]
fn old_128_item_locator_pages_read_and_split_when_rewritten() {
    watchdog::arm();
    let fixture = PathBuf::from(
        std::env::var_os("VOX_PROOF_OLD_LOCATORS")
            .expect("APPARATUS: supply stopped baseline locator fixture"),
    );
    let room = std::fs::read_to_string(fixture.join("proof-room")).unwrap();
    let cid = vox_core::node::link::b32_decode(&room, "proof room").unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("legacy");
    let inspect = tmp.path().join("before");
    copy_small_row_profile(&fixture, &root);
    copy_small_row_profile(&fixture, &inspect);
    let old_pages = small_row_index_pages(&inspect, &cid);
    assert!(
        old_pages.iter().any(|(_, _, rows, _)| *rows == 128),
        "APPARATUS: baseline fixture did not retain a genuine 128-item page: {old_pages:?}"
    );
    let old_ids: std::collections::BTreeSet<_> = old_pages.iter().map(|(id, ..)| *id).collect();
    let running = small_row_daemon(&root, None);
    small_row_ready(&root);
    let shown = small_row_all_messages(&root, &room);
    for i in 0..128 {
        assert!(
            shown.contains(&format!("LEGACY-LOCATOR-{i:04}")),
            "PRODUCT: old128 page did not read row{i}"
        );
    }
    small_row_custom_posts(&root, &cid, 128..129);
    drop(running);
    let after_copy = tmp.path().join("after");
    copy_small_row_profile(&root, &after_copy);
    let pages = small_row_index_pages(&after_copy, &cid);
    assert!(
        pages
            .iter()
            .filter(|(id, ..)| !old_ids.contains(id))
            .all(|(_, bytes, _, _)| *bytes <= 4013),
        "PRODUCT: rewritten legacy128 page still needs an oversized allocation: {pages:?}"
    );
    let running = small_row_daemon(&root, None);
    small_row_ready(&root);
    let shown = small_row_all_messages(&root, &room);
    for i in 0..129 {
        assert!(
            shown.contains(&format!("LEGACY-LOCATOR-{i:04}")),
            "PRODUCT: old/new row{i} missing after restart"
        );
    }
    drop(running);
}

/// A failed optional layout conversion must not hide saved readable history.
#[test]
#[ignore = "real binary and a file-armed store write failure; run with test-knobs"]
fn a_failed_small_row_move_keeps_the_room_readable_and_retries() {
    watchdog::arm();
    let fixture = PathBuf::from(
        std::env::var_os("VOX_PROOF_OLD_STORE")
            .expect("APPARATUS: supply stopped baseline fixture VOX_PROOF_OLD_STORE"),
    );
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("node");
    copy_small_row_profile(&fixture, &root);
    let room = std::fs::read_to_string(root.join("proof-room")).unwrap();
    let arm = root.join("fail-small-row-move");
    std::fs::write(&arm, b"fail the optional packing write before commit\n").unwrap();
    let running = small_row_daemon(&root, None);
    let log_path = root.join("small-rows-daemon.err");
    assert!(
        within(240, || std::fs::read_to_string(&log_path)
            .unwrap_or_default()
            .contains("small-row move ENOSPC fault engaged before commit")),
        "APPARATUS: the packing write failure did not engage in the daemon"
    );
    let last = std::cell::RefCell::new(String::new());
    let readable = std::cell::Cell::new(false);
    let finished = within(240, || {
        let (ok, said) = small_row_command(&root, &["room", "read", &room, "--limit", "1"], None);
        *last.borrow_mut() = said;
        readable.set(ok);
        ok || std::fs::read_to_string(&log_path)
            .unwrap_or_default()
            .contains("stays closed")
    });
    let log = std::fs::read_to_string(&log_path).unwrap_or_default();
    eprintln!("MOVE FAILURE DAEMON LOG\n{log}");
    assert!(
        finished,
        "APPARATUS: failed move never reached an open or closed verdict: {}",
        last.borrow()
    );
    assert!(
        readable.get(),
        "PRODUCT: a failed optional small-row move kept the room closed: {}",
        last.borrow()
    );
    let shown = small_row_all_messages(&root, &room);
    for i in 0..160 {
        assert!(
            shown.contains(&format!("PACKED-ROW-{i:04}-")),
            "PRODUCT: failed small-row move hid acknowledged post{i}"
        );
    }
    drop(running);
    std::fs::remove_file(arm).unwrap();
    let running = small_row_daemon(&root, None);
    small_row_ready(&root);
    let shown = small_row_all_messages(&root, &room);
    for i in 0..160 {
        assert!(
            shown.contains(&format!("PACKED-ROW-{i:04}-")),
            "PRODUCT: retried small-row move lost acknowledged post{i}"
        );
    }
    // Packing is derived state: an acknowledged own post carries its unflushed
    // transactions to disk before the deliberately abrupt stop below.
    let (ok, said) = small_row_command(
        &root,
        &["room", "post", &room, "packing-retry-durable"],
        None,
    );
    assert!(
        ok,
        "PRODUCT: post after the packing retry was not saved: {said}"
    );
    drop(running);
    assert_small_rows_share(&small_row_paths(&root).store_file());
}

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
        let mut rows = std::collections::BTreeMap::new();
        for name in ["segments", "small_segments"] {
            match transaction.open_table(TableDefinition::<([u8; 32], u8, u64), &[u8]>::new(name)) {
                Ok(table) => {
                    for row in table.iter().expect("APPARATUS: segment rows") {
                        let (key, value) = row.expect("APPARATUS: segment row");
                        let (room, kind, position) = key.value();
                        if room == id && kind == 10 {
                            rows.insert((name, position), value.value().len());
                        }
                    }
                }
                Err(redb::TableError::TableDoesNotExist(_)) => {}
                Err(error) => panic!("APPARATUS: product segment table: {error}"),
            }
        }
        let small = rows
            .keys()
            .filter(|(name, _)| *name == "small_segments")
            .count();
        eprintln!(
            "PRODUCT STORE TABLE RECEIPT {tag}: small_segments kind-10 rows={small}; rows by (table, position)={rows:?}"
        );
        rows
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

    // The hashes of the wires the stopped driver keeps as private Session rows.
    let driver_rows = || {
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
            .map(|(position, sealed)| {
                let bytes =
                    open_segment(&sek, SegmentKind::PrivateSession, position, &sealed).unwrap();
                let mut d = Decoder::new(&bytes);
                d.array().unwrap();
                d.uint().unwrap();
                vox_core::hash::sha256(d.bytes().unwrap())
            })
            .collect::<Vec<_>>()
    };

    // An actual member's stopped profile supplies the apparatus identity and the
    // exact next ciphertexts. Only the running recipient decides acceptance.
    drop(driver.take());
    let pending = (4..11).map(|seq| append(seq, 256).1).collect::<Vec<_>>();
    drop(author.take());
    let mut tampered = Vec::new();
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
            .take(7)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .map(|(_, wire)| wire)
            .collect::<Vec<_>>();
        assert_eq!(wires.len(), 7, "APPARATUS: seven withheld steps");
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
        let signature_of = |wire: &[u8]| {
            let mut d = Decoder::new(wire);
            d.array().unwrap();
            d.uint().unwrap();
            d.bytes().unwrap();
            d.bytes().unwrap();
            d.bytes().unwrap().to_vec()
        };
        let mut position = 0;
        let _ = asks
            .recv_timeout(Duration::from_secs(90))
            .expect("APPARATUS: recipient did not ask authenticated peer");
        // `splice` puts the genuine signature of the withheld next step on this step's
        // genuine message: only a signature that covers the message refuses it.
        let arms = [
            "root-signature",
            "header",
            "room",
            "author",
            "ciphertext",
            "splice",
        ];
        for (index, arm) in arms.into_iter().enumerate() {
            let (wire, text) = (wires[index].clone(), pending[index].clone());
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
                "splice" => signature = signature_of(&wires[index + 1]),
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
            let forged = e.finish();
            tampered.push(vox_core::hash::sha256(&forged));
            position += 1;
            responses.send((position, forged)).unwrap();
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
        // The step whose signature was spliced is still read whole as it was written.
        position += 1;
        responses.send((position, wires[6].clone())).unwrap();
        expected.push(pending[6].clone());
        wait_replies(&b, &expected);
        eprintln!("PRODUCT TAMPER RECEIPT: the step whose signature was spliced read whole");
        drop(responses);
        serving.abort();
        drop((endpoint, attack_rt, profile));
    }
    drop(driver.take());
    let stored = driver_rows();
    assert!(
        tampered.iter().all(|hash| !stored.contains(hash))
            && authored.borrow().iter().all(|hash| stored
                .iter()
                .filter(|row| *row == hash)
                .count()
                == 1),
        "PRODUCT: recipient store does not hold each genuine step once and no forged step: \
         forged={tampered:?}, genuine={:?}, stored={stored:?}",
        authored.borrow()
    );
    eprintln!("PRODUCT TAMPER RECEIPT: recipient stored each genuine step once, no forged step");
    driver = Some(daemon_on(
        &b,
        "after-tamper-driver",
        &format!("{IDENTITY}\n{ROOMPASS}\n"),
        &driver_at,
    ));
    attached(&b, "after-tamper-driver");
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
    let (_, post_rotation) = append(11, 1024);
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
        driver_rows()
            .iter()
            .filter(|hash| authored.borrow().contains(hash))
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

/// A metadata change is measured only after the binary publishes the complete Session
/// listing. Allocations are sealed SessionIndex ids, not physical pages; OS write bytes
/// are reported separately. Plain private activity is a different input and is measured too.
/// Mutant: rebuild every Session on every candidate revision.
#[cfg(all(feature = "optional-proofs", target_os = "macos"))]
#[test]
#[ignore = "real binary with 100 and 1500 unrelated Sessions; run in release with test-knobs"]
fn a_session_change_rewrites_only_that_session() {
    use redb::{ReadableDatabase, ReadableTable, TableDefinition};
    use vox_core::node::ipc::{Frame, IpcClient, NodeSocket, Request};
    use vox_core::node::paths::{NodeName, Paths};
    watchdog::arm();
    let evidence = std::env::var_os("RG13_SESSION_LOCAL_EVIDENCE")
        .map(PathBuf::from)
        .expect("APPARATUS: RG13_SESSION_LOCAL_EVIDENCE receipt directory");
    std::fs::create_dir_all(&evidence).expect("APPARATUS: receipt directory");
    let tmp = tempfile::tempdir_in(&evidence).expect("APPARATUS: scratch profile");
    let root = tmp.path();
    std::fs::create_dir_all(root.join("cfg")).expect("APPARATUS: scratch config");
    let (ok, out, err) = vox(root, &["id"], None);
    assert!(ok, "APPARATUS: identity staging: {out}{err}");
    let keychain = attach::keychain(root);
    let pass = root.join("identity.pass");
    std::fs::write(&pass, IDENTITY).expect("APPARATUS: identity passphrase");
    let launch = |tag: &str, clock_step: i64| {
        let child = Command::new(VOX)
            .args(["daemon", "--listen", "127.0.0.1:0", "--passphrase-file"])
            .arg(&pass)
            .env("VOX_DATA_DIR", root)
            .env("VOX_CONFIG_DIR", root.join("cfg"))
            .env("VOX_TEST_KEYCHAIN", &keychain)
            .env("VOX_PROXY", "127.0.0.1:0")
            .env("VOX_TEST_CLOCK_STEP_MS", clock_step.to_string())
            .env_remove("VOX_NODE")
            .env_remove("VOX_ROOM")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(
                std::fs::File::create(evidence.join(format!("{tag}.daemon.log")))
                    .expect("APPARATUS: daemon log"),
            )
            .spawn()
            .expect("APPARATUS: scratch daemon");
        let daemon = Daemon(child);
        attached(root, tag);
        daemon
    };
    let running = launch("initial", 0);
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("APPARATUS: IPC runtime");
    let paths = Paths::resolve("default", Some(root), Some(&root.join("cfg")))
        .expect("APPARATUS: scratch paths");
    // Decode only the allocator field of the copied product header. The highest live
    // row id misses pages allocated and retired during cleanup, so it is not a count.
    let vault = vox_core::atrest::vault::IdentityVault::from_canonical_slice(
        &std::fs::read(paths.vault_file()).expect("APPARATUS: scratch identity vault"),
    )
    .expect("APPARATUS: scratch vault format");
    let signer = vault
        .unlock_signer(IDENTITY.as_bytes())
        .expect("APPARATUS: scratch vault unlock");
    let mut client = rt
        .block_on(IpcClient::open_at(&NodeSocket::one_shot(
            paths.account().socket(),
            NodeName::parse("default").expect("APPARATUS: node name"),
        )))
        .expect("APPARATUS: daemon IPC");
    let request = |client: &mut IpcClient, request: Request| {
        let deadline = Instant::now() + Duration::from_secs(300);
        loop {
            let frame = rt
                .block_on(client.request(&request))
                .expect("APPARATUS: IPC request");
            // These replies explicitly report that this request made no change, or ask the
            // caller to wait for governance. The product fact, not a guessed sleep, gates staging.
            let retry = matches!(&frame, Frame::Error { reason } if
                reason.contains("permissions are still being read") ||
                reason.contains("room governance is refreshing") ||
                reason == &vox_core::node::api::Fault::RoomChangePending.to_string());
            if !retry {
                return frame;
            }
            assert!(
                Instant::now() < deadline,
                "APPARATUS: governance never became ready: {frame:?}"
            );
            std::thread::sleep(Duration::from_millis(100));
        }
    };
    let disk_writes = || {
        libproc::libproc::pid_rusage::pidrusage::<libproc::libproc::pid_rusage::RUsageInfoV2>(
            i32::try_from(running.0.id()).expect("APPARATUS: daemon PID"),
        )
        .expect("APPARATUS: daemon OS write counter")
        .ri_diskio_byteswritten
    };
    let sample = |cid: &[u8; 32], tag: &str| {
        let copy = evidence.join(format!("{tag}.redb"));
        std::fs::copy(paths.store_file(), &copy).expect("APPARATUS: durable store copy");
        let db = redb::Database::open(&copy).expect("APPARATUS: copied product store");
        let txn = db.begin_read().expect("APPARATUS: copied read transaction");
        let mut bytes = 0u64;
        for name in ["segments", "small_segments"] {
            match txn.open_table(TableDefinition::<([u8; 32], u8, u64), &[u8]>::new(name)) {
                Ok(table) => {
                    for row in table.iter().expect("APPARATUS: product rows") {
                        let (key, value) = row.expect("APPARATUS: product row");
                        let (room, kind, _) = key.value();
                        if &room == cid && kind == 14 {
                            bytes += value.value().len() as u64;
                        }
                    }
                }
                Err(redb::TableError::TableDoesNotExist(_)) => {}
                Err(error) => panic!("APPARATUS: product segment table: {error}"),
            }
        }
        drop(txn);
        drop(db);
        let stored = vox_core::node::store::Store::open_read_only(&copy)
            .expect("APPARATUS: copied store reader");
        let wrap = stored
            .get_sek_wrap(cid)
            .expect("APPARATUS: room wrap read")
            .expect("APPARATUS: room wrap");
        let sek = wrap
            .unwrap_sek(
                &vox_core::atrest::idfactor::SignatureIdentityFactor::new(&signer),
                cid,
                ROOMPASS.as_bytes(),
            )
            .expect("APPARATUS: scratch room key");
        let segment = stored
            .get_segment(cid, vox_core::atrest::store::SegmentKind::SessionIndex, 0)
            .expect("APPARATUS: copied Session header read")
            .expect("APPARATUS: copied Session header");
        let header = vox_core::atrest::store::open_segment(
            &sek,
            vox_core::atrest::store::SegmentKind::SessionIndex,
            0,
            &segment,
        )
        .expect("APPARATUS: copied Session header authentication");
        let mut d = vox_core::cbor::Decoder::new(&header);
        let shape = (
            d.array().expect("APPARATUS: header arity"),
            d.uint().expect("APPARATUS: header version"),
        );
        assert!(
            matches!(shape, (12, 1) | (14, 2)),
            "APPARATUS: unsupported copied header {shape:?}"
        );
        let next = d.uint().expect("APPARATUS: exact Session allocator");
        (next, bytes)
    };
    let mut measured = Vec::new();
    let mut index_costs = Vec::new();
    let mut preserved = Vec::new();
    let mut sizes = vec![100usize, 1500];
    if let Ok(count) = std::env::var("RG13_SESSION_LOCAL_LARGER_COUNT") {
        sizes.push(
            count
                .parse()
                .expect("APPARATUS: larger Session count must be an integer"),
        );
    }
    for n in sizes {
        let name = format!("local-{n}");
        let (ok, out, err) = vox(
            root,
            &["room", "create", "--name", &name, "--passphrase-file", "-"],
            Some(ROOMPASS),
        );
        assert!(ok, "APPARATUS: room staging: {out}{err}");
        let Frame::Rooms { rooms } = request(&mut client, Request::Rooms { after: None }) else {
            panic!("APPARATUS: room listing");
        };
        let cid = rooms
            .iter()
            .find(|(_, label, ..)| label == &name)
            .expect("APPARATUS: created room")
            .0;
        let room = vox_core::node::link::b32_encode(&cid);
        let metadata = |id: &str, name: &str| {
            serde_json::json!({
            "v":1,"type":"session","from":id,"body":"","at":{"session_name":name},
            "data":{"session":{"harness":"rg13 locality"}}})
            .to_string()
        };
        for i in 0..=n {
            let frame = request(
                &mut client,
                Request::Post {
                    channel_id: cid,
                    text: metadata(&format!("other-{i:04}"), &format!("Other {i:04}")),
                    card: false,
                },
            );
            assert!(
                matches!(frame, Frame::Ok),
                "APPARATUS: seed {n}/{i}: {frame:?}"
            );
        }
        let heads = |needle: &str| {
            let deadline = Instant::now() + Duration::from_secs(1200);
            loop {
                let (ok, out, err) = vox(root, &["room", "sessions", &room, "--json"], None);
                let rows: Vec<serde_json::Value> = out
                    .lines()
                    .filter_map(|l| serde_json::from_str(l).ok())
                    .collect();
                if ok
                    && rows.len() == n + 1
                    && out.contains(needle)
                    && !err.contains("provisional")
                    && !err.contains("fetching")
                {
                    return rows;
                }
                assert!(
                    Instant::now() < deadline,
                    "APPARATUS: complete Session publication not reached n={n}: {out}{err}"
                );
                std::thread::sleep(Duration::from_millis(100));
            }
        };
        heads("Other 0000");
        let append = |client: &mut IpcClient, id: &str, body: String| {
            let frame = request(
                client,
                Request::AppendSession {
                    channel_id: cid,
                    session_id: id.to_owned(),
                    body,
                },
            );
            assert!(
                matches!(frame, Frame::Appended { .. }),
                "APPARATUS: append: {frame:?}"
            );
        };
        let step = |seq| {
            serde_json::json!({"v":1,"session":"other-0000","kind":"reply",
            "seq":seq,"text":format!("TARGET-STEP-{seq} with literal session_name prose")})
            .to_string()
        };
        append(
            &mut client,
            "other-0001",
            serde_json::json!({"v":1,"session":"other-0001",
            "kind":"reply","seq":1,"text":"UNCHANGED-STEP"})
            .to_string(),
        );
        append(&mut client, "other-0000", step(1));
        append(&mut client, "other-0000", step(2));
        let read_step = |id: &str, needle: &str| {
            let deadline = Instant::now() + Duration::from_secs(300);
            loop {
                let _ = vox(root, &["room", "sessions", &room, "--json"], None);
                let (ok, out, err) = vox(root, &["room", "session", &room, id, "--json"], None);
                if ok && out.contains(needle) {
                    return;
                }
                assert!(
                    Instant::now() < deadline,
                    "APPARATUS: Session step not readable: {out}{err}"
                );
                std::thread::sleep(Duration::from_millis(100));
            }
        };
        read_step("other-0000", "TARGET-STEP-2");
        read_step("other-0001", "UNCHANGED-STEP");
        let unchanged = |rows: Vec<serde_json::Value>| {
            assert!(
                rows.windows(2)
                    .all(|rows| rows[0]["opened_millis"].as_u64()
                        <= rows[1]["opened_millis"].as_u64()),
                "PRODUCT: Session listing is not oldest opening first"
            );
            rows.into_iter()
                .filter(|row| row["id"] != "other-0000")
                .collect::<Vec<_>>()
        };
        let before_heads = unchanged(heads("Other 0000"));
        // A normal durable post fences the product's derived roots. Sample only after
        // complete public publication and after retired-root work has stopped allocating.
        let settle = |tag: &str| {
            post(root, &room, "RG13-DURABILITY-FENCE");
            let deadline = Instant::now() + Duration::from_secs(300);
            let mut prior = None;
            let mut stable = 0;
            loop {
                let current = sample(&cid, tag);
                if prior == Some(current) {
                    stable += 1;
                } else {
                    stable = 0;
                }
                if stable == 3 {
                    return current;
                }
                assert!(
                    Instant::now() < deadline,
                    "APPARATUS: derived cleanup never settled"
                );
                prior = Some(current);
                std::thread::sleep(Duration::from_millis(200));
            }
        };
        let before = settle(&format!("n{n}-step-before"));
        let writes = disk_writes();
        append(&mut client, "other-0000", step(3));
        read_step("other-0000", "TARGET-STEP-3");
        let after = settle(&format!("n{n}-step-after"));
        let step_delta = after.0 - before.0;
        let step_bytes = disk_writes() - writes;
        let before = after;
        let writes = disk_writes();
        append(
            &mut client,
            "other-0000",
            metadata("other-0000", "CHANGED-TARGET"),
        );
        let after_heads = heads("CHANGED-TARGET");
        assert_eq!(
            unchanged(after_heads),
            before_heads,
            "PRODUCT: changing one Session changed unrelated Session names or state"
        );
        let after = settle(&format!("n{n}-name-after"));
        let name_delta = after.0 - before.0;
        let name_bytes = disk_writes() - writes;
        let receipt = serde_json::json!({"unrelated_sessions":n,"ordinary_step_allocations":step_delta,
            "ordinary_step_os_write_bytes":step_bytes,"name_change_allocations":name_delta,
            "name_change_os_write_bytes":name_bytes,"session_index_value_bytes":after.1});
        std::fs::write(evidence.join(format!("n{n}.json")), receipt.to_string())
            .expect("APPARATUS: measurement receipt");
        eprintln!("RG13 SESSION LOCALITY {receipt}");
        measured.push((step_bytes, name_bytes));
        eprintln!(
            "RG13 INDEX COST n={n}: encrypted_index_bytes={} bytes_per_session={:.3}",
            after.1,
            after.1 as f64 / (n + 1) as f64
        );
        index_costs.push((n, after.1));
        // A late/out-of-order multipart dependency is not a Session until its complete
        // canonical body hashes correctly. Replaying it must preserve unrelated heads.
        let large_name = format!("MULTIPART-{n}-{}", "m".repeat(2400));
        let inner = metadata("other-0000", &large_name);
        let tag = vox_core::node::link::b32_encode(&vox_core::hash::sha256(inner.as_bytes()));
        let outer = serde_json::json!({"v":1,"type":"session","body":inner,
            "data":{"session_parts":tag}});
        let parts = vox_agentcomms::activity::split(
            outer
                .as_object()
                .expect("APPARATUS: multipart object")
                .clone(),
            "body",
            512,
        );
        assert!(
            parts.len() > 1,
            "APPARATUS: multipart staging did not split"
        );
        for part in parts.iter().rev().chain(parts.iter()) {
            append(&mut client, "other-0000", part.clone());
        }
        let complete = heads(&large_name);
        assert_eq!(
            unchanged(complete),
            before_heads,
            "PRODUCT: reordered multipart metadata changed another Session"
        );
        eprintln!("RG13 canonical reordered multipart n={n}: complete name and unchanged peers");
        preserved.push((room, before_heads));
    }
    let (ok, out, err) = vox(
        root,
        &[
            "room",
            "create",
            "--name",
            "removal",
            "--passphrase-file",
            "-",
        ],
        Some(ROOMPASS),
    );
    assert!(ok, "APPARATUS: removal room: {out}{err}");
    let Frame::Rooms { rooms } = request(&mut client, Request::Rooms { after: None }) else {
        panic!("APPARATUS: removal room listing");
    };
    let removal_id = rooms
        .iter()
        .find(|(_, name, ..)| name == "removal")
        .expect("APPARATUS: removal id")
        .0;
    let removal = vox_core::node::link::b32_encode(&removal_id);
    let old = serde_json::json!({"v":1,"type":"session","from":"expired","body":"",
        "at":{"session_name":"EXPIRED-METADATA"}});
    assert!(
        matches!(
            request(
                &mut client,
                Request::Post {
                    channel_id: removal_id,
                    text: old.to_string(),
                    card: false
                }
            ),
            Frame::Ok
        ),
        "APPARATUS: removal source"
    );
    let deadline = Instant::now() + Duration::from_secs(300);
    loop {
        let (ok, out, err) = vox(root, &["room", "sessions", &removal, "--json"], None);
        if ok && out.contains("EXPIRED-METADATA") {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "APPARATUS: removal source publication: {out}{err}"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    let policy = request(
        &mut client,
        Request::SetRetention {
            channel_id: removal_id,
            ttl: 3600,
        },
    );
    assert!(
        !matches!(policy, Frame::Error { .. }),
        "APPARATUS: removal retention: {policy:?}"
    );
    post(root, &removal, "REMOVAL-DURABILITY-FENCE");
    drop(client);
    drop(running);
    let restarted = launch("restarted", 7_200_000);
    for (room, expected) in preserved {
        let deadline = Instant::now() + Duration::from_secs(300);
        loop {
            let (ok, out, err) = vox(root, &["room", "sessions", &room, "--json"], None);
            let rows: Vec<serde_json::Value> = out
                .lines()
                .filter_map(|line| serde_json::from_str(line).ok())
                .filter(|row: &serde_json::Value| row["id"] != "other-0000")
                .collect();
            if ok
                && rows.len() == expected.len()
                && !err.contains("provisional")
                && !err.contains("fetching")
            {
                assert_eq!(
                    rows, expected,
                    "PRODUCT: restart changed unrelated Sessions"
                );
                break;
            }
            assert!(
                Instant::now() < deadline,
                "APPARATUS: restart Session publication: {out}{err}"
            );
            std::thread::sleep(Duration::from_millis(100));
        }
        loop {
            let _ = vox(root, &["room", "sessions", &room, "--json"], None);
            let (ok, out, err) = vox(
                root,
                &["room", "session", &room, "other-0001", "--json"],
                None,
            );
            if ok {
                assert!(
                    out.contains("UNCHANGED-STEP"),
                    "PRODUCT: unchanged Session's saved step did not survive restart: {out}{err}"
                );
                break;
            }
            assert!(
                err.contains("Sessions changed; refresh the listing") && Instant::now() < deadline,
                "APPARATUS: restart Session read did not reach its current listing: {out}{err}"
            );
        }
    }
    let deadline = Instant::now() + Duration::from_secs(300);
    loop {
        let (ok, out, err) = vox(root, &["room", "sessions", &removal, "--json"], None);
        if ok && out.trim().is_empty() && !err.contains("provisional") {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "PRODUCT: expired Session metadata survived source removal: {out}{err}"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    eprintln!("RG13 canonical removal: expired source no longer publishes a Session");
    let (ok, out, err) = vox(
        root,
        &[
            "room",
            "create",
            "--name",
            "reordered-time",
            "--passphrase-file",
            "-",
        ],
        Some(ROOMPASS),
    );
    assert!(ok, "APPARATUS: reordered room: {out}{err}");
    let (ok, out, err) = vox(root, &["room", "list"], None);
    assert!(ok, "APPARATUS: reordered room listing: {out}{err}");
    let reordered = out
        .lines()
        .find(|line| line.contains("reordered-time"))
        .and_then(|line| line.split_whitespace().next())
        .expect("APPARATUS: reordered room id")
        .to_owned();
    let metadata = |name: &str| {
        serde_json::json!({"v":1,"type":"session","from":"ordered","body":"",
        "at":{"session_name":name}})
        .to_string()
    };
    post(root, &reordered, &metadata("CANONICAL-LATER"));
    drop(restarted);
    let _final = launch("earlier-clock", 0);
    let deadline = Instant::now() + Duration::from_secs(300);
    loop {
        let (ok, out, err) = vox(root, &["room", "sessions", &reordered, "--json"], None);
        if ok && out.contains("CANONICAL-LATER") && !err.contains("provisional") {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "APPARATUS: reordered room has not reopened before its next post: {out}{err}"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    post(root, &reordered, &metadata("ARRIVED-LATE-BUT-EARLIER"));
    post(root, &reordered, "REORDERED-DURABILITY-FENCE");
    let deadline = Instant::now() + Duration::from_secs(300);
    loop {
        let (ok, out, err) = vox(root, &["room", "sessions", &reordered, "--json"], None);
        if ok && out.contains("CANONICAL-LATER") && !err.contains("provisional") {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "PRODUCT: metadata followed arrival rather than canonical time: {out}{err}"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    eprintln!("RG13 canonical order: later event wins despite earlier event arriving last");
    let mut failures = Vec::new();
    for (column, label) in [
        (0, "ordinary private step"),
        (1, "private lifecycle/name change"),
    ] {
        let small = if column == 0 {
            measured[0].0
        } else {
            measured[0].1
        };
        let large = if column == 0 {
            measured[1].0
        } else {
            measured[1].1
        };
        let bound = small.saturating_mul(3).saturating_add(256 * 1024);
        eprintln!("RG13 OUTSIDE {label}: 100={small} OS-write bytes; 1500={large}; bound={bound}; passed={}", large <= bound);
        if large > bound {
            failures.push(format!("PRODUCT: {label} rewrote unrelated Sessions: 100={small} OS-write bytes; 1500={large}; bound={bound}"));
        }
    }
    for &(n, bytes) in &index_costs {
        let bound = 2100 * (n as u64 + 1);
        if bytes > bound {
            failures.push(format!("PRODUCT: encrypted Session index exceeds 2100 bytes per Session at {n} unrelated Sessions: {bytes} bytes; bound={bound}"));
        }
    }
    let (small_n, small_bytes) = index_costs[0];
    let (large_n, large_bytes) = index_costs[1];
    if u128::from(large_bytes) * (small_n as u128 + 1) * 100
        > u128::from(small_bytes) * (large_n as u128 + 1) * 103
    {
        failures.push("PRODUCT: encrypted index bytes per Session grew by more than 3% between 100 and 1500 unrelated Sessions".to_owned());
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// The first fixed read must preserve the base binary's published order, even while
/// lazy membership backfill is held before it takes a writer. The hold/receipt are
/// apparatus only; verdicts are the binary's listing and the daemon's OS write bytes.
#[cfg(all(feature = "optional-proofs", target_os = "macos"))]
#[test]
#[ignore = "BASE-to-fixed real binary upgrade; run in release with test-knobs"]
fn an_existing_session_index_keeps_its_listing_when_upgraded() {
    watchdog::arm();
    let evidence = std::env::var_os("RG13_SESSION_LOCAL_EVIDENCE")
        .map(PathBuf::from)
        .expect("APPARATUS: upgrade receipt directory");
    let base = std::env::var_os("RG13_SESSION_BASE_VOX")
        .map(PathBuf::from)
        .expect("APPARATUS: pinned c5b12cef4 binary");
    let fresh = std::env::var_os("RG13_SESSION_FRESH_RECEIPTS")
        .map(PathBuf::from)
        .expect("APPARATUS: fresh fixed outside measurements");
    std::fs::create_dir_all(&evidence).expect("APPARATUS: upgrade receipts");
    let mut tmp = tempfile::tempdir_in(&evidence).expect("APPARATUS: upgrade scratch profile");
    tmp.disable_cleanup(true);
    eprintln!(
        "RG13 UPGRADE retained scratch profile {}",
        tmp.path().display()
    );
    let root = tmp.path();
    std::fs::create_dir_all(root.join("cfg")).expect("APPARATUS: upgrade config");
    let keychain = attach::keychain(root);
    let pass = root.join("identity.pass");
    std::fs::write(&pass, IDENTITY).expect("APPARATUS: upgrade passphrase");
    let run = |exe: &Path, argv: &[&str], input: Option<&str>| {
        let mut child = Command::new(exe)
            .args(argv)
            .env("VOX_DATA_DIR", root)
            .env("VOX_CONFIG_DIR", root.join("cfg"))
            .env("VOX_TEST_KEYCHAIN", &keychain)
            .env("VOX_PROXY", "127.0.0.1:0")
            .env_remove("VOX_NODE")
            .env_remove("VOX_ROOM")
            .env_remove("VOX_SESSION")
            .stdin(if input.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("APPARATUS: upgrade CLI");
        if let Some(input) = input {
            child
                .stdin
                .take()
                .expect("APPARATUS: upgrade stdin")
                .write_all(input.as_bytes())
                .expect("APPARATUS: upgrade CLI input");
        }
        let out = child
            .wait_with_output()
            .expect("APPARATUS: upgrade CLI result");
        (
            out.status.success(),
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    };
    let fixed = Path::new(VOX);
    let id = run(
        &base,
        &[
            "id",
            "--identity-passphrase-file",
            pass.to_str().expect("APPARATUS: pass path"),
        ],
        None,
    );
    assert!(id.0, "APPARATUS: base identity: {id:?}");
    let launch = |exe: &Path, tag: &str, hold: bool| {
        let mut command = Command::new(exe);
        command
            .args(["daemon", "--listen", "127.0.0.1:0", "--passphrase-file"])
            .arg(&pass)
            .env("VOX_DATA_DIR", root)
            .env("VOX_CONFIG_DIR", root.join("cfg"))
            .env("VOX_TEST_KEYCHAIN", &keychain)
            .env("VOX_PROXY", "127.0.0.1:0")
            .env_remove("VOX_NODE")
            .env_remove("VOX_ROOM")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(
                std::fs::File::create(evidence.join(format!("upgrade-{tag}.daemon.log")))
                    .expect("APPARATUS: upgrade daemon log"),
            );
        if hold {
            command.env("VOX_TEST_HOLD_SESSION_BACKFILL", root.join("backfill"));
        }
        Daemon(command.spawn().expect("APPARATUS: upgrade daemon"))
    };
    let base_daemon = launch(&base, "base", false);
    let deadline = Instant::now() + Duration::from_secs(240);
    loop {
        let listed = run(&base, &["room", "list"], None);
        if listed.0 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "APPARATUS: base daemon not ready: {listed:?}"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    let created = run(
        &base,
        &[
            "room",
            "create",
            "--name",
            "upgrade",
            "--passphrase-file",
            "-",
        ],
        Some(ROOMPASS),
    );
    assert!(created.0, "APPARATUS: base room: {created:?}");
    let listed = run(&base, &["room", "list"], None);
    assert!(listed.0, "APPARATUS: base room listing: {listed:?}");
    let room = listed
        .1
        .lines()
        .find(|line| line.contains("upgrade"))
        .and_then(|line| line.split_whitespace().next())
        .expect("APPARATUS: upgrade room id")
        .to_owned();
    let metadata = |i: usize, name: &str| {
        serde_json::json!({"v":1,"type":"session",
        "from":format!("upgrade-{i:04}"),"body":"","at":{"session_name":name},
        "data":{"session":{"harness":"rg13 upgrade"}}})
        .to_string()
    };
    for i in 0..=100 {
        let posted = run(
            &base,
            &[
                "room",
                "post",
                &room,
                &metadata(i, &format!("Upgrade {i:04}")),
            ],
            None,
        );
        assert!(posted.0, "APPARATUS: base Session {i}: {posted:?}");
    }
    // The terminal's room label/id is abbreviated. Scope the hold by the full room
    // identity returned by the BASE daemon, not by that display abbreviation.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let paths =
        vox_core::node::paths::Paths::resolve("default", Some(root), Some(&root.join("cfg")))
            .unwrap();
    let mut client = rt
        .block_on(vox_core::node::ipc::IpcClient::open_at(
            &vox_core::node::ipc::NodeSocket::one_shot(
                paths.account().socket(),
                vox_core::node::paths::NodeName::parse("default").unwrap(),
            ),
        ))
        .unwrap();
    let rooms = rt
        .block_on(client.request(&vox_core::node::ipc::Request::Rooms { after: None }))
        .expect("APPARATUS: base full room identities");
    let vox_core::node::ipc::Frame::Rooms { rooms } = rooms else {
        panic!("APPARATUS: base full room listing frame");
    };
    let cid = rooms
        .iter()
        .find(|(_, name, ..)| name == "upgrade")
        .expect("APPARATUS: base full upgrade room")
        .0;
    let full_room = vox_core::node::link::b32_encode(&cid);
    drop(client);
    let parse = |output: &(bool, String, String)| -> Vec<serde_json::Value> {
        output
            .1
            .lines()
            .filter(|line| !line.is_empty())
            .map(|line| serde_json::from_str(line).expect("APPARATUS: Session JSON line"))
            .collect()
    };
    let deadline = Instant::now() + Duration::from_secs(300);
    let golden = loop {
        let shown = run(&base, &["room", "sessions", &room, "--json"], None);
        if shown.0 && !shown.2.contains("provisional") {
            let rows = parse(&shown);
            if rows.len() == 101 {
                break rows;
            }
        }
        assert!(
            Instant::now() < deadline,
            "APPARATUS: base publication incomplete: {shown:?}"
        );
        std::thread::sleep(Duration::from_millis(100));
    };
    assert!(
        golden
            .windows(2)
            .all(|pair| pair[0]["opened_millis"].as_u64() <= pair[1]["opened_millis"].as_u64()),
        "APPARATUS: base fixture was not oldest opening first"
    );
    let fence = run(
        &base,
        &["room", "post", &room, "UPGRADE-BASE-DURABILITY-FENCE"],
        None,
    );
    assert!(fence.0, "APPARATUS: base durable fixture: {fence:?}");
    std::fs::write(
        evidence.join("upgrade-base-listing.json"),
        serde_json::to_vec(&golden).unwrap(),
    )
    .expect("APPARATUS: base listing receipt");
    drop(base_daemon);
    let hold = root.join("backfill");
    std::fs::create_dir(&hold).expect("APPARATUS: backfill staging directory");
    std::fs::write(hold.join("arm"), &full_room).expect("APPARATUS: arm exact room backfill");
    let daemon = launch(fixed, "fixed", true);
    struct Release(PathBuf);
    impl Drop for Release {
        fn drop(&mut self) {
            let _ = std::fs::write(self.0.join("release"), "");
        }
    }
    let release = Release(hold.clone());
    let deadline = Instant::now() + Duration::from_secs(300);
    while !hold.join("engaged").exists() {
        if Instant::now() >= deadline {
            let status = run(fixed, &["status", "--json"], None);
            panic!(
                "APPARATUS: base index did not reach held backfill; status={status:?}; log={}",
                std::fs::read_to_string(evidence.join("upgrade-fixed.daemon.log"))
                    .unwrap_or_default()
            );
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(
        std::fs::read_to_string(hold.join("engaged")).unwrap(),
        full_room,
        "APPARATUS: a different room engaged the backfill hold"
    );
    let first = run(fixed, &["room", "sessions", &room, "--json"], None);
    eprintln!(
        "RG13 UPGRADE first read while backfill held: ok={} rows={} log={}",
        first.0,
        first.1.lines().count(),
        std::fs::read_to_string(evidence.join("upgrade-fixed.daemon.log")).unwrap_or_default()
    );
    assert!(
        first.0,
        "PRODUCT: first fixed read refused the base Session listing: {first:?}"
    );
    assert_eq!(
        parse(&first),
        golden,
        "PRODUCT: first fixed read changed the base's oldest-first Session listing"
    );
    drop(release);
    let deadline = Instant::now() + Duration::from_secs(300);
    while !hold.join("published").exists() {
        assert!(
            Instant::now() < deadline,
            "APPARATUS: backfill did not report complete publication; log={}",
            std::fs::read_to_string(evidence.join("upgrade-fixed.daemon.log")).unwrap_or_default()
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    let after = loop {
        let after = run(fixed, &["room", "sessions", &room, "--json"], None);
        if after.0 {
            break after;
        }
        // Publication can invalidate a multi-page read between its stamp and rows.
        // Follow only that explicit read-only retry; never treat a refused write as saved.
        assert!(
            after
                .2
                .contains("Sessions changed while listing; run the command again")
                && Instant::now() < deadline,
            "PRODUCT: completed backfill refused its listing: {after:?}"
        );
    };
    assert_eq!(
        parse(&after),
        golden,
        "PRODUCT: published backfill changed the base's oldest-first Session listing"
    );
    eprintln!(
        "RG13 UPGRADE first and published listings identical: {} oldest-first Sessions",
        golden.len()
    );
    let writes = || {
        libproc::libproc::pid_rusage::pidrusage::<libproc::libproc::pid_rusage::RUsageInfoV2>(
            i32::try_from(daemon.0.id()).unwrap(),
        )
        .expect("APPARATUS: upgraded daemon write counter")
        .ri_diskio_byteswritten
    };
    // Let retired backfill pages leave the writer before measuring an ordinary rename.
    // The durable product store's file bytes are outside data, not an allocator verdict.
    let paths =
        vox_core::node::paths::Paths::resolve("default", Some(root), Some(&root.join("cfg")))
            .unwrap();
    let deadline = Instant::now() + Duration::from_secs(300);
    let mut prior = None;
    let mut stable = 0;
    loop {
        let metadata =
            std::fs::metadata(paths.store_file()).expect("APPARATUS: upgraded store metadata");
        let current = (
            metadata.len(),
            metadata
                .modified()
                .expect("APPARATUS: store modification time"),
        );
        if prior == Some(current) {
            stable += 1;
        } else {
            stable = 0;
        }
        if stable == 5 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "APPARATUS: backfill cleanup did not settle"
        );
        prior = Some(current);
        std::thread::sleep(Duration::from_millis(200));
    }
    let before = writes();
    let renamed = run(
        fixed,
        &["room", "post", &room, &metadata(0, "UPGRADED-TARGET")],
        None,
    );
    assert!(
        renamed.0,
        "PRODUCT: upgraded room refused a rename: {renamed:?}"
    );
    let deadline = Instant::now() + Duration::from_secs(300);
    loop {
        let shown = run(fixed, &["room", "sessions", &room, "--json"], None);
        if shown.0 && shown.1.contains("UPGRADED-TARGET") && !shown.2.contains("provisional") {
            let rows = parse(&shown);
            let unchanged = |rows: Vec<serde_json::Value>| {
                rows.into_iter()
                    .filter(|row| row["id"] != "upgrade-0000")
                    .collect::<Vec<_>>()
            };
            assert_eq!(
                unchanged(rows),
                unchanged(golden),
                "PRODUCT: upgraded rename changed other Sessions or order"
            );
            break;
        }
        assert!(
            Instant::now() < deadline,
            "PRODUCT: upgraded rename did not appear in its Session listing: {shown:?}"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    let fence = run(
        fixed,
        &["room", "post", &room, "UPGRADE-RENAME-DURABILITY-FENCE"],
        None,
    );
    assert!(fence.0, "APPARATUS: upgrade rename fence: {fence:?}");
    let bytes = writes() - before;
    let fresh: serde_json::Value = serde_json::from_slice(
        &std::fs::read(fresh.join("n100.json")).expect("APPARATUS: fresh outside measurements"),
    )
    .expect("APPARATUS: fresh metrics JSON");
    let reference = fresh["name_change_os_write_bytes"]
        .as_u64()
        .expect("APPARATUS: fresh name write bytes");
    let bound = reference.saturating_mul(3).saturating_add(256 * 1024);
    eprintln!("RG13 UPGRADE rename OS-write bytes={bytes} fresh100={reference} bound={bound}");
    assert!(bytes<=bound,"PRODUCT: rename after upgrading the base index rewrote unrelated Sessions: {bytes} OS-write bytes; bound={bound}");
}

/// A restart reclaims deleted bodies without losing the messages or private steps we kept.
/// The crash arm kills the real daemon after backend relocation but before that commit.
#[cfg(feature = "test-knobs")]
#[test]
#[ignore = "real daemon, grown/expired store and crash during in-place compaction"]
fn a_restart_compacts_expired_space_and_keeps_acknowledged_rows_after_a_crash() {
    compaction_journey(false, false);
}

#[cfg(feature = "test-knobs")]
#[test]
#[ignore = "real daemon and grown/expired store with compaction failure"]
fn a_failed_startup_compaction_still_opens_the_node_and_its_rooms() {
    compaction_journey(true, false);
}

#[cfg(feature = "test-knobs")]
#[test]
#[ignore = "real daemon and store holding more than 256 MiB"]
fn a_store_holding_more_than_the_startup_cap_is_left_alone() {
    compaction_journey(false, true);
}

#[cfg(feature = "test-knobs")]
fn compaction_journey(failure: bool, over_cap: bool) {
    use redb::ReadableDatabase;
    use vox_core::node::ipc::{Frame, IpcClient, NodeSocket, Request};
    use vox_core::node::paths::{NodeName, Paths};
    const DAY: i64 = 86_400_000;
    let measure = std::env::var_os("VOX_MUTANT_RG13_MEASURE").is_some();
    let tmp = tempfile::tempdir().expect("APPARATUS: scratch account");
    let root = tmp.path();
    std::fs::create_dir(root.join("cfg")).unwrap();
    let keychain = attach::keychain(root);
    let launch = |tag: &str, step: i64, marker: Option<&Path>| {
        let mut cmd = Command::new(VOX);
        cmd.args(["daemon", "--listen", "127.0.0.1:0"])
            .env("VOX_DATA_DIR", root)
            .env("VOX_CONFIG_DIR", root.join("cfg"))
            .env("VOX_TEST_KEYCHAIN", &keychain)
            .env("VOX_TEST_CLOCK_STEP_MS", step.to_string())
            .env("VOX_PROXY", "127.0.0.1:0")
            .env_remove("VOX_ROOM")
            .env_remove("VOX_NODE")
            .env_remove("VOX_IDENTITY_PASSPHRASE")
            .env_remove("VOX_TEST_COMPACT_RELOCATED")
            .env_remove("VOX_TEST_COMPACT_FAIL")
            .env_remove("VOX_TEST_COMPACT_FAILURE_LOCKS")
            .env_remove("VOX_TEST_SKIP_STARTUP_COMPACTION")
            .env_remove("VOX_TEST_COMPACT_IGNORE_CAP")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(std::fs::File::create(root.join(format!("daemon-{tag}.err"))).unwrap());
        if let Some(marker) = marker {
            cmd.env("VOX_TEST_COMPACT_RELOCATED", marker);
        }
        if std::env::var_os("VOX_MUTANT_SKIP_STARTUP_COMPACTION").is_some() {
            cmd.env("VOX_TEST_SKIP_STARTUP_COMPACTION", "1");
        }
        if std::env::var_os("VOX_MUTANT_REMOVE_COMPACTION_CAP").is_some() {
            cmd.env("VOX_TEST_COMPACT_IGNORE_CAP", "1");
        }
        if tag == "failed" {
            cmd.env("VOX_TEST_COMPACT_FAIL", "1");
            if std::env::var_os("VOX_MUTANT_COMPACTION_FAILURE_LOCKS").is_some() {
                cmd.env("VOX_TEST_COMPACT_FAILURE_LOCKS", "1");
            }
        }
        let mut child = cmd.spawn().expect("APPARATUS: spawn scratch daemon");
        writeln!(child.stdin.take().unwrap(), "{IDENTITY}").unwrap();
        Daemon(child)
    };
    let stop = |mut daemon: Daemon| {
        Command::new("kill")
            .args(["-TERM", &daemon.0.id().to_string()])
            .status()
            .expect("APPARATUS: signal own daemon");
        daemon.0.wait().expect("APPARATUS: reap own daemon");
    };
    let paths = Paths::resolve("default", Some(root), Some(&root.join("cfg"))).unwrap();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let request = |request: Request| {
        let started = Instant::now();
        loop {
            let mut client = rt
                .block_on(IpcClient::open_at(&NodeSocket::one_shot(
                    paths.account().socket(),
                    NodeName::parse("default").unwrap(),
                )))
                .expect("APPARATUS: connect to scratch daemon");
            let frame = rt
                .block_on(client.request(&request))
                .expect("APPARATUS: request");
            if !matches!(&frame, Frame::Error { reason } if reason.contains("permissions are still being read")
                || reason.contains("room governance is refreshing")
                || reason.contains("preparing its saved history")
                || reason.contains("refreshing saved history"))
            {
                break frame;
            }
            assert!(
                started.elapsed() < Duration::from_secs(180),
                "PRODUCT (staging): room did not become writable: {frame:?}"
            );
            std::thread::sleep(Duration::from_millis(100));
        }
    };
    let (ok, out, err) = vox(root, &["id"], None);
    assert!(ok, "PRODUCT (staging): identity: {out}{err}");
    let initial = launch("grown", 0, None);
    attached(root, "grown");
    let (ok, out, err) = vox(
        root,
        &[
            "room",
            "create",
            "--passphrase-file",
            "-",
            "--name",
            "compact",
        ],
        Some(&format!("{ROOMPASS}\n")),
    );
    assert!(ok, "PRODUCT (staging): create room: {out}{err}");
    let Frame::Rooms { rooms } = request(Request::Rooms { after: None }) else {
        panic!("APPARATUS: room listing frame");
    };
    let cid = rooms
        .iter()
        .find(|(_, name, ..)| name == "compact")
        .unwrap()
        .0;
    let room = vox_core::node::link::b32_encode(&cid);
    let read_room = || loop {
        let (ok, shown, err) = vox(root, &["room", "read", &room, "--json"], None);
        if ok {
            break shown;
        }
        assert!(
            err.contains("preparing its saved history") || err.contains("refreshing saved history"),
            "PRODUCT (staging): saved room did not become readable: {shown}{err}"
        );
        std::thread::sleep(Duration::from_millis(100));
    };
    if !failure && !measure && !over_cap {
        stop(initial);
        let small_file = paths.store_file();
        let before = std::fs::metadata(&small_file).unwrap().len();
        assert!(
            before < 64 * 1024 * 1024,
            "APPARATUS: small-store fixture reached 64 MiB: {before}"
        );
        let small = launch("small", 0, None);
        attached(root, "small");
        let after = std::fs::metadata(&small_file).unwrap().len();
        let log = std::fs::read_to_string(root.join("daemon-small.err")).unwrap();
        assert_eq!(
            before, after,
            "PRODUCT: startup resized a small store: {log}"
        );
        assert!(
            !log.contains("reclaiming unused store space"),
            "PRODUCT: small store startup announced compaction: {log}"
        );
        eprintln!("PRODUCT: small store unchanged at {before} bytes; no compaction wait line");
        stop(small);
    } else {
        stop(initial);
    }
    let initial = launch("grow", 0, None);
    attached(root, "grow");
    let _ = read_room();
    if !measure && !over_cap {
        let (ok, out, err) = vox(root, &["room", "retention", &room, "1d"], None);
        assert!(ok, "PRODUCT (staging): retention: {out}{err}");
    }
    let mut id = 0;
    loop {
        let posts = if over_cap {
            12_000
        } else if measure {
            4400
        } else {
            1024
        };
        if id >= posts {
            break;
        }
        let frame = request(Request::Post {
            channel_id: cid,
            text: format!("expire-{id:04}-{}", "x".repeat(60_000)),
            card: false,
        });
        assert!(
            matches!(frame, Frame::Ok),
            "PRODUCT (staging): grow post {id}: {frame:?}"
        );
        id += 1;
    }
    eprintln!(
        "APPARATUS: grew store through {id} acknowledged 60000-byte posts; file {} bytes",
        std::fs::metadata(paths.store_file()).unwrap().len()
    );
    let expired = if measure || over_cap {
        // Expire in the running daemon so startup cannot first shrink a just-grown file.
        let (ok, out, err) = vox(root, &["room", "retention", &room, "1s"], None);
        assert!(ok, "PRODUCT (staging): large-store expiry: {out}{err}");
        initial
    } else {
        stop(initial);
        let expired = launch("expiry", 2 * DAY, None);
        attached(root, "expiry");
        expired
    };
    loop {
        let shown = read_room();
        if !shown.contains("expire-") {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    if measure || over_cap {
        let (ok, out, err) = vox(root, &["room", "retention", &room, "forever"], None);
        assert!(ok, "PRODUCT (staging): retain measurement rows: {out}{err}");
    }
    for id in 0..8 {
        let frame = request(Request::Post {
            channel_id: cid,
            text: format!("retained-message-{id}"),
            card: false,
        });
        assert!(
            matches!(frame, Frame::Ok),
            "PRODUCT (staging): retained post {id}: {frame:?}"
        );
    }
    let opening = serde_json::json!({"v":1,"type":"session","from":"compact-session",
        "body":"","at":{"session_name":"Compaction retained Session"},
        "data":{"session":{"harness":"compaction proof"}}})
    .to_string();
    let frame = request(Request::Post {
        channel_id: cid,
        text: opening,
        card: false,
    });
    assert!(
        matches!(frame, Frame::Ok),
        "PRODUCT (staging): open retained Session: {frame:?}"
    );
    let frame = request(Request::AppendSession {
        channel_id: cid,
        session_id: "compact-session".into(),
        body: serde_json::json!({"v":1,"session":"compact-session","kind":"reply","seq":1,
            "text":"retained-private-step"})
        .to_string(),
    });
    assert!(
        matches!(frame, Frame::Appended { .. }),
        "PRODUCT (staging): retained private step: {frame:?}"
    );
    let retained = || {
        let shown = read_room();
        for id in 0..8 {
            assert!(
                shown.contains(&format!("retained-message-{id}")),
                "PRODUCT: acknowledged retained message {id} missing: {shown}"
            );
        }
        assert!(
            !shown.contains("expire-"),
            "PRODUCT: expired body returned: {shown}"
        );
        let started = Instant::now();
        loop {
            let _ = vox(root, &["room", "sessions", &room, "--json"], None);
            let (ok, shown, err) = vox(
                root,
                &["room", "session", &room, "compact-session", "--json"],
                None,
            );
            if ok && shown.contains("retained-private-step") {
                break;
            }
            assert!(
                started.elapsed() < Duration::from_secs(180),
                "PRODUCT: acknowledged private Session step missing: {shown}{err}"
            );
            std::thread::sleep(Duration::from_millis(100));
        }
    };
    retained();
    stop(expired);
    let file = paths.store_file();
    let before = std::fs::metadata(&file).unwrap().len();
    let db = redb::Database::open(&file).expect("APPARATUS: inspect stopped store");
    let txn = db.begin_read().unwrap();
    let used = txn.allocated_bytes().unwrap();
    drop(txn);
    drop(db);
    assert!(
        before > used.checked_mul(2).unwrap(),
        "APPARATUS: expiry did not reach compaction threshold: file {before}, reachable {used}"
    );
    assert!(
        before - used >= 64 * 1024 * 1024,
        "APPARATUS: expiry did not free 64 MiB: file {before}, used {used}"
    );
    if over_cap {
        assert!(
            used > 256 * 1024 * 1024,
            "APPARATUS: over-cap store did not hold more than 256 MiB: {used}"
        );
        let restarted = launch("over-cap", 0, None);
        attached(root, "over-cap");
        retained();
        let after = std::fs::metadata(&file).unwrap().len();
        let log = std::fs::read_to_string(root.join("daemon-over-cap.err")).unwrap();
        if std::env::var_os("VOX_MUTANT_REMOVE_COMPACTION_CAP").is_some() {
            assert!(
                log.contains("mutant remove_compaction_cap engaged"),
                "APPARATUS: cap mutant not seen: {log}"
            );
            eprintln!("{log}");
        }
        assert_eq!(
            before, after,
            "PRODUCT: startup compacted an over-cap store: used {used}; {log}"
        );
        assert!(
            !log.contains("reclaiming unused store space"),
            "PRODUCT: over-cap store startup announced compaction: {log}"
        );
        eprintln!(
            "PRODUCT: over-cap store unchanged at {before} bytes, holding {used}; no wait line"
        );
        stop(restarted);
        return;
    }
    if measure {
        assert!(
            (230 * 1024 * 1024..=256 * 1024 * 1024).contains(&used),
            "APPARATUS: cap measurement must hold about 250 MiB: {used}"
        );
    }
    if failure {
        let failed = launch("failed", 2 * DAY, None);
        // Unlock's own reply reports the terminal startup outcome, not elapsed silence.
        let (ok, out, err) = vox(root, &["node", "unlock", "default"], None);
        let log = std::fs::read_to_string(root.join("daemon-failed.err")).unwrap();
        if std::env::var_os("VOX_MUTANT_COMPACTION_FAILURE_LOCKS").is_some() {
            assert!(
                log.contains("mutant compaction_failure_locks engaged"),
                "APPARATUS: mutant not seen in daemon: {log}"
            );
            eprintln!("{log}");
        }
        assert!(
            ok && out.contains("Ready"),
            "PRODUCT: failed compaction kept node from Ready: {out}{err}; daemon: {log}"
        );
        retained();
        assert!(
            log.contains("node default: store compaction skipped:")
                && log.contains("compaction fault staged by proof")
                && log.contains("continuing startup"),
            "PRODUCT: compaction failure did not name node and true reason: {log}"
        );
        eprintln!("PRODUCT: compaction failed, node Ready, room and retained private step readable; {log}");
        stop(failed);
        return;
    }
    let saved = root.join("acknowledged.redb");
    std::fs::copy(&file, &saved).unwrap();
    if measure {
        use vox_core::node::daemonipc::{DaemonClient, DaemonFrame, DaemonRequest, KeepSource};
        let shipped = std::env::var_os("RG13_SHIPPED_VOX")
            .map(PathBuf::from)
            .expect("APPARATUS: RG13_SHIPPED_VOX names the no-features binary");
        let passphrase_file = root.join("measurement.passphrase");
        std::fs::write(&passphrase_file, format!("{IDENTITY}\n")).unwrap();
        let measured_cli = |args: &[&str]| {
            Command::new(&shipped)
                .args(args)
                .env("VOX_DATA_DIR", root)
                .env("VOX_CONFIG_DIR", root.join("cfg"))
                .env_remove("VOX_IDENTITY_PASSPHRASE")
                .env_remove("VOX_NODE")
                .env_remove("VOX_ROOM")
                .stdin(Stdio::null())
                .output()
                .expect("APPARATUS: measurement command")
        };
        // The CLI chooses the login Keychain on macOS even with a passphrase file.
        // Send its real unlock request with the supported File source, touching no Keychain.
        let measured_unlock = || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async {
                let mut daemon = DaemonClient::open(&paths.account().socket())
                    .await
                    .expect("APPARATUS: measurement unlock socket");
                let started = Instant::now();
                let frame = daemon
                    .request(DaemonRequest::Attach {
                        node: NodeName::parse("default").unwrap(),
                        passphrase: Some(IDENTITY.to_owned().into()),
                        keep: Some(KeepSource::File(passphrase_file.clone())),
                        rooms: Vec::new(),
                        anchors: Vec::new(),
                    })
                    .await
                    .expect("APPARATUS: measurement unlock request");
                (started.elapsed(), frame)
            })
        };
        let measured_daemon = |tag: &str| {
            let child = Command::new(&shipped)
                .args(["daemon", "--no-node", "--listen", "127.0.0.1:0"])
                .env("VOX_DATA_DIR", root)
                .env("VOX_CONFIG_DIR", root.join("cfg"))
                .env("VOX_PROXY", "127.0.0.1:0")
                .env_remove("VOX_IDENTITY_PASSPHRASE")
                .env_remove("VOX_NODE")
                .env_remove("VOX_ROOM")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(std::fs::File::create(root.join(format!("daemon-{tag}.err"))).unwrap())
                .spawn()
                .expect("APPARATUS: no-features measurement daemon");
            Daemon(child)
        };
        // Foreground fixture starts were not kept. This daemon serves the locked node,
        // so the CLI's explicit unlock defines the start of the measured interval.
        let measuring = measured_daemon("measure");
        loop {
            if rt
                .block_on(DaemonClient::open(&paths.account().socket()))
                .is_ok()
            {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        std::thread::scope(|scope| {
            let started = Instant::now();
            let unlock = scope.spawn(measured_unlock);
            loop {
                let log = std::fs::read_to_string(root.join("daemon-measure.err")).unwrap();
                if log.contains("reclaiming unused store space in place") {
                    break;
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            let status = measured_cli(&["status"]);
            eprintln!(
                "MEASUREMENT vox status exit={:?}:\n{}{}",
                status.status.code(),
                String::from_utf8_lossy(&status.stdout),
                String::from_utf8_lossy(&status.stderr)
            );
            let rooms = measured_cli(&["room", "list"]);
            eprintln!(
                "MEASUREMENT vox room list exit={:?} elapsed={:.6}s:\n{}{}",
                rooms.status.code(),
                started.elapsed().as_secs_f64(),
                String::from_utf8_lossy(&rooms.stdout),
                String::from_utf8_lossy(&rooms.stderr)
            );
            let (elapsed, ready) = unlock.join().expect("APPARATUS: unlock command thread");
            assert!(
                matches!(ready, DaemonFrame::Attached(..)),
                "PRODUCT: measurement unlock failed: {ready:?}"
            );
            eprintln!(
                "MEASUREMENT explicit-unlock-to-Ready={:.6}s file={before} used={used}",
                elapsed.as_secs_f64()
            );
        });
        retained();
        rt.block_on(async {
            let mut daemon = DaemonClient::open(&paths.account().socket()).await.unwrap();
            daemon
                .request(DaemonRequest::Detach {
                    node: NodeName::parse("default").unwrap(),
                })
                .await
                .expect("APPARATUS: detach for no-compaction comparison");
        });
        let (elapsed, ready) = measured_unlock();
        eprintln!(
            "MEASUREMENT no-compaction-explicit-unlock-to-Ready={:.6}s reply={ready:?}",
            elapsed.as_secs_f64()
        );
        assert!(
            matches!(ready, DaemonFrame::Attached(..)),
            "PRODUCT: no-compaction unlock failed: {ready:?}"
        );
        stop(measuring);
        return;
    }
    let restarted = launch("compacted", 2 * DAY, None);
    attached(root, "compacted");
    retained();
    let log = std::fs::read_to_string(root.join("daemon-compacted.err")).unwrap();
    if std::env::var_os("VOX_MUTANT_SKIP_STARTUP_COMPACTION").is_some() {
        assert!(
            log.contains("mutant skip_startup_compaction engaged"),
            "APPARATUS: skip mutant not seen in daemon: {log}"
        );
        eprintln!("{log}");
    }
    let after = std::fs::metadata(&file).unwrap().len();
    assert!(after < before,
        "PRODUCT: daemon restart left expired space allocated: before {before}, after {after}, reachable {used}");
    let note = std::fs::read_to_string(root.join("daemon-compacted.err")).unwrap();
    assert!(
        note.contains("reclaiming unused store space in place")
            && note.contains("Ready when compaction finishes"),
        "PRODUCT: the startup wait did not explain compaction: {note}"
    );
    stop(restarted);
    std::fs::remove_file(&file).unwrap();
    std::fs::copy(saved, &file).unwrap();
    let marker = root.join("relocated");
    let mut crashing = launch("relocating", 2 * DAY, Some(&marker));
    let started = Instant::now();
    while !marker.exists() {
        assert!(
            crashing.0.try_wait().unwrap().is_none(),
            "PRODUCT: daemon exited before compaction relocation: {}",
            std::fs::read_to_string(root.join("daemon-relocating.err")).unwrap()
        );
        assert!(
            started.elapsed() < Duration::from_secs(180),
            "PRODUCT: bloated store was not compacted on restart: {}",
            std::fs::read_to_string(root.join("daemon-relocating.err")).unwrap()
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    crashing
        .0
        .kill()
        .expect("APPARATUS: kill own relocating daemon");
    crashing.0.wait().unwrap();
    drop(crashing);
    let recovered = launch("recovered", 2 * DAY, None);
    attached(root, "recovered");
    retained();
    assert!(
        std::fs::metadata(&file).unwrap().len() < before,
        "PRODUCT: restart after killed relocation did not reclaim the store"
    );
    stop(recovered);
}

