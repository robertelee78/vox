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
//! Mutations (each run, each red): the sweep disabled; a reload that refuses a pruned entry; the
//! node's own retention ignored; the node's retention winning whenever it is set (so a node
//! keeping more than its room keeps more); the arrival check removed.

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

/// A free loopback UDP port, so a node can come back on the address its peers know.
fn free_port() -> String {
    let s = std::net::UdpSocket::bind("127.0.0.1:0").expect("APPARATUS: a free UDP port");
    format!(
        "127.0.0.1:{}",
        s.local_addr().expect("APPARATUS: a free UDP port").port()
    )
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
        let (ok, _, err) = vox(dir, &["trust", "add", fp, "--name", "peer"], None);
        assert!(ok, "PRODUCT (staging): vox trust add: {err}");
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
    assert!(ok, "PRODUCT (staging): vox room create: {err}");
    let room = attached(creator, "creator")
        .split_whitespace()
        .next()
        .expect("PRODUCT (staging): a room id in `vox room list`")
        .to_owned();
    let (ok, link, err) = vox(creator, &["room", "invite", &room], None);
    assert!(ok, "PRODUCT (staging): vox room invite: {err}");
    let (ok, _, err) = vox(
        joiner,
        &["room", "join", link.trim(), "--name", "r"],
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
    let (ok, out, err) = vox(&alice, &["room", "retention", &room, "30"], None);
    assert!(ok, "PRODUCT: the admin's vox room retention 30: {err}");
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
    // Fixed addresses, so both can be restarted and still find each other below.
    let (bob_at, alice_at) = (free_port(), free_port());
    let bob_d = daemon_on(&bob, "bob", &format!("{IDENTITY}\n"), &bob_at);
    attached(&bob, "bob");
    let alice_d = daemon_on(&alice, "alice", &format!("{IDENTITY}\n"), &alice_at);
    attached(&alice, "alice");
    let room = room(&bob, &alice);
    let (ok, out, err) = vox(&bob, &["room", "retention", &room, "1w"], None);
    assert!(ok, "PRODUCT (staging): vox room retention 1w: {err}");
    println!("{}", out.trim());

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
    .expect("APPARATUS: alice's profile paths")
    .socket_file();
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
                let mut client = vox_core::node::ipc::IpcClient::open(&sock)
                    .await
                    .unwrap_or_else(|e| {
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
