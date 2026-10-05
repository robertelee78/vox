//! ADR-023 M23.6 / PRD-001 R1, R6 — checkpoints, driven through the **shipped `vox` binary**.
//!
//! A room that keeps messages for a while still kept every signed skeleton forever, and the
//! composite signature is 3,373 bytes of each. Now each author, once enough of its own entries
//! have expired, posts a checkpoint on its own feed naming the position below which they are
//! past retention; a node holding it drops those entries' signatures and keeps their hashes and
//! links, so the chain still verifies up to the signed checkpoint.
//!
//! One room, one author, 100 messages, then a disappearing retention:
//! - **The bytes go.** Alice's store is measured stopped, before the retention and after the
//!   expiry: every page at or below the checkpoint becomes smaller than a signature alone, and
//!   the room's log shrinks by at least 3,373 bytes for each (sizes printed).
//! - **A restart still opens the room**, from the shed store.
//! - **A cold joiner syncs it**: signed from the checkpoint onward, and hash-chained skeletons
//!   below it (its own store is measured the same way). The order it prints with
//!   `vox room read --hashes` is identical to alice's.
//! - **V030-10: a newcomer after an expiry reads the author on.** The expired skeletons are taken,
//!   bob reckons them expired himself (none shows as "not received yet", none is shown), and
//!   alice's next message reaches him.
//!
//! **Measured, not driven, in this process:** the page sizes. No `vox` command reports them, and
//! the store file does not shrink when a page does (redb reuses its pages), so the claim that the
//! bytes go is read from the stopped node's store. Nothing here acts as a participant.
//!
//! **Moved:** a forged entry below the checkpoint, refused as pre-checkpoint and never raised as a
//! fork, was offered here to a stopped node's room in this process. It is proved through the
//! shipped daemon by `retention_requirements_proof`'s R10 (#227): a conflicting entry signed with
//! the author's own key is offered over a real sync session to a running member, whose
//! `vox status --json` must count it refused below the checkpoint and freeze nobody.
//!
//! Mutations (each run, each red): shedding disabled; v0.2.10's Withheld rule (a payload-less
//! entry set aside) — "bob never caught up"; expiry never reckoned by the receiver — bob shows
//! the expired ones as not received yet.

#![cfg(unix)]

#[path = "support/test_knobs.rs"]
mod test_knobs;
#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/attach.rs"]
mod attach;

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use vox_core::atrest::store::SegmentKind;
use vox_core::hash::COMPOSITE_SIG_LEN;

const VOX: &str = env!("CARGO_BIN_EXE_vox");
/// What `vox room read` prints for a message whose body is still owed (V030-10).
const NOT_RECEIVED_YET: &str = vox_core::node::api::NOT_RECEIVED_YET;
const IDENTITY: &str = "an identity passphrase";
const ROOMPASS: &str = "the room passphrase";
/// Messages alice writes before the room starts disappearing.
const POSTS: usize = 100;
/// The room's retention, seconds.
const RETENTION: u64 = 20;

/// A `vox daemon`, killed by its own PID when dropped.
struct Daemon(Child);

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

impl Daemon {
    /// Kill it by its PID and report whether it is gone (reaped): the check that nothing
    /// was left running.
    fn stop(mut self) -> bool {
        let _ = self.0.kill();
        let _ = self.0.wait();
        matches!(self.0.try_wait(), Ok(Some(_)))
    }
}

/// Stop every daemon and assert none is left running.
fn stop_all(daemons: Vec<Daemon>) {
    let n = daemons.len();
    let gone = daemons.into_iter().map(Daemon::stop).filter(|g| *g).count();
    println!(
        "{gone} of {n} daemons stopped by PID; {} left running",
        n - gone
    );
    assert_eq!(gone, n, "a daemon outlived its test");
}

/// A verb as a person runs it since ADR-026 L-2: one that needs its node attached, run while no
/// daemon holds the data root, runs with the node attached by `vox node attach` and let go after.
fn vox(dir: &std::path::Path, args: &[&str], stdin: Option<&str>) -> (bool, String, String) {
    let verb: Vec<&str> = args.to_vec();
    match attach::needs(dir, &verb) {
        Some(node) => {
            attach::Root::at(dir, IDENTITY).attached(&node, || vox_plain(dir, args, stdin))
        }
        None => vox_plain(dir, args, stdin),
    }
}

fn vox_plain(dir: &Path, args: &[&str], stdin: Option<&str>) -> (bool, String, String) {
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

/// The **test-only** override of how long a room must be quiet before a backlog under a
/// checkpoint batch is closed anyway (production: ten minutes).
const IDLE_ENV: &str = "VOX_TEST_CHECKPOINT_IDLE_SECS";

/// Start `vox daemon` on `dir` at `listen`, optionally with a short checkpoint idle time.
fn daemon(
    dir: &Path,
    tag: &str,
    listen: &str,
    stdin_lines: &str,
    idle_secs: Option<u64>,
) -> Daemon {
    let out = std::fs::File::create(dir.join(format!("daemon-{tag}.out"))).unwrap();
    let err = std::fs::File::create(dir.join(format!("daemon-{tag}.err"))).unwrap();
    let mut cmd = Command::new(VOX);
    cmd.args(["daemon", "--listen", listen])
        .env("VOX_DATA_DIR", dir)
        .env("VOX_CONFIG_DIR", dir.join("cfg"))
        .env_remove("VOX_ROOM")
        .env_remove(vox_core::time::TEST_CLOCK_SKEW_ENV)
        .env_remove(IDLE_ENV)
        .stdin(Stdio::piped())
        .stdout(Stdio::from(out))
        .stderr(Stdio::from(err));
    if let Some(idle) = idle_secs {
        test_knobs::require(&[IDLE_ENV]);
        cmd.env(IDLE_ENV, idle.to_string());
    }
    let mut child = cmd.spawn().expect("spawn vox daemon");
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

/// `vox room read`: `(entry hash, text)` per row, in the order printed.
fn read(dir: &Path, room: &str) -> Vec<(String, String)> {
    let (ok, out, err) = vox(dir, &["room", "read", room], None);
    assert!(ok, "vox room read: {err}");
    // `<entry-hash> <author-prefix> <text>`
    out.lines()
        .filter_map(|l| {
            let mut parts = l.splitn(3, ' ');
            let hash = parts.next()?.to_owned();
            let text = parts.nth(1)?.to_owned();
            Some((hash, text))
        })
        .collect()
}

/// `vox room read --hashes`: every entry the node holds, in the room's order.
fn order(dir: &Path, room: &str) -> Vec<String> {
    order_clocks(dir, room)
        .into_iter()
        .map(|(h, _)| h)
        .collect()
}

/// `vox room read --hashes` with the clock that placed each entry: `(hash, clock ms)`.
fn order_clocks(dir: &Path, room: &str) -> Vec<(String, u64)> {
    let (ok, out, err) = vox(dir, &["room", "read", room, "--hashes"], None);
    assert!(ok, "vox room read --hashes: {err}");
    out.lines()
        .map(|l| {
            let (h, c) = l.split_once(' ').expect("`<hash> <clock>`");
            (h.to_owned(), c.parse().expect("a clock"))
        })
        .collect()
}

fn texts(rows: &[(String, String)]) -> Vec<&str> {
    rows.iter().map(|(_, t)| t.as_str()).collect()
}

fn post(dir: &Path, room: &str, text: &str) {
    let (ok, _, err) = vox(dir, &["room", "post", room, text], None);
    assert!(ok, "vox room post {text:?}: {err}");
}

/// Fresh profiles that all trust each other.
fn members(tmp: &Path, names: &[&str]) -> Vec<PathBuf> {
    let dirs: Vec<PathBuf> = names.iter().map(|n| tmp.join(n)).collect();
    let mut fps = Vec::new();
    for d in &dirs {
        std::fs::create_dir_all(d.join("cfg")).unwrap();
        let (ok, out, err) = vox(d, &["id"], None);
        assert!(ok, "vox id: {err}");
        fps.push(out.trim().to_owned());
    }
    for (i, d) in dirs.iter().enumerate() {
        for (j, fp) in fps.iter().enumerate() {
            if i != j {
                let name = format!("peer{j}");
                let (ok, _, err) = vox(d, &["trust", "add", fp, "--name", &name], None);
                assert!(ok, "vox trust add: {err}");
            }
        }
    }
    dirs
}

/// The sizes of every log page in a **stopped** node's store, in page order.
fn log_pages(dir: &Path) -> Vec<usize> {
    let paths = vox_core::node::paths::Paths::resolve("default", Some(dir), Some(&dir.join("cfg")))
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    let profile = loop {
        match vox_core::node::profile::Profile::open(paths.clone()) {
            Ok(p) => break p,
            Err(_) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(200)),
            Err(e) => panic!("CANNOT MEASURE: the stopped node's store did not open: {e:?}"),
        }
    };
    let store = profile.store();
    let cid = store.channels().unwrap()[0];
    store
        .segments(&cid, SegmentKind::LogDb)
        .unwrap()
        .into_iter()
        .map(|(_, page)| page.ciphertext.len())
        .collect()
}

/// `(pages, total bytes, pages smaller than a signature alone)`.
fn page_stats(pages: &[usize]) -> (usize, usize, usize) {
    (
        pages.len(),
        pages.iter().sum(),
        pages.iter().filter(|p| **p < COMPOSITE_SIG_LEN).count(),
    )
}

#[test]
#[ignore = "two real vox daemons and real seconds (about two minutes); CI runs it in release"]
fn a_disappearing_room_sheds_expired_signatures_reopens_and_a_newcomer_syncs_it() {
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();
    let dirs = members(tmp.path(), &["alice", "bob"]);
    let (alice, bob) = (&dirs[0], &dirs[1]);

    // ---- alice alone: a room and 100 messages --------------------------------------------
    let alice_d = daemon(
        alice,
        "alice",
        "127.0.0.1:0",
        &format!("{IDENTITY}\n"),
        None,
    );
    attached(alice, "alice");
    let (ok, _, err) = vox(
        alice,
        &["room", "create", "--passphrase-file", "-", "--name", "r"],
        Some(&format!("{ROOMPASS}\n")),
    );
    assert!(ok, "vox room create: {err}");
    let room = attached(alice, "alice")
        .split_whitespace()
        .next()
        .expect("a room id")
        .to_owned();
    for i in 1..=POSTS {
        post(alice, &room, &format!("old {i}"));
    }
    assert_eq!(
        texts(&read(alice, &room)).len(),
        POSTS,
        "alice shows her 100"
    );
    stop_all(vec![alice_d]);
    let before = log_pages(alice);
    let (b_pages, b_bytes, b_small) = page_stats(&before);
    println!(
        "before: {b_pages} log pages, {b_bytes} bytes, {b_small} smaller than a signature \
         ({COMPOSITE_SIG_LEN} bytes)"
    );

    // ---- the room disappears after 20 s --------------------------------------------------
    // Set once all 100 are already older than it, so one sweep expires them together and one
    // checkpoint covers them all. Expiring piecemeal would leave the last few (fewer than the 32
    // a checkpoint waits for) signed until more expire, which is the design, not the claim.
    std::thread::sleep(Duration::from_secs(RETENTION + 2));
    let alice_d = daemon(
        alice,
        "alice-2",
        "127.0.0.1:0",
        &format!("{IDENTITY}\n{ROOMPASS}\n"),
        None,
    );
    attached(alice, "alice");
    let (ok, out, err) = vox(
        alice,
        &["room", "retention", &room, &RETENTION.to_string()],
        None,
    );
    assert!(ok, "vox room retention: {err}");
    println!("{}", out.trim());
    let deadline = Instant::now() + Duration::from_secs(120);
    while texts(&read(alice, &room))
        .iter()
        .any(|t| t.starts_with("old "))
    {
        assert!(Instant::now() < deadline, "the 100 never expired");
        std::thread::sleep(Duration::from_millis(500));
    }
    // The checkpoint and the shedding run on the sweep that pruned them; a few ticks more.
    std::thread::sleep(Duration::from_secs(3));
    stop_all(vec![alice_d]);
    let after = log_pages(alice);
    let (a_pages, a_bytes, a_small) = page_stats(&after);
    let shed = a_small.saturating_sub(b_small);
    println!(
        "after: {a_pages} log pages, {a_bytes} bytes, {a_small} smaller than a signature; the \
         log shrank by {} bytes for {shed} shed signatures ({shed} × {COMPOSITE_SIG_LEN} = {})",
        b_bytes.saturating_sub(a_bytes),
        shed * COMPOSITE_SIG_LEN
    );
    assert!(
        shed >= POSTS,
        "only {shed} of alice's {POSTS} expired entries shed their signature"
    );
    assert!(
        b_bytes.saturating_sub(a_bytes) >= shed * COMPOSITE_SIG_LEN,
        "the log shrank by less than the signatures shed"
    );

    // ---- a restart opens the room; a cold joiner syncs it --------------------------------
    let alice_d = daemon(
        alice,
        "alice-3",
        "127.0.0.1:0",
        &format!("{IDENTITY}\n{ROOMPASS}\n"),
        None,
    );
    let listed = attached(alice, "alice");
    println!("after the restart: `room list` says {listed:?}");
    assert!(
        !listed.contains("[closed]"),
        "a room with shed signatures must reopen: {listed:?}"
    );
    let bob_d = daemon(bob, "bob", "127.0.0.1:0", &format!("{IDENTITY}\n"), None);
    attached(bob, "bob");
    let (ok, link, err) = vox(alice, &["room", "link", &room], None);
    assert!(ok, "vox room link: {err}");
    let (ok, _, err) = vox(
        bob,
        &[
            "room",
            "join",
            "--passphrase-file",
            "-",
            link.trim(),
            "--name",
            "r",
        ],
        Some(&format!("{ROOMPASS}\n")),
    );
    assert!(ok, "vox room join: {err}");
    let alice_order = order(alice, &room);
    let deadline = Instant::now() + Duration::from_secs(120);
    let bob_order = loop {
        let o = order(bob, &room);
        let a = order(alice, &room);
        // Bob's joining adds entries on both sides; converged when both hold the same set.
        let mut sa = a.clone();
        let mut sb = o.clone();
        sa.sort();
        sb.sort();
        if sa == sb && o.len() >= alice_order.len() {
            break (a, o);
        }
        assert!(
            Instant::now() < deadline,
            "PRODUCT: bob never caught up: `vox room read --hashes` shows him {} of alice's {} \
             entries; a newcomer's sync stopped at alice's expired ones",
            o.len(),
            a.len()
        );
        std::thread::sleep(Duration::from_millis(500));
    };
    let (a, b) = bob_order;
    println!(
        "alice {} entries, bob {} — orders identical: {}",
        a.len(),
        b.len(),
        a == b
    );
    assert_eq!(a, b, "the newcomer's order differs from alice's");

    // ---- V030-10: the expired skeletons are expired to bob, and alice's feed goes on ----------
    // Bob reckons their expiry himself, from each skeleton's signed time and the room's retention:
    // none is owed, so none shows as "not received yet", and none is shown at all (R10).
    let shown = read(bob, &room);
    let owed = texts(&shown)
        .iter()
        .filter(|t| **t == NOT_RECEIVED_YET)
        .count();
    let old = texts(&shown)
        .iter()
        .filter(|t| t.starts_with("old "))
        .count();
    println!(
        "bob shows {} rows: {owed} not received yet, {old} expired ones",
        shown.len()
    );
    assert_eq!(
        owed, 0,
        "PRODUCT: bob shows {owed} of alice's expired messages as not received yet; their expiry \
         is his to reckon from the room's retention, and they are expired"
    );
    assert_eq!(
        old, 0,
        "PRODUCT: bob shows {old} of alice's expired messages"
    );
    let next = "alice, after bob joined";
    post(alice, &room, next);
    let deadline = Instant::now() + Duration::from_secs(60);
    while !texts(&read(bob, &room)).contains(&next) {
        assert!(
            Instant::now() < deadline,
            "PRODUCT: alice's next message never reached bob: her feed stopped at the expired \
             ones\nbob shows: {:?}",
            read(bob, &room)
        );
        std::thread::sleep(Duration::from_millis(500));
    }
    println!("bob reads alice's next message: {next:?}");
    stop_all(vec![alice_d, bob_d]);
    let joined = log_pages(bob);
    let (j_pages, j_bytes, j_small) = page_stats(&joined);
    println!(
        "bob's store: {j_pages} log pages, {j_bytes} bytes, {j_small} smaller than a signature"
    );
    assert!(
        j_small >= POSTS,
        "the newcomer received {j_small} unsigned skeletons for {POSTS} checkpointed entries"
    );
}

/// A room of one: alice creates it on a fresh daemon and posts `n` messages `"old <i>"`.
/// Returns the running daemon and the room id.
fn room_with_posts(alice: &Path, n: usize, idle_secs: Option<u64>) -> (Daemon, String) {
    let alice_d = daemon(
        alice,
        "alice",
        "127.0.0.1:0",
        &format!("{IDENTITY}\n"),
        idle_secs,
    );
    attached(alice, "alice");
    let (ok, _, err) = vox(
        alice,
        &["room", "create", "--passphrase-file", "-", "--name", "r"],
        Some(&format!("{ROOMPASS}\n")),
    );
    assert!(ok, "vox room create: {err}");
    let room = attached(alice, "alice")
        .split_whitespace()
        .next()
        .expect("a room id")
        .to_owned();
    for i in 1..=n {
        post(alice, &room, &format!("old {i}"));
    }
    (alice_d, room)
}

/// Poll `vox room read` until none of the `"old "` messages is shown.
fn until_expired(alice: &Path, room: &str, secs: u64) {
    let deadline = Instant::now() + Duration::from_secs(secs);
    while texts(&read(alice, room))
        .iter()
        .any(|t| t.starts_with("old "))
    {
        assert!(Instant::now() < deadline, "the old messages never expired");
        std::thread::sleep(Duration::from_millis(500));
    }
}

/// Fewer expired entries than a checkpoint batch (32) are still checkpointed once nothing new
/// has expired for the idle time — a **closing** checkpoint — so none keeps its signature
/// indefinitely. The idle time is the test-only 15 s instead of production's ten minutes; the
/// gate first shows that nothing is shed before it passes.
#[test]
#[ignore = "one real vox daemon and real seconds (about a minute); CI runs it in release"]
fn a_backlog_under_a_batch_is_checkpointed_once_the_room_goes_quiet() {
    const FEW: usize = 10;
    const IDLE: u64 = 15;
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();
    let alice = &members(tmp.path(), &["alice"])[0];
    let (alice_d, room) = room_with_posts(alice, FEW, Some(IDLE));
    std::thread::sleep(Duration::from_secs(RETENTION + 2));
    let (ok, _, err) = vox(
        alice,
        &["room", "retention", &room, &RETENTION.to_string()],
        None,
    );
    assert!(ok, "vox room retention: {err}");
    until_expired(alice, &room, 60);
    stop_all(vec![alice_d]);
    let (_, _, before) = page_stats(&log_pages(alice));
    println!("just after the {FEW} expired: {before} pages smaller than a signature");
    assert_eq!(
        before, 0,
        "a backlog under a batch was checkpointed before the room went quiet"
    );

    let alice_d = daemon(
        alice,
        "alice-2",
        "127.0.0.1:0",
        &format!("{IDENTITY}\n{ROOMPASS}\n"),
        Some(IDLE),
    );
    attached(alice, "alice");
    std::thread::sleep(Duration::from_secs(IDLE + 5));
    stop_all(vec![alice_d]);
    let (pages, bytes, after) = page_stats(&log_pages(alice));
    println!(
        "{} s quiet: {pages} log pages, {bytes} bytes, {after} smaller than a signature",
        IDLE + 5
    );
    assert_eq!(after, FEW, "the closing checkpoint did not shed all {FEW}");
}

/// A backlog that expired while the room still kept everything (a node's own shorter limit
/// pruned it, and a room that keeps everything is never checkpointed) is checkpointed as soon as
/// the room starts disappearing, and after a restart, **without another prune**: nothing is left
/// to prune.
#[test]
#[ignore = "one real vox daemon and real seconds (about a minute); CI runs it in release"]
fn an_expired_backlog_is_checkpointed_without_waiting_for_another_prune() {
    const MANY: usize = 40;
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();
    let alice = &members(tmp.path(), &["alice"])[0];
    // The node keeps 20 s; the room keeps everything.
    std::fs::write(
        alice.join("cfg").join("retention"),
        format!("default {RETENTION}\n"),
    )
    .unwrap();
    let (alice_d, room) = room_with_posts(alice, MANY, None);
    until_expired(alice, &room, 90);
    // Nothing more can expire now; the room starts disappearing only afterwards.
    let (ok, out, err) = vox(alice, &["room", "retention", &room, "1w"], None);
    assert!(ok, "vox room retention 1w: {err}");
    println!("{}", out.trim());
    stop_all(vec![alice_d]);
    let alice_d = daemon(
        alice,
        "alice-2",
        "127.0.0.1:0",
        &format!("{IDENTITY}\n{ROOMPASS}\n"),
        None,
    );
    attached(alice, "alice");
    std::thread::sleep(Duration::from_secs(5));
    stop_all(vec![alice_d]);
    let (pages, bytes, shed) = page_stats(&log_pages(alice));
    println!(
        "after the restart: {pages} log pages, {bytes} bytes, {shed} smaller than a signature"
    );
    assert_eq!(
        shed, MANY,
        "the expired backlog was not checkpointed without another prune"
    );
}
