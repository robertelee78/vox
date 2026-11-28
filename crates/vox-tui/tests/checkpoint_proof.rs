//! ADR-023 M23.6 / PRD-001 R1, R6 — checkpoints, driven through the **shipped `vox` binary**.
//!
//! Each author, once enough of its own entries have expired, posts a checkpoint on its own feed
//! naming the position below which they are past retention. A v2 entry keeps its signature after
//! its body expires (ADR-036, `4f7f95041`: a later entry may cite any earlier header as a parent
//! receipt), so a checkpoint sheds no signature in this release; what it still owes is below.
//!
//! One room, one author, 100 messages, then a disappearing retention:
//! - **A restart still opens the room** once they expired.
//! - **A cold joiner syncs it**: the order it prints with `vox room read --hashes` is identical
//!   to alice's.
//! - **V030-10: a newcomer after an expiry reads the author on.** The expired skeletons are taken,
//!   bob reckons them expired himself (none shows as "not received yet", none is shown), and
//!   alice's next message reaches him.
//!
//! **Moved:** a forged entry below the checkpoint, refused as pre-checkpoint and never raised as a
//! fork, was offered here to a stopped node's room in this process. It is proved through the
//! shipped daemon by `retention_requirements_proof`'s R10 (#227): a conflicting entry signed with
//! the author's own key is offered over a real sync session to a running member, whose
//! `vox status --json` must count it refused below the checkpoint and freeze nobody.
//!
//! Mutations (each run, each red): v0.2.10's Withheld rule (a payload-less entry set aside) —
//! "bob never caught up"; expiry never reckoned by the receiver — bob shows the expired ones as
//! not received yet.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/attach.rs"]
mod attach;
#[path = "support/test_knobs.rs"]
mod test_knobs;
#[path = "support/typed.rs"]
mod typed;

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

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
/// The **test-only** switch of the checkpoint walk's mutant arms (`own-uncounted`, `unwritten`),
/// set on every daemon here from the run's [`CHECKPOINT_MUTANT_RUN`].
const CHECKPOINT_MUTANT: &str = "VOX_TEST_CHECKPOINT_MUTANT";
/// The run setting that selects a checkpoint mutant arm: `VOX_MUTANT_CHECKPOINT=own-uncounted`.
const CHECKPOINT_MUTANT_RUN: &str = "VOX_MUTANT_CHECKPOINT";

/// Start `vox daemon` on `dir` at `listen`; `idle` sets the test-only [`IDLE_ENV`], else it is
/// removed and the node waits the production ten minutes. A run's [`CHECKPOINT_MUTANT_RUN`] is
/// passed on as [`CHECKPOINT_MUTANT`].
fn daemon(dir: &Path, tag: &str, listen: &str, stdin_lines: &str) -> Daemon {
    daemon_idle(dir, tag, listen, stdin_lines, None)
}

fn daemon_idle(
    dir: &Path,
    tag: &str,
    listen: &str,
    stdin_lines: &str,
    idle: Option<u64>,
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
    if let Some(arm) = std::env::var_os(CHECKPOINT_MUTANT_RUN) {
        cmd.env(CHECKPOINT_MUTANT, arm);
    }
    if let Some(idle) = idle {
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

#[test]
#[ignore = "two real vox daemons and real seconds (about two minutes); CI runs it in release"]
fn a_disappearing_room_reopens_and_a_newcomer_syncs_it() {
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();
    let dirs = members(tmp.path(), &["alice", "bob"]);
    let (alice, bob) = (&dirs[0], &dirs[1]);

    // ---- alice alone: a room and 100 messages --------------------------------------------
    let alice_d = daemon(alice, "alice", "127.0.0.1:0", &format!("{IDENTITY}\n"));
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
    // A few ticks more, for the sweep that pruned them to finish.
    std::thread::sleep(Duration::from_secs(3));
    stop_all(vec![alice_d]);

    // ---- a restart opens the room; a cold joiner syncs it --------------------------------
    let alice_d = daemon(
        alice,
        "alice-3",
        "127.0.0.1:0",
        &format!("{IDENTITY}\n{ROOMPASS}\n"),
    );
    let listed = attached(alice, "alice");
    println!("after the restart: `room list` says {listed:?}");
    assert!(
        !listed.contains("[closed]"),
        "a room whose messages expired must reopen: {listed:?}"
    );
    let bob_d = daemon(bob, "bob", "127.0.0.1:0", &format!("{IDENTITY}\n"));
    attached(bob, "bob");
    let (ok, link, err) = vox(alice, &["room", "link", &room], None);
    assert!(ok, "vox room link: {err}");
    let (ok, _, err) = vox(
        bob,
        &["room", "join", "--passphrase-file", "-", link.trim()],
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
}

/// How long, in the test-only knob's seconds, a quiet room waits before closing its expired
/// backlog with a checkpoint (production: ten minutes).
const QUIET_IDLE_SECS: u64 = 3;
/// Answered `vox status --json` reads, a second apart, over which a quiet room is watched once its
/// last message has expired: several idle intervals.
const QUIET_READS: usize = 20;
/// The last reads over which the quiet room's feed must not change: three idle intervals and
/// their retention turns.
const QUIET_STILL: usize = 12;
/// What a `test-knobs` daemon says each time it writes a checkpoint, followed by the room's id
/// (`pending_retention.rs`, `PendingCheckpoint::save`).
const CHECKPOINT_SAID: &str = "test-knobs: checkpoint written in room ";

/// This node's own feed position in `room` as `vox status --json` shows it (`own_feed_through`).
fn own_feed_through(dir: &Path, room: &str) -> Option<u64> {
    let (ok, out, _) = vox(dir, &["status", "--json"], None);
    if !ok {
        return None;
    }
    serde_json::from_str::<serde_json::Value>(&out).ok()?["rooms"]
        .as_array()?
        .iter()
        .find(|row| row["id"].as_str().is_some_and(|id| id.starts_with(room)))?["own_feed_through"]
        .as_u64()
}

/// **A quiet room with the shortest retention a person can set stops writing.** Alice keeps a
/// room for one second (`vox room retention <room> 1`); Bob joins, posts once and the room goes
/// quiet. Once his message has expired, his node closes that backlog with one idle checkpoint
/// (ADR-023 decision 3), and then writes nothing more. Over [`QUIET_READS`] reads a second apart
/// after the expiry: his daemon says exactly once that it wrote a checkpoint for this room
/// ([`CHECKPOINT_SAID`]), the feed `vox status --json` shows for him is past where it stood at
/// the last read before that line, and it stays still for the last [`QUIET_STILL`] reads, several
/// idle intervals.
///
/// Nothing a person can run names an entry's kind (`vox room read --hashes` prints hash and
/// clock; `vox status --json` counts the feed), and a joiner's own writes besides his post (his
/// Session support record, a key package re-sent to a member whose prekey was used) land at no
/// fixed point, so a count from a baseline cannot tell them from a checkpoint. The checkpoint is
/// identified by the node's own words instead: a `test-knobs`-only line said where the checkpoint
/// is written, after it is appended, naming the room and the position it closes through. The
/// feed count is taken relative to that line, so whatever else lands before it does not matter.
///
/// Before the fix his node never counted its own earlier checkpoint and wrote the same one again
/// on every idle turn, without end (ledger 145 klo/i1: one a second for 37 minutes). The idle
/// interval is shortened by the test-only knob `VOX_TEST_CHECKPOINT_IDLE_SECS` (production: ten
/// minutes).
///
/// Mutant arms (run setting `VOX_MUTANT_CHECKPOINT`, passed to the daemons as
/// `VOX_TEST_CHECKPOINT_MUTANT`; test-knobs builds only), each red on its own assertion:
/// `own-uncounted` puts that fault back (the walk does not count the node's own earlier
/// checkpoint) — "kept growing"; `unwritten` skips the checkpoint write — "no closing checkpoint
/// was written".
#[test]
#[ignore = "two real vox daemons and real seconds (about a minute); run it in release"]
fn a_quiet_room_with_a_one_second_retention_stops_writing_checkpoints() {
    watchdog::arm();
    test_knobs::require(&[IDLE_ENV]);
    if std::env::var_os(CHECKPOINT_MUTANT_RUN).is_some() {
        test_knobs::require(&[CHECKPOINT_MUTANT]);
    }
    let tmp = tempfile::tempdir().unwrap();
    let dirs = members(tmp.path(), &["alice", "bob"]);
    let (alice, bob) = (&dirs[0], &dirs[1]);
    let alice_d = daemon(alice, "alice", "127.0.0.1:0", &format!("{IDENTITY}\n"));
    attached(alice, "alice");
    let (ok, _, err) = vox(
        alice,
        &[
            "room",
            "create",
            "--passphrase-file",
            "-",
            "--name",
            "quiet",
        ],
        Some(&format!("{ROOMPASS}\n")),
    );
    assert!(ok, "vox room create: {err}");
    let room = attached(alice, "alice")
        .split_whitespace()
        .next()
        .expect("a room id")
        .to_owned();
    let (ok, out, err) = vox(alice, &["room", "retention", &room, "1"], None);
    assert!(
        ok,
        "PRODUCT: `vox room retention {room} 1` was refused: {out}{err}"
    );
    let bob_d = daemon_idle(
        bob,
        "bob",
        "127.0.0.1:0",
        &format!("{IDENTITY}\n"),
        Some(QUIET_IDLE_SECS),
    );
    attached(bob, "bob");
    let (ok, link, err) = vox(alice, &["room", "link", &room], None);
    assert!(ok, "vox room link: {err}");
    let (ok, _, err) = vox(
        bob,
        &["room", "join", "--passphrase-file", "-", link.trim()],
        Some(&format!("{ROOMPASS}\n")),
    );
    assert!(ok, "vox room join: {err}");
    let said = || {
        std::fs::read_to_string(bob.join("daemon-bob.err"))
            .unwrap_or_else(|e| format!("(its stderr could not be read: {e})"))
    };
    let checkpoint_line = format!("{CHECKPOINT_SAID}{room}");
    let checkpoints_said = || {
        said()
            .lines()
            .filter(|l| l.contains(&checkpoint_line))
            .count()
    };
    post(bob, &room, "quiet 1");
    let after_post = own_feed_through(bob, &room)
        .unwrap_or_else(|| panic!("PRODUCT: `vox status --json` named no own feed for {room}"));
    let deadline = Instant::now() + Duration::from_secs(120);
    while texts(&read(bob, &room)).contains(&"quiet 1") {
        assert!(
            Instant::now() < deadline,
            "PRODUCT: a message kept for one second still shows after two minutes"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
    // Each answered read, a second apart: the feed size, the read it last changed at, and the
    // feed as it stood at the last read after which the daemon had not yet said a checkpoint.
    let mut shown = Vec::new();
    let mut changed_at = 0;
    let mut unsaid_feed = after_post;
    let mut said_at = None;
    for read_no in 1..=QUIET_READS {
        std::thread::sleep(Duration::from_secs(1));
        let now = own_feed_through(bob, &room)
            .unwrap_or_else(|| panic!("PRODUCT: `vox status --json` named no own feed for {room}"));
        if shown.last().copied().unwrap_or(after_post) != now {
            println!("bob's own feed in the quiet room: {now} (after his post: {after_post})");
            shown.push(now);
            changed_at = read_no;
        }
        let lines = checkpoints_said();
        if lines == 0 {
            unsaid_feed = now;
        } else if said_at.is_none() {
            println!(
                "bob's daemon said its checkpoint by read {read_no} (feed before: {unsaid_feed})"
            );
            said_at = Some(read_no);
        }
    }
    let end = shown.last().copied().unwrap_or(after_post);
    let still = QUIET_READS - changed_at;
    let lines = checkpoints_said();
    assert!(
        lines != 0,
        "PRODUCT: no closing checkpoint was written: bob's daemon never said it wrote one for \
         {room} over {QUIET_READS} reads a second apart after his only message expired (his own \
         feed: {after_post} after his post, then {shown:?}); a quiet room closes its expired \
         backlog with one checkpoint once idle for {QUIET_IDLE_SECS} s\nbob's daemon said: {}",
        said()
    );
    assert!(
        lines == 1 && still >= QUIET_STILL,
        "PRODUCT: a quiet room kept for one second kept growing: bob's daemon said {lines} \
         checkpoint(s) written for {room}, and his own feed went from {after_post} through \
         {shown:?} over {QUIET_READS} reads a second apart after his only message expired, the \
         last change {still} read(s) before the end; the one closing checkpoint is all that is \
         due, so it must be said once and the feed then stay still for {QUIET_STILL} reads, \
         several idle intervals\nbob's daemon said: {}",
        said()
    );
    assert!(
        end > unsaid_feed,
        "PRODUCT: bob's daemon said it wrote a checkpoint for {room} (by read {said_at:?}), but \
         his own feed is at {end}, where it stood before that line ({unsaid_feed}): the \
         checkpoint is not in his feed\nbob's daemon said: {}",
        said()
    );
    stop_all(vec![alice_d, bob_d]);
}
