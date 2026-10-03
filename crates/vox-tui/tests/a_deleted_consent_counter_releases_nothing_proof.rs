//! V210-49 (#224) — **deleting the consent counter does not release a closed room's history**,
//! driven through the **shipped `vox` binary** and the real `vox tui` in a pty.
//!
//! **The claim.** What a newly trusted member may read is ordered by the profile's consent
//! counter (V210-45, #220): a generation of alice's sender key minted after her decision to trust
//! bob is released whole, the one live at it only from where it stood, nothing older. The counter
//! is one sealed row (`consent-order`) of alice's store. A corrupt row fails closed, but a
//! *missing* one used to read as an empty counter, so its next value was small: every generation
//! stamped by the old counter looked minted **after** the next decision. For a room open at the
//! decision the stamp is floored by that room's generations, but a room **closed** at it is not,
//! so deleting the row released that room's whole pre-trust history to the next member trusted.
//! The fix gives each counter a random id, stored with every stamp; stamps of two counters are
//! never ordered, so a generation stamped before the deletion is released to no one it cannot be
//! proved to follow.
//!
//! **Staging.** Bob trusts alice; alice does not trust bob. Alice trusts carol (so the counter is
//! past its first value), creates room C and posts 1–20 in it. Her daemon is stopped and her real
//! `vox tui` opens C and `:close`s it (`tests/pty/tui_close_room.py`): no command closes a room,
//! and a daemon reopens every room it held open. With every vox process of alice's stopped, the
//! test deletes the `consent-order` row from her `store.redb`. Her daemon starts again, and C is
//! confirmed `[closed]`; alice trusts bob. Her daemon restarts with C's passphrase, which opens
//! C, and alice posts 21–30. Bob joins C and reads.
//!
//! **Asserted,** with hard-coded numbers, after bob keeps reading 45 s past the moment his
//! required posts arrived (a late history release must be caught): bob reads **0** of posts 1–20
//! and exactly posts 21–30. A TUI that does not close C as a person does (exits, never unlocks,
//! never answers `:close`) is a `PRODUCT (staging)` red; the TUI driver's own apparatus is
//! `APPARATUS`. Preconditions the product must meet, or `PRODUCT (staging)`: C was closed at
//! the decision and open after; alice reads all 30 posts; bob reads post 30 (without it, 0
//! pre-trust posts would say nothing). The attack's own staging, or `PRODUCT (staging)`: the row
//! existed and was deleted, with every vox process of alice's stopped.
//!
//! **Every participant is the shipped binary.** One step is not a `vox` command, because it is the
//! attack: deleting the row. The test opens alice's `store.redb` with `redb` for that alone, only
//! while no vox process of hers runs, and does nothing else with it.
//!
//! **Mutation that must turn it red:** a missing counter read as empty *and ordered* — the old
//! behaviour — e.g. every counter created under the same id: bob then reads posts 1–20.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/pty_driver.rs"]
mod pty_driver;

use std::collections::BTreeSet;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const VOX: &str = env!("CARGO_BIN_EXE_vox");
const IDENTITY: &str = "an identity passphrase";
const ROOMPASS: &str = "the room passphrase";
/// How long bob has to read what he is entitled to.
const BOUND: Duration = Duration::from_secs(300);
/// The counter's row in the store's `meta` table: the thing the attacker deletes.
const COUNTER_ROW: &str = "consent-order";

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
        // In the environment, not argv: a command line is world-readable (ADR-015).
        .env("VOX_IDENTITY_PASSPHRASE", IDENTITY)
        .env_remove("VOX_ROOM")
        .env_remove("VOX_SESSION")
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
            .expect("APPARATUS: vox stdin")
            .write_all(text.as_bytes())
            .expect("APPARATUS: write vox stdin");
        drop(child.stdin.take());
    }
    let out = child.wait_with_output().expect("APPARATUS: wait for vox");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// Start `vox daemon` with `stdin` piped in (the identity passphrase, then any room passphrase
/// lines), its output to files by the profile.
fn daemon(dir: &Path, tag: &str, stdin: &str) -> Daemon {
    let out = std::fs::File::create(dir.join(format!("daemon-{tag}.out")))
        .expect("APPARATUS: harness file I/O");
    let err = std::fs::File::create(dir.join(format!("daemon-{tag}.err")))
        .expect("APPARATUS: harness file I/O");
    let mut child = Command::new(VOX)
        .args(["daemon", "--listen", "127.0.0.1:0"])
        .env("VOX_DATA_DIR", dir)
        .env("VOX_CONFIG_DIR", dir.join("cfg"))
        .env_remove("VOX_ROOM")
        .stdin(Stdio::piped())
        .stdout(Stdio::from(out))
        .stderr(Stdio::from(err))
        .spawn()
        .expect("APPARATUS: spawn vox daemon");
    // Write, then close: the daemon reads stdin to EOF before it binds its socket.
    let mut pipe = child.stdin.take().expect("APPARATUS: daemon stdin");
    pipe.write_all(stdin.as_bytes())
        .expect("APPARATUS: write the daemon's stdin");
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

/// `room`'s line in `vox room list`, once the list names it.
fn room_line(dir: &Path, tag: &str, room: &str) -> String {
    attached(dir, tag)
        .lines()
        .find(|l| l.contains(room))
        .unwrap_or_else(|| panic!("PRODUCT (staging): {tag}'s room list does not name {room}"))
        .to_owned()
}

/// Every `post <i>` this profile's `vox room read --json` shows for `room`.
fn read_posts(dir: &Path, room: &str) -> (BTreeSet<usize>, usize) {
    let (ok, out, err) = vox(
        dir,
        &["room", "read", room, "--json", "--limit", "500"],
        None,
    );
    assert!(ok, "PRODUCT: vox room read --json refused: {err}");
    let mut seen = BTreeSet::new();
    let mut rows = 0usize;
    for l in out.lines().filter(|l| !l.trim().is_empty()) {
        let row: serde_json::Value = serde_json::from_str(l).unwrap_or_else(|e| {
            panic!("PRODUCT: vox room read --json printed a row that is not JSON ({e}): {l}")
        });
        if let Some(n) = row["text"]
            .as_str()
            .and_then(|t| t.strip_prefix("post "))
            .and_then(|n| n.parse::<usize>().ok())
        {
            rows += 1;
            seen.insert(n);
        }
    }
    (seen, rows)
}

fn post_range(alice: &Path, room: &str, lo: usize, hi: usize) {
    for i in lo..=hi {
        let (ok, _, err) = vox(alice, &["room", "post", room, &format!("post {i}")], None);
        assert!(ok, "PRODUCT (staging): alice's post {i} was refused: {err}");
    }
}

/// `seen` as a few ranges, for a message.
fn ranges(seen: impl IntoIterator<Item = usize>) -> Vec<(usize, usize)> {
    let mut out: Vec<(usize, usize)> = Vec::new();
    for n in seen {
        match out.last_mut() {
            Some((_, hi)) if *hi + 1 == n => *hi = n,
            _ => out.push((n, n)),
        }
    }
    out
}

/// The profile's `store.redb`, under `<data>/<profile>/`.
fn store_file(dir: &Path) -> PathBuf {
    std::fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("APPARATUS: cannot list the profile dir {dir:?}: {e}"))
        .filter_map(Result::ok)
        .map(|e| e.path().join("store.redb"))
        .find(|p| p.is_file())
        .unwrap_or_else(|| panic!("PRODUCT (staging): no <profile>/store.redb under {dir:?}"))
}

/// The attack: delete the counter's row from a stopped node's store. Returns the rows the `meta`
/// table held before, and the deleted row's length (`None`: there was no such row).
fn delete_counter(dir: &Path) -> (Vec<String>, Option<usize>) {
    const META: redb::TableDefinition<&str, &[u8]> = redb::TableDefinition::new("meta");
    // Opening fails while any vox process still holds the store: the staging (every process of
    // alice's stopped) was not achieved.
    let db = redb::Database::open(store_file(dir)).unwrap_or_else(|e| {
        panic!("PRODUCT (staging): store still held, or unreadable, when it should be stopped: {e}")
    });
    let tx = db
        .begin_write()
        .unwrap_or_else(|e| panic!("APPARATUS: redb write transaction on alice's store: {e}"));
    let (names, removed) = {
        let mut table = tx
            .open_table(META)
            .unwrap_or_else(|e| panic!("APPARATUS: open alice's meta table: {e}"));
        let names = redb::ReadableTable::iter(&table)
            .unwrap_or_else(|e| panic!("APPARATUS: list alice's meta table: {e}"))
            .filter_map(Result::ok)
            .map(|(k, _)| k.value().to_owned())
            .collect::<Vec<_>>();
        let removed = table
            .remove(COUNTER_ROW)
            .unwrap_or_else(|e| panic!("APPARATUS: delete the counter row: {e}"))
            .map(|v| v.value().len());
        (names, removed)
    };
    tx.commit()
        .unwrap_or_else(|e| panic!("APPARATUS: commit the counter's deletion: {e}"));
    (names, removed)
}

#[test]
#[ignore = "real vox daemons and `vox tui` in a pty, with production Argon2id; CI runs it in release"]
fn a_deleted_consent_counter_releases_nothing_sealed_before_the_trust() {
    watchdog::arm();
    let tmp = tempfile::tempdir().expect("APPARATUS: tempdir");
    let alice = tmp.path().join("alice");
    let bob = tmp.path().join("bob");
    let carol = tmp.path().join("carol");
    for d in [&alice, &bob, &carol] {
        std::fs::create_dir_all(d.join("cfg")).expect("APPARATUS: harness file I/O");
    }
    let mut fps = Vec::new();
    for dir in [&alice, &bob, &carol] {
        let (ok, out, err) = vox(dir, &["id"], None);
        assert!(ok, "PRODUCT (staging): vox id failed: {err}");
        fps.push(out.trim().to_owned());
    }
    let (ok, _, err) = vox(&bob, &["trust", "add", &fps[0], "--name", "alice"], None);
    assert!(
        ok,
        "PRODUCT (staging): bob's trust add of alice failed: {err}"
    );

    // ---- alice's counter moves past its first value; room C gets its pre-trust posts ----------
    let first = daemon(&alice, "alice-1", &format!("{IDENTITY}\n"));
    attached(&alice, "alice-1");
    let (ok, _, err) = vox(&alice, &["trust", "add", &fps[2], "--name", "carol"], None);
    assert!(
        ok,
        "PRODUCT (staging): alice's trust add of carol failed: {err}"
    );
    let (ok, _, err) = vox(
        &alice,
        &["room", "create", "--name", "c"],
        Some(&format!("{ROOMPASS}\n")),
    );
    assert!(ok, "PRODUCT (staging): vox room create failed: {err}");
    let listing = attached(&alice, "alice-1");
    let room = listing
        .split_whitespace()
        .find(|w| w.len() >= 8 && w.chars().all(|c| c.is_ascii_alphanumeric()))
        .unwrap_or_else(|| {
            panic!("PRODUCT (staging): no room id in `room list` after create: {listing:?}")
        })
        .to_owned();
    post_range(&alice, &room, 1, 20);
    drop(first);

    // ---- close C as a person does: in the TUI ---------------------------------------------------
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/pty/tui_close_room.py");
    let out = pty_driver::run(
        script,
        &[
            VOX,
            &alice.to_string_lossy(),
            &alice.join("cfg").to_string_lossy(),
            IDENTITY,
            ROOMPASS,
            "cargo",
        ],
    );
    let said = out.stdout.clone();
    println!(
        "[proof] the TUI driver took {:?}; its last stage: {:?}",
        out.took, out.stage
    );
    assert!(
        out.has_verdict("cargo"),
        "APPARATUS: the TUI driver was stopped before it gave a verdict — by its faulthandler \
         backstop, or from outside — at stage {:?} (exit {:?}): {said}",
        out.stage.as_deref().unwrap_or("(before its first stage)"),
        out.code
    );
    println!("[proof] tui: {}", said.trim());
    assert!(
        !said.contains("cargo APPARATUS"),
        "APPARATUS: the TUI driver's own apparatus failed (exit {:?}): {said}",
        out.code
    );
    // Closing the room is staging for this claim, but a TUI that does not do it — exits, never
    // unlocks with the right passphrase, never answers `:close`, stops reading what is typed —
    // is the product failing a person, not the test (V210-107's verdict on 480c6a73).
    assert!(
        out.code == Some(0) && said.contains("cargo the TUI said done to :close"),
        "PRODUCT (staging): alice's `vox tui` did not unlock, open room C and close it as a person \
         does; the driver exited {:?} at stage {:?} and saw this screen:\n{said}",
        out.code,
        out.stage.as_deref().unwrap_or("(before its first stage)")
    );

    // ---- the attack: delete the counter while every vox process of alice's is stopped ---------
    let (rows, removed) = delete_counter(&alice);
    println!(
        "[proof] alice's meta rows before: {rows:?}; deleted {COUNTER_ROW:?}: {removed:?} bytes"
    );
    assert!(
        removed.is_some(),
        "PRODUCT (staging): alice's store holds no {COUNTER_ROW:?} row to delete (rows: {rows:?})"
    );

    // ---- alice trusts bob while C is closed -----------------------------------------------------
    let second = daemon(&alice, "alice-2", &format!("{IDENTITY}\n"));
    let line = room_line(&alice, "alice-2", &room);
    println!("[proof] at the decision: {}", line.trim());
    assert!(
        line.contains("[closed]"),
        "PRODUCT (staging): room C is open at the decision, so this is not the closed-room path: \
         {line}"
    );
    let (ok, _, err) = vox(&alice, &["trust", "add", &fps[1], "--name", "bob"], None);
    assert!(
        ok,
        "PRODUCT (staging): alice's trust add of bob, with room C closed, failed: {err}"
    );
    drop(second);

    // ---- C opens again (its passphrase to the daemon); alice posts after the trust ------------
    let _third = daemon(&alice, "alice-3", &format!("{IDENTITY}\n{ROOMPASS}\n"));
    let line = room_line(&alice, "alice-3", &room);
    println!("[proof] after reopening: {}", line.trim());
    assert!(
        !line.contains("[closed]"),
        "PRODUCT (staging): room C did not reopen from its passphrase line: {line}\nalice's daemon \
         said: {}",
        std::fs::read_to_string(alice.join("daemon-alice-3.err")).unwrap_or_default()
    );
    post_range(&alice, &room, 21, 30);
    let (mine, rows) = read_posts(&alice, &room);
    assert!(
        mine.len() == 30 && rows == 30,
        "PRODUCT (staging): alice herself reads {} distinct posts in {rows} rows, not 30",
        mine.len()
    );

    // ---- bob joins C and reads ------------------------------------------------------------------
    let _bob_daemon = daemon(&bob, "bob", &format!("{IDENTITY}\n"));
    attached(&bob, "bob");
    let (ok, link, err) = vox(&alice, &["room", "invite", &room], None);
    assert!(ok, "PRODUCT (staging): vox room invite failed: {err}");
    let (ok, _, err) = vox(
        &bob,
        &["room", "join", link.trim(), "--name", "c"],
        Some(&format!("{ROOMPASS}\n")),
    );
    assert!(ok, "PRODUCT (staging): vox room join failed: {err}");

    let t0 = Instant::now();
    let mut all = BTreeSet::new();
    let mut got_at: Option<Instant> = None;
    let mut last = usize::MAX;
    loop {
        all.extend(read_posts(&bob, &room).0);
        if all.len() != last {
            println!(
                "[proof] +{:?}: bob reads {} posts {:?}",
                t0.elapsed(),
                all.len(),
                ranges(all.iter().copied())
            );
            last = all.len();
        }
        if got_at.is_none() && (21..=30).all(|n| all.contains(&n)) {
            got_at = Some(Instant::now());
        }
        if got_at.is_some_and(|g| g.elapsed() > Duration::from_secs(45)) || t0.elapsed() > BOUND {
            break;
        }
        std::thread::sleep(Duration::from_secs(2));
    }
    let pre: Vec<usize> = all.iter().copied().filter(|n| *n <= 20).collect();
    let post: Vec<usize> = all.iter().copied().filter(|n| *n > 20).collect();
    println!(
        "[proof] bob reads {} of the 20 posts sealed before alice trusted him {:?}, and {} of \
         the 10 after {:?}",
        pre.len(),
        ranges(pre.iter().copied()),
        post.len(),
        ranges(post.iter().copied())
    );
    assert!(
        pre.is_empty(),
        "PRODUCT: LEAK: after the counter was deleted, bob reads {} posts alice sealed before she trusted \
         him: {:?}",
        pre.len(),
        ranges(pre.iter().copied())
    );
    assert!(
        post.contains(&30),
        "PRODUCT (staging): bob never read post 30, made after alice trusted him, so his key never \
         arrived\nbob's daemon said: {}\nalice's daemon said: {}",
        std::fs::read_to_string(bob.join("daemon-bob.err")).unwrap_or_default(),
        std::fs::read_to_string(alice.join("daemon-alice-3.err")).unwrap_or_default()
    );
    assert_eq!(
        post,
        (21..=30).collect::<Vec<_>>(),
        "PRODUCT: bob must read exactly posts 21-30, the 10 alice made after trusting him"
    );
}
