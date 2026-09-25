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
//! - **A forged entry below the checkpoint is refused as pre-checkpoint**, not raised as a fork:
//!   one signed by alice's own key (an equivocation) and one without a signature, both offered
//!   to alice's room through the same acceptance path sync uses.
//!
//! Mutations (each run, each red): shedding disabled; the pre-checkpoint refusal removed.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use vox_core::atrest::store::SegmentKind;
use vox_core::hash::COMPOSITE_SIG_LEN;

const VOX: &str = env!("CARGO_BIN_EXE_vox");
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

/// Start `vox daemon` on `dir` at `listen`, optionally with its millisecond clock skewed
/// (test-only).
fn daemon(dir: &Path, tag: &str, listen: &str, stdin_lines: &str, skew_ms: Option<i64>) -> Daemon {
    let out = std::fs::File::create(dir.join(format!("daemon-{tag}.out"))).unwrap();
    let err = std::fs::File::create(dir.join(format!("daemon-{tag}.err"))).unwrap();
    let mut cmd = Command::new(VOX);
    cmd.args(["daemon", "--listen", listen])
        .env("VOX_DATA_DIR", dir)
        .env("VOX_CONFIG_DIR", dir.join("cfg"))
        .env_remove("VOX_ROOM")
        .env_remove(vox_core::time::TEST_CLOCK_SKEW_ENV)
        .stdin(Stdio::piped())
        .stdout(Stdio::from(out))
        .stderr(Stdio::from(err));
    if let Some(skew) = skew_ms {
        cmd.env(vox_core::time::TEST_CLOCK_SKEW_ENV, skew.to_string());
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
            Err(e) => panic!("the store did not open: {e:?}"),
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

/// Offer `entry` to alice's room, stopped, through the acceptance path a sync uses; the error
/// text, or `None` if it was taken.
fn offer(
    dir: &Path,
    forge: impl FnOnce(&vox_core::node::profile::Profile, [u8; 32], u64) -> vox_core::log::entry::Entry,
) -> (Option<String>, usize, usize) {
    let paths = vox_core::node::paths::Paths::resolve("default", Some(dir), Some(&dir.join("cfg")))
        .unwrap();
    let mut profile = vox_core::node::profile::Profile::open(paths).expect("open the store");
    profile.unlock(IDENTITY.as_bytes()).expect("unlock");
    let cid = profile.store().channels().unwrap()[0];
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut ch =
        vox_core::node::channel::ChannelState::open(&profile, &cid, ROOMPASS.as_bytes(), now)
            .expect("open the room");
    let before = ch.entry_count();
    let entry = forge(&profile, cid, ch.epoch());
    let outcome = ch.accept_entry(profile.store(), entry, now);
    let after = ch.entry_count();
    (outcome.err().map(|e| format!("{e}")), before, after)
}

/// A skeleton for alice's own feed at `seq`, conflicting with the one she holds there.
fn forged_skeleton(
    author: [u8; 32],
    cid: [u8; 32],
    epoch: u64,
    seq: u64,
) -> vox_core::log::entry::EntrySkeleton {
    vox_core::log::entry::EntrySkeleton {
        author_id: author,
        seq,
        prev_hash: [7u8; 32],
        lipmaa_backlink: [7u8; 32],
        channel_id: cid,
        epoch,
        algo_ids: [
            vox_core::suite::algo::COMPOSITE_ED25519_ML_DSA_65,
            vox_core::suite::algo::AES_256_GCM,
        ],
        payload_hash: vox_core::hash::sha256(b"a forged message"),
        payload_len: 16,
        end_of_feed: false,
        claimed_ms: 0,
        seen: Vec::new(),
    }
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
        &["room", "create", "--name", "r"],
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

    // ---- a forged entry below the checkpoint is refused as pre-checkpoint ------------------
    let signed = offer(alice, |profile, cid, epoch| {
        let signer = profile.signer().unwrap();
        let sk = forged_skeleton(profile.fingerprint(), cid, epoch, 5);
        vox_core::log::entry::Entry::build_signed_skeleton_only(signer, sk).unwrap()
    });
    let unsigned = offer(alice, |profile, cid, epoch| {
        let signer = profile.signer().unwrap();
        let sk = forged_skeleton(profile.fingerprint(), cid, epoch, 6);
        let mut e = vox_core::log::entry::Entry::build_signed_skeleton_only(signer, sk).unwrap();
        e.drop_signature();
        e
    });
    for (what, (err, before, after)) in [("signed by alice", &signed), ("unsigned", &unsigned)] {
        println!("forged entry {what}: {err:?}; the room held {before} entries, then {after}");
        assert_eq!(
            before, after,
            "a forged entry below the checkpoint was stored"
        );
    }
    // The unsigned one is refused inside a sync session by the same predicate; offered alone
    // it is refused before it (an unsigned entry needs its feed). The signed one is the test:
    // alice's own key made it, so it would be a fork proof anywhere else.
    assert!(
        signed
            .0
            .as_deref()
            .is_some_and(|e| e.contains("at or below its author's checkpoint")),
        "an equivocation below the checkpoint must be refused as pre-checkpoint, not frozen \
         as a fork: {:?}",
        signed.0
    );
    assert!(unsigned.0.is_some(), "an unsigned forged entry was taken");

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
    let (ok, link, err) = vox(alice, &["room", "invite", &room], None);
    assert!(ok, "vox room invite: {err}");
    let (ok, _, err) = vox(
        bob,
        &["room", "join", link.trim(), "--name", "r"],
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
            "bob never caught up: {} of {} entries",
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
