//! V210-45 (#220) — **a member reads what follows its trust, and never a post sealed before
//! it**, driven through the **shipped `vox` binary**. The negative half of
//! `a_newcomer_reads_the_whole_history_proof`, adapted from the security verifier's check on
//! #220.
//!
//! **The claim.** Consent is forward-only from the moment it is decided (ADR-006, ADR-020 §3):
//! trusting bob entitles him to every post alice seals after that decision, however long the
//! stretch, and to none she sealed before it. What was sealed when is decided by the profile's
//! logical consent order — each sender-key generation and each trust decision draws the next
//! value of one persisted counter — never by a clock.
//!
//! **Staging.** Bob trusts alice; alice does not trust bob yet. Alice creates rooms A and B and
//! posts 1,100 times in each, which is past one sender-key rotation (every 1,000 messages), so
//! each room has a rotated-out generation (posts 1–1,000) and a live one (1,001–1,100 so far).
//! - **Arm A (a member when trusted):** bob joins A; alice trusts bob and posts 1,101–1,110 in A.
//! - **Arm B (spanning):** alice posts 1,101–2,050 in B — 1,101–2,000 finish the generation live
//!   at her decision, 2,001–2,050 ride one minted after it — and only then bob joins B.
//!
//! **Asserted,** with hard-coded numbers, after each arm keeps reading 45–60 s past the moment
//! its required posts arrived (a late history release must be caught): in arm A bob reads
//! exactly posts 1,101–1,110; in arm B exactly 1,101–2,050, all 950 of them; in neither any of
//! posts 1–1,100. Precondition, or `CANNOT MEASURE`: alice's own paged reads show every post she
//! made in both rooms.
//!
//! **The clock-step attack cannot be staged here** (it needs clock control, and sudo is
//! forbidden): the design makes it inexpressible, since no clock reading enters the order.
//!
//! **Every participant is the shipped binary.** Nothing in this process runs a node, opens a
//! store or speaks a wire protocol; each step is a `vox` process with its own
//! `VOX_DATA_DIR`/`VOX_CONFIG_DIR`, killed by its PID when dropped.
//!
//! **Mutations that must turn it red:** drop the consent-order comparison, so every retained
//! generation goes whole (bob reads posts 1–1,100 in both arms); release the generation live at
//! the decision from its origin instead of its position then (bob reads 1,001–1,100 in both
//! arms). Dropping the live generation's post-trust part (the first fix's behaviour) leaves arm B
//! at 50 of 950.

// Optional (decider, 2026-10-01): it blocks nothing and CI only compiles it. Without
// `--features optional-proofs` a stand-in takes its place and says it was not run
// (`support/optional_proof.rs`). How to run it: docs/release/optional-proofs.md.
#![cfg_attr(not(feature = "optional-proofs"), allow(dead_code, unused_imports))]
#![cfg(unix)]

#[path = "support/optional_proof.rs"]
mod optional_proof;
optional_proof::not_run!(posts_sealed_before_trust_stay_unreadable_and_everything_after_is_read);

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::collections::BTreeSet;
use std::io::Write;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const VOX: &str = env!("CARGO_BIN_EXE_vox");
const IDENTITY: &str = "an identity passphrase";
const ROOMPASS: &str = "the room passphrase";
/// How long bob has, in each arm, to read what he is entitled to.
const BOUND: Duration = Duration::from_secs(300);
/// Rows per page when walking a room, as an agent reading a long room pages it.
const PAGE: usize = 500;

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

/// Start `vox daemon` with the identity passphrase piped in, its output to files by the profile.
fn daemon(dir: &Path, tag: &str) -> Daemon {
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
    // Write, then close: the daemon reads stdin to EOF before it binds its socket.
    let mut pipe = child.stdin.take().expect("daemon stdin");
    pipe.write_all(format!("{IDENTITY}\n").as_bytes()).unwrap();
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
        "CANNOT MEASURE: {tag}'s daemon never answered: {last}\nits stderr: {}",
        std::fs::read_to_string(dir.join(format!("daemon-{tag}.err"))).unwrap_or_default()
    );
}

/// Every `post <i>` this profile's `vox room read --json` shows for `room`, walked a page at a
/// time with `--limit` and `--since`. Returns the distinct post numbers, how many rows carried
/// one (a duplicate would make this larger than the set), and the pages read.
fn read_posts(dir: &Path, room: &str) -> (BTreeSet<usize>, usize, usize) {
    let mut seen = BTreeSet::new();
    let (mut rows_with_post, mut pages) = (0usize, 0usize);
    let mut since: Option<String> = None;
    loop {
        let limit = PAGE.to_string();
        let mut args = vec!["room", "read", room, "--json", "--limit", &limit];
        if let Some(c) = since.as_deref() {
            args.extend(["--since", c]);
        }
        let (ok, out, err) = vox(dir, &args, None);
        assert!(ok, "vox room read --json refused: {err}");
        pages += 1;
        let page: Vec<serde_json::Value> = out
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("bad row ({e}): {l}")))
            .collect();
        for row in &page {
            if let Some(n) = row["text"]
                .as_str()
                .and_then(|t| t.strip_prefix("post "))
                .and_then(|n| n.parse::<usize>().ok())
            {
                rows_with_post += 1;
                seen.insert(n);
            }
        }
        match page.last() {
            Some(last) if page.len() == PAGE => {
                since = Some(
                    last["entry_hash"]
                        .as_str()
                        .expect("every row carries its entry hash")
                        .to_owned(),
                );
            }
            _ => return (seen, rows_with_post, pages),
        }
    }
}

/// Create room `name` on alice's daemon and return its id: the one `vox room list` shows now and
/// did not before.
fn create_room(alice: &Path, name: &str, before: &BTreeSet<String>) -> String {
    let (ok, _, err) = vox(
        alice,
        &["room", "create", "--passphrase-file", "-", "--name", name],
        Some(&format!("{ROOMPASS}\n")),
    );
    assert!(ok, "vox room create: {err}");
    attached(alice, "alice")
        .split_whitespace()
        .filter(|w| w.len() >= 8 && w.chars().all(|c| c.is_ascii_alphanumeric()))
        .map(str::to_owned)
        .find(|w| !before.contains(w))
        .expect("a new room id in `room list`")
}

/// `post <lo>` .. `post <hi>`, each a separate `vox room post`.
fn post_range(alice: &Path, room: &str, lo: usize, hi: usize) {
    for i in lo..=hi {
        let (ok, _, err) = vox(alice, &["room", "post", room, &format!("post {i}")], None);
        assert!(ok, "CANNOT MEASURE: alice's post {i} was refused: {err}");
    }
}

/// Bob joins `room` from alice's `vox room invite`.
fn join(bob: &Path, alice: &Path, room: &str, name: &str) {
    let (ok, link, err) = vox(alice, &["room", "invite", room], None);
    assert!(ok, "vox room invite: {err}");
    let (ok, _, err) = vox(
        bob,
        &[
            "room",
            "join",
            "--passphrase-file",
            "-",
            link.trim(),
            "--name",
            name,
        ],
        Some(&format!("{ROOMPASS}\n")),
    );
    assert!(ok, "CANNOT MEASURE: vox room join: {err}");
}

/// Read bob's view of `room` until every post in `need` is there (or [`BOUND`] passes), then
/// keep reading for `hold`, to catch a late release. Returns everything ever seen.
fn watch(bob: &Path, room: &str, tag: &str, need: &[usize], hold: Duration) -> BTreeSet<usize> {
    let t0 = Instant::now();
    let mut all = BTreeSet::new();
    let mut got_at: Option<Instant> = None;
    let mut last = usize::MAX;
    loop {
        let (seen, _, _) = read_posts(bob, room);
        all.extend(seen);
        if all.len() != last {
            println!(
                "[proof] {tag} +{:?}: bob reads {} posts (min {:?}, max {:?})",
                t0.elapsed(),
                all.len(),
                all.first(),
                all.last()
            );
            last = all.len();
        }
        if got_at.is_none() && need.iter().all(|n| all.contains(n)) {
            got_at = Some(Instant::now());
        }
        if got_at.is_some_and(|g| g.elapsed() > hold) || t0.elapsed() > BOUND {
            return all;
        }
        std::thread::sleep(Duration::from_secs(2));
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

#[cfg(feature = "optional-proofs")]
#[test]
#[ignore = "real vox daemons, 3,160 CLI posts and production Argon2id; optional, run it in release"]
fn posts_sealed_before_trust_stay_unreadable_and_everything_after_is_read() {
    // Two joins; 8 unlocks: two `vox id`s, two `trust add`s, two daemons and two rooms created.
    watchdog::arm_for_setup(2, 8);
    let tmp = tempfile::tempdir().unwrap();
    let alice = tmp.path().join("alice");
    let bob = tmp.path().join("bob");
    for d in [&alice, &bob] {
        std::fs::create_dir_all(d.join("cfg")).unwrap();
    }
    let mut fps = Vec::new();
    for dir in [&alice, &bob] {
        let (ok, out, err) = vox(dir, &["id"], None);
        assert!(ok, "vox id: {err}");
        fps.push(out.trim().to_owned());
    }
    // Only bob trusts alice up front; alice's decision comes later.
    let (ok, _, err) = vox(&bob, &["trust", "add", &fps[0], "--name", "alice"], None);
    assert!(ok, "bob trusts alice: {err}");

    let alice_daemon = daemon(&alice, "alice");
    let before: BTreeSet<String> = attached(&alice, "alice")
        .split_whitespace()
        .map(str::to_owned)
        .collect();
    let room_a = create_room(&alice, "arma", &before);
    let mut before_b = before.clone();
    before_b.insert(room_a.clone());
    let room_b = create_room(&alice, "armb", &before_b);

    let t = Instant::now();
    post_range(&alice, &room_a, 1, 1_100);
    post_range(&alice, &room_b, 1, 1_100);
    println!(
        "[proof] 2,200 posts before alice trusts bob, in {:?}",
        t.elapsed()
    );

    let bob_daemon = daemon(&bob, "bob");
    attached(&bob, "bob");
    join(&bob, &alice, &room_a, "arma");
    // Let bob's join settle on alice, so he is a member of A when she decides.
    std::thread::sleep(Duration::from_secs(5));

    // No pause around the decision: the order is logical, so the same second as a mint or a
    // post decides nothing.
    let (ok, _, err) = vox(&alice, &["trust", "add", &fps[1], "--name", "bob"], None);
    assert!(ok, "alice trusts bob: {err}");

    post_range(&alice, &room_a, 1_101, 1_110);
    post_range(&alice, &room_b, 1_101, 2_050);

    for (room, total) in [(&room_a, 1_110usize), (&room_b, 2_050)] {
        let (mine, rows, _) = read_posts(&alice, room);
        assert!(
            mine.len() == total && rows == total,
            "CANNOT MEASURE: alice herself reads {} distinct posts in {rows} rows of {room}, not \
             {total}",
            mine.len()
        );
    }

    // ---- arm A: a member of the room when alice decided --------------------------------
    let a_need: Vec<usize> = (1_101..=1_110).collect();
    let a = watch(&bob, &room_a, "arm A", &a_need, Duration::from_secs(45));
    let a_pre: Vec<usize> = a.iter().copied().filter(|n| *n <= 1_100).collect();
    let a_post: Vec<usize> = a.iter().copied().filter(|n| *n > 1_100).collect();
    println!(
        "[proof] arm A: bob reads {} posts sealed before the decision {:?}, and {} of the 10 \
         after it {:?}",
        a_pre.len(),
        ranges(a_pre.iter().copied()),
        a_post.len(),
        ranges(a_post.iter().copied())
    );

    // ---- arm B: joins after a generation that spans the decision ------------------------
    join(&bob, &alice, &room_b, "armb");
    let b_need: Vec<usize> = (1_101..=2_050).collect();
    let b = watch(&bob, &room_b, "arm B", &b_need, Duration::from_secs(60));
    let b_pre: Vec<usize> = b.iter().copied().filter(|n| *n <= 1_100).collect();
    let b_post: Vec<usize> = b.iter().copied().filter(|n| *n > 1_100).collect();
    println!(
        "[proof] arm B: bob reads {} posts sealed before the decision {:?}, and {} of the 950 \
         after it {:?}",
        b_pre.len(),
        ranges(b_pre.iter().copied()),
        b_post.len(),
        ranges(b_post.iter().copied())
    );

    let daemons = || {
        format!(
            "\nbob's daemon said: {}\nalice's daemon said: {}",
            std::fs::read_to_string(bob.join("daemon-bob.err")).unwrap_or_default(),
            std::fs::read_to_string(alice.join("daemon-alice.err")).unwrap_or_default()
        )
    };
    assert!(
        a_pre.is_empty(),
        "LEAK arm A: bob reads {} posts alice sealed before she trusted him: {:?}",
        a_pre.len(),
        ranges(a_pre.iter().copied())
    );
    assert!(
        b_pre.is_empty(),
        "LEAK arm B: bob reads {} posts alice sealed before she trusted him: {:?}",
        b_pre.len(),
        ranges(b_pre.iter().copied())
    );
    assert!(
        a_post.contains(&1_110),
        "CANNOT MEASURE: in arm A bob never read post 1110, made after alice trusted him, so his \
         key never arrived{}",
        daemons()
    );
    assert_eq!(
        a_post,
        (1_101..=1_110).collect::<Vec<_>>(),
        "arm A: bob must read exactly posts 1101-1110, the 10 alice made after trusting him"
    );
    assert_eq!(
        (
            b_post.len(),
            b_post.first().copied(),
            b_post.last().copied()
        ),
        (950, Some(1_101), Some(2_050)),
        "arm B: bob must read all 950 posts alice made after trusting him, 1101-2050, however the \
         generations fall; he read {:?}",
        ranges(b_post.iter().copied())
    );
    drop(bob_daemon);
    drop(alice_daemon);
}
