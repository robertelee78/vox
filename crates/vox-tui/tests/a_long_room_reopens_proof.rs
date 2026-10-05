//! PRD-001 R1/R3 — a room with a long history reopens, and a newcomer's log catches up with all of it,
//! driven through the **shipped `vox` binary**.
//!
//! **The defect (PRD-001 D1).** Every log entry passed `Dag::accept`, which charged it to a
//! per-author quota of 1,000 entries per rolling hour: an entry authored here, an entry arriving
//! by sync, and — the part that made it a defect rather than a policy — every **stored** entry
//! replayed when a room is opened. Replay is one burst, so the 1,001st stored entry from one
//! author was "over quota" at open time and the room could not be opened: a room was lost for good
//! once one member had posted a thousand times in an hour, and restarting the node was what
//! triggered it. The same charge refused the 1,001st post outright and throttled a newcomer's
//! catch-up. The decider removed the quota (R3): invitees are trusted, agents are not throttled.
//!
//! What this drives, as an operator would type it:
//!
//! ```text
//! vox id; vox trust add …          # two identities that consent to each other
//! vox daemon                       # alice's node, no terminal
//! vox room create; vox room post   # posts from one author, every one must succeed
//! (kill the daemon) vox daemon     # restart: the room must open, and read back every row
//! vox room link / vox room join  # bob, cold
//! vox room post (alice, after)      # bob must render it: his log holds her whole feed
//! vox room read --json --limit/--since  # counted page by page, as an agent reads a long room
//! ```
//!
//! **Every participant is the shipped binary.** What is counted is what `vox room read --json`
//! prints, paged with `--limit` and `--since` the way an agent walks a long room. Each count is
//! of the distinct `post <i>` texts, so a duplicated or missing row cannot hide behind a right
//! total. Nothing in this process runs a node or opens a store.
//!
//! **How bob's catch-up is seen from outside.** Alice posts once more after bob has joined, and
//! bob must render that post. A member's log accepts an author's entry at `seq` only after that
//! author's entries `1..seq-1` (the feed append checks the sequence is contiguous and the
//! `prev_hash` and `lipmaa_backlink` chain), so a rendered post `n + 1` means bob's log holds
//! every one of alice's `n` posts before it. That is the claim: the newcomer's **log** catches
//! up with the whole history, of any size.
//!
//! **Sizes.** "Any size" cannot be run, so two are: [`MID`] (5,000), which is five times the old
//! 1,000-per-author cap and more than three times the 1,500 this proof used to stage; and [`LARGE`]
//! (100,000), past 65,536 where a 16-bit count or index would wrap, whose staging takes most of an
//! hour. Both are **optional** (`--features optional-proofs`): heavy proofs block nothing and run
//! on demand (decider, 2026-10-01 and 2026-10-02). The posts come from several shells at once to
//! stage them faster; every shell is the same profile, so it is still one author's feed.
//!
//! **Not asserted, printed:** how many of the pre-join posts bob can *read*. Bob was trusted
//! before any post, so he is entitled to all of them; that is #220's own proof to assert, and here
//! it is printed so a regression shows.
//!
//! **Mutation that must turn it red:** a lifetime cap on one author's entries anywhere between
//! 1,500 and [`MID`] in `Dag::accept`: the 5,000 arm goes red on its post assertion.

// Optional (decider, 2026-10-01): it blocks nothing and CI only compiles it. Without
// `--features optional-proofs` a stand-in takes each test's place and says it was not run
// (`support/optional_proof.rs`). How to run them: docs/release/optional-proofs.md.
#![cfg_attr(not(feature = "optional-proofs"), allow(dead_code, unused_imports))]
#![cfg(unix)]

#[path = "support/optional_proof.rs"]
mod optional_proof;
optional_proof::not_run!(
    a_room_of_five_thousand_posts_from_one_author_reopens_and_a_newcomer_holds_them_all,
    a_room_of_a_hundred_thousand_posts_reopens_and_a_newcomer_holds_them_all
);

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/attach.rs"]
mod attach;

use std::io::Write;
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

fn vox_plain(dir: &std::path::Path, args: &[&str], stdin: Option<&str>) -> (bool, String, String) {
    let mut cmd = Command::new(VOX);
    cmd.args(args)
        .env("VOX_DATA_DIR", dir)
        .env("VOX_CONFIG_DIR", dir.join("cfg"))
        // In the environment, not argv: a command line is world-readable (ADR-015).
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
            .expect("APPARATUS: stdin")
            .write_all(text.as_bytes())
            .expect("PRODUCT (staging): vox exited without reading its stdin");
        drop(child.stdin.take());
    }
    let out = child.wait_with_output().expect("APPARATUS: wait for vox");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// Start `vox daemon` with `stdin_lines` piped in, its output to files next to the profile.
fn daemon(dir: &std::path::Path, tag: &str, stdin_lines: &str) -> Daemon {
    let out = std::fs::File::create(dir.join(format!("daemon-{tag}.out")))
        .expect("APPARATUS: daemon log");
    let err = std::fs::File::create(dir.join(format!("daemon-{tag}.err")))
        .expect("APPARATUS: daemon log");
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
    pipe.write_all(stdin_lines.as_bytes())
        .expect("PRODUCT (staging): vox exited without reading its stdin");
    drop(pipe);
    Daemon(child)
}

/// `vox room list` once the daemon's socket answers.
fn attached(dir: &std::path::Path, tag: &str) -> String {
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

/// Rows per page when walking a room, as an agent reading a long room pages it.
const PAGE: usize = 500;

/// Every `post <i>` this profile's `vox room read --json` shows for `room`, walked a page at a
/// time with `--limit` and `--since`. Returns the distinct post numbers, how many rows carried
/// one (a duplicate would make this larger than the set), the pages read, and any refusal.
fn read_posts(
    dir: &std::path::Path,
    room: &str,
) -> (std::collections::BTreeSet<usize>, usize, usize, String) {
    let mut seen = std::collections::BTreeSet::new();
    let (mut rows_with_post, mut pages) = (0usize, 0usize);
    let mut since: Option<String> = None;
    loop {
        let limit = PAGE.to_string();
        let mut args = vec!["room", "read", room, "--json", "--limit", &limit];
        if let Some(c) = since.as_deref() {
            args.extend(["--since", c]);
        }
        let (ok, out, err) = vox(dir, &args, None);
        if !ok {
            return (seen, rows_with_post, pages, err);
        }
        pages += 1;
        let page: Vec<serde_json::Value> = out
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| {
                serde_json::from_str(l)
                    .unwrap_or_else(|e| panic!("PRODUCT: `vox room read --json` row ({e}): {l}"))
            })
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
                        .expect("PRODUCT: every row carries its entry hash")
                        .to_owned(),
                );
            }
            _ => return (seen, rows_with_post, pages, String::new()),
        }
    }
}

/// Post `"post 1"` … `"post {posts}"` to `room` as this profile, from `writers` shells at once
/// (one author: every shell is this profile's daemon). Returns the first refusal, if any.
fn post_all(dir: &std::path::Path, room: &str, posts: usize, writers: usize) -> Option<String> {
    let refused = std::sync::Mutex::new(None::<String>);
    let posted = std::sync::atomic::AtomicUsize::new(0);
    std::thread::scope(|s| {
        for w in 0..writers {
            let (refused, posted) = (&refused, &posted);
            s.spawn(move || {
                for i in (1 + w..=posts).step_by(writers) {
                    if refused.lock().unwrap().is_some() {
                        return;
                    }
                    let (ok, _, err) =
                        vox(dir, &["room", "post", room, &format!("post {i}")], None);
                    if !ok {
                        let done = posted.load(std::sync::atomic::Ordering::Relaxed);
                        refused.lock().unwrap().get_or_insert(format!(
                            "post {i} of {posts} was refused after {done} succeeded: {err}"
                        ));
                        return;
                    }
                    posted.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
            });
        }
    });
    refused.into_inner().unwrap()
}

/// **Optional** (PRD-001 R1): past 1,000 posts from one author (D1) and past what a room held
/// before, the room reopens after a restart and a newcomer catches up cold.
const MID: usize = 5_000;

/// **Optional**, the heavier arm: a room of this many posts from one author, past 65,536, where
/// any 16-bit count or index would wrap. Staging alone takes most of an hour.
const LARGE: usize = 100_000;

#[cfg(feature = "optional-proofs")]
#[test]
#[ignore = "optional: real vox daemons, 5,000 CLI posts and production Argon2id; run it in release"]
fn a_room_of_five_thousand_posts_from_one_author_reopens_and_a_newcomer_holds_them_all() {
    watchdog::arm_for(Duration::from_secs(1_200));
    a_room_of(MID, 4, Duration::from_secs(300));
}

#[cfg(feature = "optional-proofs")]
#[test]
#[ignore = "optional: 100,000 CLI posts, most of an hour; run in release"]
fn a_room_of_a_hundred_thousand_posts_reopens_and_a_newcomer_holds_them_all() {
    watchdog::arm_for(Duration::from_secs(4 * 3_600));
    a_room_of(LARGE, 8, Duration::from_secs(1_800));
}

/// One author posts `posts` times (from `writers` shells); the room must reopen after a restart
/// with every post, and a newcomer who joins cold must catch up within `catch_up`.
fn a_room_of(posts: usize, writers: usize, catch_up: Duration) {
    let tmp = tempfile::tempdir().expect("APPARATUS: a tempdir");
    let alice = tmp.path().join("alice");
    let bob = tmp.path().join("bob");
    for d in [&alice, &bob] {
        std::fs::create_dir_all(d.join("cfg")).expect("APPARATUS: create a profile dir");
    }

    // ---- two identities that consent to each other, decided before any daemon runs ----
    let mut fps = Vec::new();
    for dir in [&alice, &bob] {
        let (ok, out, err) = vox(dir, &["id"], None);
        assert!(ok, "PRODUCT (staging): vox id: {err}");
        fps.push(out.trim().to_owned());
    }
    for (dir, fp, name) in [(&alice, &fps[1], "bob"), (&bob, &fps[0], "alice")] {
        let (ok, _, err) = vox(dir, &["trust", "add", fp, "--name", name], None);
        assert!(ok, "PRODUCT (staging): vox trust add {name}: {err}");
    }

    // ---- alice: a room, and `posts` posts from one author --------------------------------
    let first = daemon(&alice, "first", &format!("{IDENTITY}\n"));
    attached(&alice, "alice");
    let (ok, _, err) = vox(
        &alice,
        &["room", "create", "--passphrase-file", "-", "--name", "long"],
        Some(&format!("{ROOMPASS}\n")),
    );
    assert!(ok, "PRODUCT (staging): vox room create: {err}");
    let listed = attached(&alice, "alice");
    let room = listed
        .split_whitespace()
        .find(|w| w.len() >= 8 && w.chars().all(|c| c.is_ascii_alphanumeric()))
        .unwrap_or_else(|| panic!("PRODUCT: no room id in `room list`: {listed:?}"))
        .to_owned();

    let started = Instant::now();
    if let Some(why) = post_all(&alice, &room, posts, writers) {
        panic!("PRODUCT: {why} — one author may post without limit (PRD-001 R1/R3)");
    }
    let (before, before_rows, pages, why) = read_posts(&alice, &room);
    println!(
        "[proof] alice posted {posts} through `vox room post` ({writers} shells) in {:?}; `vox \
         room read --json` shows {} distinct posts in {before_rows} rows over {pages} pages {why}",
        started.elapsed(),
        before.len()
    );
    assert_eq!(
        (before.len(), before_rows),
        (posts, posts),
        "PRODUCT: every post reads back once before the restart {why}"
    );

    // ---- restart: the room must open, with every row --------------------------------------
    drop(first); // killed by PID
    let second = daemon(&alice, "second", &format!("{IDENTITY}\n{ROOMPASS}\n"));
    let listed = attached(&alice, "alice");
    let (after, after_rows, pages, why) = read_posts(&alice, &room);
    println!(
        "[proof] after the restart: `room list` says {listed:?}; `vox room read --json` shows {} \
         distinct posts in {after_rows} rows over {pages} pages {why}",
        after.len()
    );
    assert!(
        listed.contains("long") && !listed.contains("[closed]"),
        "PRODUCT: the room with {posts} posts from one author did not reopen after a restart: \
         {listed:?} — PRD-001 D1\nalice's daemon said: {}",
        std::fs::read_to_string(alice.join("daemon-second.err")).unwrap_or_default()
    );
    assert_eq!(
        (after.len(), after_rows),
        (posts, posts),
        "PRODUCT: every post reads back once after the restart {why}"
    );

    // ---- bob joins cold and must read every row ------------------------------------------
    let (ok, link, err) = vox(&alice, &["room", "link", &room], None);
    assert!(ok, "PRODUCT (staging): vox room link: {err}");
    let link = link.trim().to_owned();
    let bob_daemon = daemon(&bob, "bob", &format!("{IDENTITY}\n"));
    attached(&bob, "bob");
    let (ok, _, err) = vox(
        &bob,
        &[
            "room",
            "join",
            "--passphrase-file",
            "-",
            &link,
            "--name",
            "long",
        ],
        Some(&format!("{ROOMPASS}\n")),
    );
    assert!(ok, "PRODUCT (staging): vox room join: {err}");
    // ---- bob's log catches up: he renders the post alice makes after his join ----------
    let joined = Instant::now();
    let after_join = format!("post {}", posts + 1);
    let (ok, _, err) = vox(&alice, &["room", "post", &room, &after_join], None);
    assert!(ok, "PRODUCT: alice's post after bob joined: {err}");
    let deadline = joined + catch_up;
    let caught_up = loop {
        let (ok, out, _) = vox(&bob, &["room", "read", &room, "--json"], None);
        let seen = ok
            && out.lines().any(|l| {
                serde_json::from_str::<serde_json::Value>(l)
                    .is_ok_and(|r| r["text"].as_str() == Some(after_join.as_str()))
            });
        if seen || Instant::now() > deadline {
            break seen;
        }
        std::thread::sleep(Duration::from_secs(2));
    };
    let took = joined.elapsed();
    let (bob_posts, bob_rows, pages, why) = read_posts(&bob, &room);
    let history: Vec<usize> = bob_posts.iter().copied().filter(|n| *n <= posts).collect();
    println!(
        "[proof] bob rendered alice's {after_join:?} (made after his join): {caught_up} after \
         {took:?}; his `vox room read --json` shows {} distinct posts in {bob_rows} rows over \
         {pages} pages {why}; of the {posts} pre-join posts he reads {} (first {:?}, last {:?}) \
         — printed, not asserted",
        bob_posts.len(),
        history.len(),
        history.first(),
        history.last()
    );
    assert!(
        caught_up,
        "PRODUCT: a newcomer's log must catch up with the whole history, of any size (PRD-001 \
         R1): bob never rendered {after_join:?}, which his log can accept only after all {posts} \
         of alice's earlier posts, within {took:?}\nbob's daemon said: {}",
        std::fs::read_to_string(bob.join("daemon-bob.err")).unwrap_or_default()
    );
    drop(bob_daemon);
    drop(second);
}
