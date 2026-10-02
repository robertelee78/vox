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
//! vox room create; vox room post   # POSTS posts from one author, every one must succeed
//! (kill the daemon) vox daemon     # restart: the room must open, and read back every row
//! vox room invite / vox room join  # bob, cold
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
//! `prev_hash` and `lipmaa_backlink` chain), so a rendered post 1,501 means bob's log holds
//! every one of alice's 1,500 posts before it. That is the claim: the newcomer's **log** catches
//! up with the whole history, of any size.
//!
//! **Not asserted, printed:** how many of the 1,500 pre-join posts bob can *read*. Bob was
//! trusted before any post, so he is entitled to all of them; on `integrate/v0.2.10` before
//! #220's fix he reads only 500 (posts 1,001–1,500), and #220 (`fix/220-whole-history`) makes it
//! 1,500. That is #220's own proof to assert; here it is printed so a regression shows.

// Optional (decider, 2026-10-01): it blocks nothing and CI only compiles it. Without
// `--features optional-proofs` a stand-in takes its place and says it was not run
// (`support/optional_proof.rs`). How to run it: docs/release/optional-proofs.md.
#![cfg_attr(not(feature = "optional-proofs"), allow(dead_code, unused_imports))]
#![cfg(unix)]

#[path = "support/optional_proof.rs"]
mod optional_proof;
optional_proof::not_run!(
    a_room_past_a_thousand_posts_from_one_author_reopens_and_a_newcomer_holds_them_all
);

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::io::Write;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const VOX: &str = env!("CARGO_BIN_EXE_vox");
const IDENTITY: &str = "an identity passphrase";
const ROOMPASS: &str = "the room passphrase";
/// Half again past the old 1,000-per-hour cap, from one author, inside a minute or two.
const POSTS: usize = 1_500;

/// A `vox daemon`, killed by its own PID when dropped.
struct Daemon(Child);

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn vox(dir: &std::path::Path, args: &[&str], stdin: Option<&str>) -> (bool, String, String) {
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

/// Start `vox daemon` with `stdin_lines` piped in, its output to files next to the profile.
fn daemon(dir: &std::path::Path, tag: &str, stdin_lines: &str) -> Daemon {
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
    pipe.write_all(stdin_lines.as_bytes()).unwrap();
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
        "{tag}'s daemon never answered: {last}\nits stderr: {}",
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
            _ => return (seen, rows_with_post, pages, String::new()),
        }
    }
}

#[cfg(feature = "optional-proofs")]
#[test]
#[ignore = "real vox daemons, 1,500 CLI posts and production Argon2id; optional, run it in release"]
fn a_room_past_a_thousand_posts_from_one_author_reopens_and_a_newcomer_holds_them_all() {
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();
    let alice = tmp.path().join("alice");
    let bob = tmp.path().join("bob");
    for d in [&alice, &bob] {
        std::fs::create_dir_all(d.join("cfg")).unwrap();
    }

    // ---- two identities that consent to each other, decided before any daemon runs ----
    let mut fps = Vec::new();
    for dir in [&alice, &bob] {
        let (ok, out, err) = vox(dir, &["id"], None);
        assert!(ok, "vox id: {err}");
        fps.push(out.trim().to_owned());
    }
    for (dir, fp, name) in [(&alice, &fps[1], "bob"), (&bob, &fps[0], "alice")] {
        let (ok, _, err) = vox(dir, &["trust", "add", fp, "--name", name], None);
        assert!(ok, "vox trust add {name}: {err}");
    }

    // ---- alice: a room, and POSTS posts from one author --------------------------------
    let first = daemon(&alice, "first", &format!("{IDENTITY}\n"));
    attached(&alice, "alice");
    let (ok, _, err) = vox(
        &alice,
        &["room", "create", "--name", "long"],
        Some(&format!("{ROOMPASS}\n")),
    );
    assert!(ok, "vox room create: {err}");
    let listed = attached(&alice, "alice");
    let room = listed
        .split_whitespace()
        .find(|w| w.len() >= 8 && w.chars().all(|c| c.is_ascii_alphanumeric()))
        .expect("a room id in `room list`")
        .to_owned();

    let started = Instant::now();
    for i in 1..=POSTS {
        let (ok, _, err) = vox(&alice, &["room", "post", &room, &format!("post {i}")], None);
        assert!(
            ok,
            "post {i} of {POSTS} was refused after {} succeeded: {err} — one author may post \
             without limit (PRD-001 R1/R3)",
            i - 1
        );
    }
    let (before, before_rows, pages, why) = read_posts(&alice, &room);
    println!(
        "[proof] alice posted {POSTS} through `vox room post` in {:?}; `vox room read --json` \
         shows {} distinct posts in {before_rows} rows over {pages} pages {why}",
        started.elapsed(),
        before.len()
    );
    assert_eq!(
        (before.len(), before_rows),
        (1_500, 1_500),
        "every post reads back once before the restart"
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
        "the room with {POSTS} posts from one author did not reopen after a restart: \
         {listed:?} — PRD-001 D1\nalice's daemon said: {}",
        std::fs::read_to_string(alice.join("daemon-second.err")).unwrap_or_default()
    );
    assert_eq!(
        (after.len(), after_rows),
        (1_500, 1_500),
        "every post reads back once after the restart"
    );

    // ---- bob joins cold and must read every row ------------------------------------------
    let (ok, link, err) = vox(&alice, &["room", "invite", &room], None);
    assert!(ok, "vox room invite: {err}");
    let link = link.trim().to_owned();
    let bob_daemon = daemon(&bob, "bob", &format!("{IDENTITY}\n"));
    attached(&bob, "bob");
    let (ok, _, err) = vox(
        &bob,
        &["room", "join", &link, "--name", "long"],
        Some(&format!("{ROOMPASS}\n")),
    );
    assert!(ok, "vox room join: {err}");
    // ---- bob's log catches up: he renders the post alice makes after his join ----------
    let joined = Instant::now();
    let after_join = format!("post {}", POSTS + 1);
    let (ok, _, err) = vox(&alice, &["room", "post", &room, &after_join], None);
    assert!(ok, "alice's post after bob joined: {err}");
    let deadline = joined + Duration::from_secs(300);
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
    let history: Vec<usize> = bob_posts.iter().copied().filter(|n| *n <= POSTS).collect();
    println!(
        "[proof] bob rendered alice's {after_join:?} (made after his join): {caught_up} after \
         {took:?}; his `vox room read --json` shows {} distinct posts in {bob_rows} rows over \
         {pages} pages {why}; of the {POSTS} pre-join posts he reads {} (first {:?}, last {:?}) \
         — printed, not asserted",
        bob_posts.len(),
        history.len(),
        history.first(),
        history.last()
    );
    assert!(
        caught_up,
        "a newcomer's log must catch up with the whole history, of any size (PRD-001 R1): bob \
         never rendered {after_join:?}, which his log can accept only after all {POSTS} of \
         alice's earlier posts, within {took:?}\nbob's daemon said: {}",
        std::fs::read_to_string(bob.join("daemon-bob.err")).unwrap_or_default()
    );
    drop(bob_daemon);
    drop(second);
}
