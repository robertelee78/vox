//! V210-45 (#220) — **a member entitled to a room's whole history reads all of it**, however
//! long, driven through the **shipped `vox` binary**.
//!
//! **The claim.** Alice and bob trust each other before either daemon runs, so alice's consent to
//! bob predates every post she makes. A room keeps history forever by default, and consent is
//! forward-only from the moment it is decided (ADR-006), so bob, joining cold after alice has
//! posted 1,500 times, must read all 1,500 — not only the ones since alice's last key rotation,
//! and not only the last 1,000 of anything.
//!
//! **The defect.** Bob's paged `vox room read --json` stopped at 500 posts, 1,001–1,500: a
//! sender key rotates every 1,000 messages (ADR-006 `N`), and a newcomer was handed only the
//! generation current at its admission, released at its origin. The rotated-out generation that
//! sealed posts 1–1,000 was never released to him, although the author retains its origin
//! precisely so it can be.
//!
//! **What this drives, as an operator would type it:**
//!
//! ```text
//! vox id; vox trust add …          # alice and bob consent to each other, before any daemon
//! vox daemon                       # alice's node
//! vox room create; vox room post   # 1,500 posts, each one a separate `vox room post`
//! vox daemon; vox room join        # bob, cold, from alice's `vox room invite`
//! vox room read --json --limit --since   # bob walks the room a page at a time
//! ```
//!
//! **Asserted:** bob's paged read shows every `post <i>` text, **each once and in order**, within
//! 300 s of his join. Two arms: [`a_newcomer_reads_a_short_history_once_each_in_order`] (60 posts
//! read 25 to a page) **blocks**; [`a_newcomer_trusted_before_every_post_reads_all_of_them`] (1,500
//! posts read 500 to a page, across the rotation at 1,000) is **optional** for its staging time. Precondition, or `CANNOT MEASURE`: alice's own paged read shows all 1,500,
//! and bob renders alice's post made *after* his join (so his log and his key did arrive).
//!
//! **Every participant is the shipped binary.** Nothing in this process runs a node, opens a
//! store or speaks a wire protocol; each step is a `vox` process with its own
//! `VOX_DATA_DIR`/`VOX_CONFIG_DIR`, killed by its PID when dropped.
//!
//! **Ordering.** Whether a generation was minted after bob was trusted is decided by the
//! profile's logical consent order (one persisted counter every mint and every trust decision
//! draws from), never by a clock. The first fix compared whole seconds and went red 1 run in 2
//! here: alice's `trust add` and her `room create` fall in the same second often enough. This
//! staging leaves them back to back on purpose, and must be green every run.
//!
//! The negative half — nothing sealed before a decision is ever read, and a generation spanning
//! the decision is read from the decision on — is `a_member_reads_only_what_follows_trust_proof`.
//!
//! **Mutation:** make the consent release cover no history (`history_plan` returns nothing) and
//! the 1,500-post arm goes red with bob short of 1,500. The short arm, inside one generation, is
//! the blocking check that a newcomer's paged read loses, repeats and reorders nothing.

// Two arms (decider, 2026-10-01: "Valid proofs block; rest optional"). The short history BLOCKS:
// a newcomer reads every post exactly once and in order, over several pages. The 1,500-post
// history, which crosses a sender-key rotation, is optional: CI only compiles it, and without
// `--features optional-proofs` a stand-in says it was not run (`support/optional_proof.rs`).
#![cfg(unix)]

#[path = "support/optional_proof.rs"]
mod optional_proof;
optional_proof::not_run!(a_newcomer_trusted_before_every_post_reads_all_of_them);

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
/// How long bob has, from his join, to read the whole history.
const BOUND: Duration = Duration::from_secs(300);

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
    let mut child = cmd
        .spawn()
        .unwrap_or_else(|e| panic!("APPARATUS: could not run {VOX} {args:?}: {e}"));
    if let Some(text) = stdin {
        // A `vox` that exits without reading its stdin closes the pipe: its exit status and what
        // it said are the verdict, so a refused write is reported, not fatal.
        if let Err(e) = child
            .stdin
            .as_mut()
            .expect("APPARATUS: a piped stdin")
            .write_all(text.as_bytes())
        {
            eprintln!("[harness] vox {args:?}: stdin not taken: {e}");
        }
        drop(child.stdin.take());
    }
    let out = child
        .wait_with_output()
        .unwrap_or_else(|e| panic!("APPARATUS: could not wait for {VOX} {args:?}: {e}"));
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// Start `vox daemon` with the identity passphrase piped in, its output to files by the profile.
fn daemon(dir: &Path, tag: &str) -> Daemon {
    let file = |kind: &str| {
        let at = dir.join(format!("daemon-{tag}.{kind}"));
        std::fs::File::create(&at)
            .unwrap_or_else(|e| panic!("APPARATUS: could not create {}: {e}", at.display()))
    };
    let mut child = Command::new(VOX)
        .args(["daemon", "--listen", "127.0.0.1:0"])
        .env("VOX_DATA_DIR", dir)
        .env("VOX_CONFIG_DIR", dir.join("cfg"))
        .env_remove("VOX_ROOM")
        .stdin(Stdio::piped())
        .stdout(Stdio::from(file("out")))
        .stderr(Stdio::from(file("err")))
        .spawn()
        .unwrap_or_else(|e| panic!("APPARATUS: could not run {VOX} daemon: {e}"));
    // Write, then close: the daemon reads stdin to EOF before it binds its socket.
    let mut pipe = child.stdin.take().expect("APPARATUS: a piped stdin");
    if let Err(e) = pipe.write_all(format!("{IDENTITY}\n").as_bytes()) {
        eprintln!("[harness] {tag}'s daemon did not take its passphrase: {e}");
    }
    drop(pipe);
    Daemon(child)
}

/// What a profile's daemon said on stderr, for a red.
fn said(dir: &Path, tag: &str) -> String {
    std::fs::read_to_string(dir.join(format!("daemon-{tag}.err")))
        .unwrap_or_else(|e| format!("(its stderr could not be read: {e})"))
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
        "PRODUCT: {tag}'s daemon never answered `vox room list` in 90 s: {last}\nits stderr: {}",
        said(dir, tag)
    );
}

/// Every `post <i>` this profile's `vox room read --json` shows for `room`, in the order its rows
/// come, walked `page` rows at a time with `--limit` and `--since`; and the pages read. A
/// duplicate shows as a number twice, a reordering as a number out of turn.
fn read_posts(dir: &Path, room: &str, page: usize) -> (Vec<usize>, usize) {
    let mut order = Vec::new();
    let mut pages = 0usize;
    let mut since: Option<String> = None;
    loop {
        let limit = page.to_string();
        let mut args = vec!["room", "read", room, "--json", "--limit", &limit];
        if let Some(c) = since.as_deref() {
            args.extend(["--since", c]);
        }
        let (ok, out, err) = vox(dir, &args, None);
        assert!(ok, "PRODUCT: `vox room read --json` refused: {err}");
        pages += 1;
        let rows: Vec<serde_json::Value> = out
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| {
                serde_json::from_str(l).unwrap_or_else(|e| {
                    panic!(
                        "PRODUCT: `vox room read --json` printed a row that is not JSON ({e}): {l}"
                    )
                })
            })
            .collect();
        order.extend(rows.iter().filter_map(|row| {
            row["text"]
                .as_str()
                .and_then(|t| t.strip_prefix("post "))
                .and_then(|n| n.parse::<usize>().ok())
        }));
        match rows.last() {
            Some(last) if rows.len() == page => {
                since = Some(
                    last["entry_hash"]
                        .as_str()
                        .unwrap_or_else(|| {
                            panic!("PRODUCT: a `vox room read --json` row carries no entry_hash: {last}")
                        })
                        .to_owned(),
                );
            }
            _ => return (order, pages),
        }
    }
}

/// The post numbers in `1..=posts` that `seen` lacks, as a few ranges for a failure message.
fn missing_ranges(seen: &BTreeSet<usize>, posts: usize) -> Vec<(usize, usize)> {
    let mut out: Vec<(usize, usize)> = Vec::new();
    for n in (1..=posts).filter(|n| !seen.contains(n)) {
        match out.last_mut() {
            Some((_, hi)) if *hi + 1 == n => *hi = n,
            _ => out.push((n, n)),
        }
    }
    out
}

/// The first place `order` is not `1, 2, 3, …`: its index, and what was there.
fn first_out_of_turn(order: &[usize]) -> Option<(usize, usize)> {
    order
        .iter()
        .enumerate()
        .find(|(i, n)| **n != i + 1)
        .map(|(i, n)| (i, *n))
}

/// The blocking arm: a history short enough to stage in seconds, read over several pages.
#[test]
#[ignore = "real vox daemons and production Argon2id; CI runs it in release"]
fn a_newcomer_reads_a_short_history_once_each_in_order() {
    newcomer_reads_the_whole_history(60, 25);
}

/// The optional arm: half again past one sender-key generation (1,000 messages), from one author.
#[cfg(feature = "optional-proofs")]
#[test]
#[ignore = "real vox daemons, 1,500 CLI posts and production Argon2id; optional, run it in release"]
fn a_newcomer_trusted_before_every_post_reads_all_of_them() {
    newcomer_reads_the_whole_history(1_500, 500);
}

/// Alice posts `posts` times; bob, trusted before any of them and joining cold, must read every
/// one exactly once and in order, `page` rows at a time.
fn newcomer_reads_the_whole_history(posts: usize, page: usize) {
    // One join; 7 unlocks: two `vox id`s, two `trust add`s, two daemons and the room.
    watchdog::arm_for_setup(1, 7);
    let tmp = tempfile::tempdir().unwrap_or_else(|e| panic!("APPARATUS: no temp dir: {e}"));
    let alice = tmp.path().join("alice");
    let bob = tmp.path().join("bob");
    for d in [&alice, &bob] {
        std::fs::create_dir_all(d.join("cfg"))
            .unwrap_or_else(|e| panic!("APPARATUS: could not create {}: {e}", d.display()));
    }

    // ---- two identities that consent to each other, decided before any daemon runs ----
    let mut fps = Vec::new();
    for dir in [&alice, &bob] {
        let (ok, out, err) = vox(dir, &["id"], None);
        assert!(ok, "PRODUCT: `vox id` failed: {err}");
        fps.push(out.trim().to_owned());
    }
    for (dir, fp, name) in [(&alice, &fps[1], "bob"), (&bob, &fps[0], "alice")] {
        let (ok, _, err) = vox(dir, &["trust", "add", fp, "--name", name], None);
        assert!(ok, "PRODUCT: `vox trust add` of {name} failed: {err}");
    }

    // ---- alice: a room, and `posts` posts from one author ------------------------------------
    let alice_daemon = daemon(&alice, "alice");
    attached(&alice, "alice");
    let (ok, _, err) = vox(
        &alice,
        &["room", "create", "--name", "long"],
        Some(&format!("{ROOMPASS}\n")),
    );
    assert!(ok, "PRODUCT: `vox room create` failed: {err}");
    let listed = attached(&alice, "alice");
    let room = listed
        .split_whitespace()
        .find(|w| w.len() >= 8 && w.chars().all(|c| c.is_ascii_alphanumeric()))
        .unwrap_or_else(|| panic!("PRODUCT: `vox room list` shows no room id: {listed}"))
        .to_owned();

    let started = Instant::now();
    for i in 1..=posts {
        let (ok, _, err) = vox(&alice, &["room", "post", &room, &format!("post {i}")], None);
        assert!(
            ok,
            "PRODUCT: alice's post {i} of {posts} was refused: {err}"
        );
    }
    let (mine, pages) = read_posts(&alice, &room, page);
    println!(
        "[proof] alice posted {posts} in {:?}; her own paged read shows {} rows over {pages} pages",
        started.elapsed(),
        mine.len()
    );
    // Every post was accepted above, so an author who cannot read them back once each, in
    // order, is the product's paged read failing, not a staging fault.
    assert!(
        first_out_of_turn(&mine).is_none() && mine.len() == posts,
        "PRODUCT: the author's own paged read of her {posts} accepted posts is not each once in \
         order: {} rows; first out of turn (index, post): {:?}",
        mine.len(),
        first_out_of_turn(&mine)
    );

    // ---- bob joins cold -------------------------------------------------------------------
    let (ok, link, err) = vox(&alice, &["room", "invite", &room], None);
    assert!(ok, "PRODUCT: `vox room invite` failed: {err}");
    let link = link.trim().to_owned();
    let bob_daemon = daemon(&bob, "bob");
    attached(&bob, "bob");
    let (ok, _, err) = vox(
        &bob,
        &["room", "join", &link, "--name", "long"],
        Some(&format!("{ROOMPASS}\n")),
    );
    assert!(ok, "PRODUCT: bob's `vox room join` was refused: {err}");
    let joined = Instant::now();
    // A post made after the join: the forward-only minimum bob must read in any case, and the
    // sign that his log and his key have arrived at all.
    let after_join = posts + 1;
    let (ok, _, err) = vox(
        &alice,
        &["room", "post", &room, &format!("post {after_join}")],
        None,
    );
    assert!(
        ok,
        "PRODUCT: alice's post after bob joined was refused: {err}"
    );

    // ---- bob walks the room until he reads everything, or the bound passes ---------------
    let (mut order, mut pages);
    let mut last_count = usize::MAX;
    loop {
        (order, pages) = read_posts(&bob, &room, page);
        let history = order.iter().filter(|n| **n <= posts).count();
        if history != last_count {
            println!(
                "[proof] +{:?}: bob reads {history} rows of the {posts} pre-join posts \
                 (post {after_join}: {})",
                joined.elapsed(),
                order.contains(&after_join)
            );
            last_count = history;
        }
        if (history >= posts && order.contains(&after_join)) || joined.elapsed() > BOUND {
            break;
        }
        std::thread::sleep(Duration::from_secs(2));
    }
    let took = joined.elapsed();
    let history: Vec<usize> = order.iter().copied().filter(|n| *n <= posts).collect();
    let distinct: BTreeSet<usize> = history.iter().copied().collect();
    println!(
        "[proof] bob, {took:?} after his join: {} rows of pre-join posts, {} distinct, over \
         {pages} pages; post {after_join} read: {}",
        history.len(),
        distinct.len(),
        order.contains(&after_join)
    );
    assert!(
        order.contains(&after_join),
        "CANNOT MEASURE: bob never read alice's post {after_join}, made after his join, within \
         {took:?}: his log or his key never arrived, so what he reads of the history says \
         nothing\nbob's daemon said: {}\nalice's daemon said: {}",
        said(&bob, "bob"),
        said(&alice, "alice")
    );
    assert!(
        distinct.len() == posts,
        "PRODUCT: a member trusted before every post must read all {posts} of them within \
         {BOUND:?} of his join (V210-45), but read {}; missing posts {:?}",
        distinct.len(),
        missing_ranges(&distinct, posts)
    );
    assert!(
        history.len() == posts,
        "PRODUCT: bob's paged read shows {} rows for {posts} posts: a post read more than once \
         (a duplicate row)",
        history.len()
    );
    assert!(
        first_out_of_turn(&history).is_none(),
        "PRODUCT: bob's paged read is out of order: at row {:?} (index, post), where post \
         index+1 belongs",
        first_out_of_turn(&history)
    );
    drop(bob_daemon);
    drop(alice_daemon);
}
