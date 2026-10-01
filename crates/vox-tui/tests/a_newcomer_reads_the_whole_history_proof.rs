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
//! **Asserted:** bob's paged read shows all 1,500 distinct `post <i>` texts, each once, within
//! 300 s of his join. Precondition, or `CANNOT MEASURE`: bob renders alice's post made *after*
//! his join (so his log and his key did arrive). Alice's own paged read must show her 1,500
//! posts, each once; a post she was told was accepted and cannot read, or reads twice, is a
//! `PRODUCT:` red, never a precondition (V210-106).
//!
//! **Every red names its side.** `PRODUCT:` quotes what a `vox` command did, including a staging
//! command that failed (`PRODUCT (staging):`); `APPARATUS:` is this harness failing to run a
//! process; `CANNOT MEASURE:` is a precondition this proof needs and did not get.
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
//! this goes red with bob short of 1,500.

#![cfg(unix)]

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
/// Half again past one sender-key generation (1,000 messages), from one author.
const POSTS: usize = 1_500;
/// How long bob has, from his join, to read the whole history.
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
    let mut child = cmd
        .spawn()
        .unwrap_or_else(|e| panic!("APPARATUS: could not spawn {VOX} {args:?}: {e}"));
    if let Some(text) = stdin {
        child
            .stdin
            .as_mut()
            .expect("APPARATUS: the child's stdin was piped")
            .write_all(text.as_bytes())
            .unwrap_or_else(|e| panic!("APPARATUS: could not write vox {args:?}'s stdin: {e}"));
        drop(child.stdin.take());
    }
    let out = child
        .wait_with_output()
        .unwrap_or_else(|e| panic!("APPARATUS: could not wait for vox {args:?}: {e}"));
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// Start `vox daemon` with the identity passphrase piped in, its output to files by the profile.
fn daemon(dir: &Path, tag: &str) -> Daemon {
    let file = |what: &str| {
        let p = dir.join(format!("daemon-{tag}.{what}"));
        std::fs::File::create(&p)
            .unwrap_or_else(|e| panic!("APPARATUS: could not create {}: {e}", p.display()))
    };
    let (out, err) = (file("out"), file("err"));
    let mut child = Command::new(VOX)
        .args(["daemon", "--listen", "127.0.0.1:0"])
        .env("VOX_DATA_DIR", dir)
        .env("VOX_CONFIG_DIR", dir.join("cfg"))
        .env_remove("VOX_ROOM")
        .stdin(Stdio::piped())
        .stdout(Stdio::from(out))
        .stderr(Stdio::from(err))
        .spawn()
        .unwrap_or_else(|e| panic!("APPARATUS: could not spawn {VOX} daemon: {e}"));
    // Write, then close: the daemon reads stdin to EOF before it binds its socket.
    let mut pipe = child
        .stdin
        .take()
        .expect("APPARATUS: the daemon's stdin was piped");
    pipe.write_all(format!("{IDENTITY}\n").as_bytes())
        .unwrap_or_else(|e| panic!("APPARATUS: could not write {tag}'s daemon stdin: {e}"));
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
        assert!(ok, "PRODUCT: `vox room read --json` refused: {err}");
        pages += 1;
        let page: Vec<serde_json::Value> = out
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| {
                serde_json::from_str(l).unwrap_or_else(|e| {
                    panic!("PRODUCT: `vox room read --json` printed a bad row ({e}): {l}")
                })
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
                        .unwrap_or_else(|| {
                            panic!(
                                "PRODUCT: a `vox room read --json` row has no entry_hash: {last}"
                            )
                        })
                        .to_owned(),
                );
            }
            _ => return (seen, rows_with_post, pages),
        }
    }
}

/// The post numbers in `1..=POSTS` that `seen` lacks, as a few ranges for a failure message.
fn missing_ranges(seen: &BTreeSet<usize>) -> Vec<(usize, usize)> {
    let mut out: Vec<(usize, usize)> = Vec::new();
    for n in (1..=POSTS).filter(|n| !seen.contains(n)) {
        match out.last_mut() {
            Some((_, hi)) if *hi + 1 == n => *hi = n,
            _ => out.push((n, n)),
        }
    }
    out
}

#[test]
#[ignore = "real vox daemons, 1,500 CLI posts and production Argon2id; CI runs it in release"]
fn a_newcomer_trusted_before_every_post_reads_all_of_them() {
    // One join; 7 unlocks: two `vox id`s, two `trust add`s, two daemons and the room.
    watchdog::arm_for_setup(1, 7);
    let tmp = tempfile::tempdir()
        .unwrap_or_else(|e| panic!("APPARATUS: could not make a temporary directory: {e}"));
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
        assert!(ok, "PRODUCT (staging): `vox id` failed: {err}");
        fps.push(out.trim().to_owned());
    }
    for (dir, fp, name) in [(&alice, &fps[1], "bob"), (&bob, &fps[0], "alice")] {
        let (ok, _, err) = vox(dir, &["trust", "add", fp, "--name", name], None);
        assert!(
            ok,
            "PRODUCT (staging): `vox trust add {name}` failed: {err}"
        );
    }

    // ---- alice: a room, and 1,500 posts from one author ----------------------------------
    let alice_daemon = daemon(&alice, "alice");
    attached(&alice, "alice");
    let (ok, _, err) = vox(
        &alice,
        &["room", "create", "--name", "long"],
        Some(&format!("{ROOMPASS}\n")),
    );
    assert!(ok, "PRODUCT (staging): `vox room create` failed: {err}");
    let listed = attached(&alice, "alice");
    let room = listed
        .split_whitespace()
        .find(|w| w.len() >= 8 && w.chars().all(|c| c.is_ascii_alphanumeric()))
        .unwrap_or_else(|| panic!("PRODUCT (staging): `vox room list` names no room id: {listed}"))
        .to_owned();

    let started = Instant::now();
    for i in 1..=POSTS {
        let (ok, _, err) = vox(&alice, &["room", "post", &room, &format!("post {i}")], None);
        assert!(
            ok,
            "PRODUCT (staging): alice's `vox room post` {i} of {POSTS} was refused: {err}"
        );
    }
    let (mine, mine_rows, pages) = read_posts(&alice, &room);
    println!(
        "[proof] alice posted {POSTS} in {:?}; her own paged read shows {} distinct posts in \
         {mine_rows} rows over {pages} pages",
        started.elapsed(),
        mine.len()
    );
    // Every post above exited 0, so what alice reads back is the product's answer, not staging.
    assert!(
        mine_rows == mine.len(),
        "PRODUCT: the author's own paged `vox room read --json` shows {} rows for {} distinct posts: \
         {} post(s) shown more than once",
        mine_rows,
        mine.len(),
        mine_rows - mine.len()
    );
    assert!(
        mine.len() == POSTS,
        "PRODUCT: the author's own paged `vox room read --json` shows {} of the {POSTS} posts it \
         accepted; missing {:?}",
        mine.len(),
        missing_ranges(&mine)
    );

    // ---- bob joins cold -------------------------------------------------------------------
    let (ok, link, err) = vox(&alice, &["room", "invite", &room], None);
    assert!(ok, "PRODUCT (staging): `vox room invite` failed: {err}");
    let link = link.trim().to_owned();
    let bob_daemon = daemon(&bob, "bob");
    attached(&bob, "bob");
    let (ok, _, err) = vox(
        &bob,
        &["room", "join", &link, "--name", "long"],
        Some(&format!("{ROOMPASS}\n")),
    );
    assert!(ok, "PRODUCT (staging): `vox room join` failed: {err}");
    let joined = Instant::now();
    // A post made after the join: the forward-only minimum bob must read in any case, and the
    // sign that his log and his key have arrived at all.
    let after_join = POSTS + 1;
    let (ok, _, err) = vox(
        &alice,
        &["room", "post", &room, &format!("post {after_join}")],
        None,
    );
    assert!(
        ok,
        "PRODUCT (staging): alice's post after bob joined was refused: {err}"
    );

    // ---- bob walks the room until he reads everything, or the bound passes ---------------
    let (mut seen, mut rows, mut pages);
    let mut last_count = usize::MAX;
    loop {
        (seen, rows, pages) = read_posts(&bob, &room);
        let history = seen.iter().filter(|n| **n <= POSTS).count();
        if history != last_count {
            println!(
                "[proof] +{:?}: bob reads {history} of the {POSTS} pre-join posts \
                 (post {after_join}: {})",
                joined.elapsed(),
                seen.contains(&after_join)
            );
            last_count = history;
        }
        if (history == POSTS && seen.contains(&after_join)) || joined.elapsed() > BOUND {
            break;
        }
        std::thread::sleep(Duration::from_secs(2));
    }
    let took = joined.elapsed();
    let history: BTreeSet<usize> = seen.iter().copied().filter(|n| *n <= POSTS).collect();
    let history_rows = rows - usize::from(seen.contains(&after_join));
    println!(
        "[proof] bob, {took:?} after his join: {} distinct pre-join posts in {history_rows} rows \
         over {pages} pages (first {:?}, last {:?}); post {after_join} read: {}",
        history.len(),
        history.first(),
        history.last(),
        seen.contains(&after_join)
    );
    assert!(
        seen.contains(&after_join),
        "CANNOT MEASURE: bob never read alice's post {after_join}, made after his join, within \
         {took:?} — his log or his key never arrived, so what he reads of the history says \
         nothing\nbob's daemon said: {}\nalice's daemon said: {}",
        std::fs::read_to_string(bob.join("daemon-bob.err")).unwrap_or_default(),
        std::fs::read_to_string(alice.join("daemon-alice.err")).unwrap_or_default()
    );
    assert!(
        history_rows == history.len(),
        "PRODUCT: bob's paged `vox room read --json` shows {history_rows} rows for {} distinct \
         pre-join posts: {} post(s) shown more than once",
        history.len(),
        history_rows - history.len()
    );
    assert!(
        history.len() == POSTS,
        "PRODUCT: a member trusted before every post must read all {POSTS} of them within \
         {BOUND:?} of his join (V210-45); bob reads {}, missing {:?}",
        history.len(),
        missing_ranges(&history)
    );
    drop(bob_daemon);
    drop(alice_daemon);
}
