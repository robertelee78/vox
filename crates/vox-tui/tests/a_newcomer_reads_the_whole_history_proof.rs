//! V210-45 (#220), ADR-037 R1 (#958) — **a newcomer to a room with a backlog talks at the fresh
//! room's wait, and reads the history on demand**, driven through the **shipped `vox` binary**.
//!
//! **The claims.** Alice and bob trust each other before either daemon runs, so alice's consent to
//! bob predates every post she makes. A room keeps history forever by default, and consent is
//! forward-only from the moment it is decided (ADR-006), so bob, joining cold after alice has
//! posted, must read every one of her posts — not only the ones since her last key rotation, and
//! not only the newest page of anything. And his join must not cost him the room's present:
//!
//! 1. **One wait, fresh or behind** (ADR-037 R1, #958). From the moment bob's `vox room join`
//!    returns, alice reads bob's first post and bob reads the post alice makes after his join
//!    within [`READY_WITHIN`], whether the room was empty when he joined or carried [`BACKLOG`]
//!    posts he has yet to fetch. [`a_newcomer_talks_both_ways_at_one_wait_fresh_or_behind_a_backlog`]
//!    stages both rooms in one run and asserts the one constant for each. Before ADR-037 a
//!    joiner's first use waited on, or was refused for, the room's convergence ("joined and has
//!    not yet synced"); the fresh room never paid that, so the two waits differed.
//! 2. **The history is read on demand** (R1). A joiner's sparse join holds a live window of the
//!    newest `MAX_PAGE_ENTRIES` (128) rows of an author and leaves the backlog below it where it
//!    is. Bob pages back through the room in its order (`--json --limit --before`, as a person
//!    pages back) and, each time he reaches the oldest row he holds, asks for the page before it
//!    with `vox room read --history older --before <that row>`; each such page arrives within
//!    [`PAGE_WITHIN`], and in the end he reads every `post <i>` **once each and in order**, within
//!    [`BOUND`] of his join. Two sizes: [`BACKLOG`] (160: 32 below the window) **blocks**; 1,500
//!    (across the sender-key rotation at 1,000, ADR-006 `N`) is **optional** for its staging time.
//!
//! **The defect this began with.** Bob's paged read stopped at 500 posts, 1,001–1,500: a sender
//! key rotates every 1,000 messages, and a newcomer was handed only the generation current at its
//! admission, released at its origin. The rotated-out generation that sealed posts 1–1,000 was
//! never released to him, although the author retains its origin precisely so it can be.
//!
//! **What this drives, as an operator would type it:**
//!
//! ```text
//! vox id; vox trust add …          # alice and bob consent to each other, before any daemon
//! vox daemon                       # alice's node
//! vox room create; vox room post   # the backlog, each one a separate `vox room post`
//! vox daemon; vox room join        # bob, cold, from alice's `vox room link`
//! vox room post                    # alice once more, and bob's first word
//! vox room read                    # each reads the other: the wait, from the join's return
//! vox room read --json --limit --before     # bob pages back through what he holds
//! vox room read --history older --before    # and asks for the page below it
//! ```
//!
//! Alice's own paged read must show every post she made once each in order, or it is a `PRODUCT`
//! red: each was accepted. A read that fails is `PRODUCT`, never an empty page; a join the product
//! turns away is `PRODUCT` with its reason.
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
//! **Mutations, one per claim:**
//! - a first-use refusal or wait on the room's convergence put back (a text post refused as
//!   `RoomNotSynced` until the backlog is in, or delivery held until it is): the backlog room's
//!   wait passes [`READY_WITHIN`] while the fresh room's does not — claim 1 red on the backlog
//!   arm's own assertion, and the fresh arm stays green, which is the point;
//! - `--history older` fetching nothing (the demand answered with no page): bob's count stops at
//!   the live window — claim 2 red as `PRODUCT: … older page never arrived`;
//! - the consent release covering no history (`history_plan` returns nothing): the 1,500-post arm
//!   red with bob short of 1,500 once the pages are asked for.

// Two blocking-or-optional arms (decider, 2026-10-01: "Valid proofs block; rest optional"). The
// 160-post history BLOCKS: a newcomer reads every post exactly once and in order, the part below
// the live window on demand. The timing claim (one wait, fresh or behind) and the 1,500-post
// history are optional: CI only compiles them, and without `--features optional-proofs` a stand-in
// says each was not run (`support/optional_proof.rs`).
#![cfg_attr(not(feature = "optional-proofs"), allow(dead_code))]
#![cfg(unix)]

#[path = "support/optional_proof.rs"]
mod optional_proof;
optional_proof::not_run!(
    a_newcomer_trusted_before_every_post_reads_all_of_them,
    a_newcomer_talks_both_ways_at_one_wait_fresh_or_behind_a_backlog,
);

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/attach.rs"]
mod attach;

#[path = "support/typed.rs"]
mod typed;

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
/// **The one wait** (ADR-037 R1): from bob's `vox room join` returning, alice reads his first
/// post and he reads hers, in a fresh room and behind a backlog alike. The bound a member back in
/// its room already meets both ways (`a_member_that_restarts_finds_its_room_proof`, 10 s); a
/// fresh room measured well under it, and the backlog room must meet the same figure.
const READY_WITHIN: Duration = Duration::from_secs(10);
/// How long one page asked for with `--history older` has to arrive.
const PAGE_WITHIN: Duration = Duration::from_secs(60);
/// The backlog: past `MAX_PAGE_ENTRIES` (128), the live window a sparse join holds of one author,
/// so 32 rows sit below the window and are read only on demand.
const BACKLOG: usize = 160;
/// Rows per page when bob pages back, so the blocking arm walks several pages.
const PAGE: usize = 25;

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

fn vox_plain(dir: &Path, args: &[&str], stdin: Option<&str>) -> (bool, String, String) {
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
    // A keyring change's passphrase is typed at a terminal, as a person types it (ADR-028 K-13).
    if typed::is_keyring_change(args) {
        let (ok, shown) = typed::keyring(&cmd);
        return (ok, shown.clone(), shown);
    }
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

/// What one profile holds of a room, walked in the **room's order** as a person pages back:
/// the newest page first (`--json --limit`), then `--before` the oldest row of each page until a
/// page comes back short.
struct Held {
    /// Every `post <i>` number, **oldest first**, in the order the rows came. A duplicate shows as
    /// a number twice, a reordering as a number out of turn.
    order: Vec<usize>,
    /// The entry hash of the oldest row this profile holds, whatever its text: what the page
    /// below it is asked for with (`--history older --before`).
    oldest: Option<String>,
    /// The pages read.
    pages: usize,
}

fn held(dir: &Path, room: &str, page: usize) -> Held {
    let mut pages_newest_first: Vec<Vec<serde_json::Value>> = Vec::new();
    let mut before: Option<String> = None;
    loop {
        let limit = page.to_string();
        let mut args = vec!["room", "read", room, "--json", "--limit", &limit];
        if let Some(b) = before.as_deref() {
            args.extend(["--before", b]);
        }
        let (ok, out, err) = vox(dir, &args, None);
        assert!(
            ok,
            "PRODUCT: `vox room read --json --limit {page}{}` refused: {out}{err}",
            before
                .as_deref()
                .map(|b| format!(" --before {b}"))
                .unwrap_or_default()
        );
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
        if rows.is_empty() {
            break;
        }
        let short = rows.len() < page;
        before = Some(
            rows[0]["entry_hash"]
                .as_str()
                .unwrap_or_else(|| {
                    panic!(
                        "PRODUCT: a `vox room read --json` row carries no entry_hash: {}",
                        rows[0]
                    )
                })
                .to_owned(),
        );
        pages_newest_first.push(rows);
        if short {
            break;
        }
    }
    let pages = pages_newest_first.len();
    let order = pages_newest_first
        .iter()
        .rev()
        .flatten()
        .filter_map(|row| {
            row["text"]
                .as_str()
                .and_then(|t| t.strip_prefix("post "))
                .and_then(|n| n.parse::<usize>().ok())
        })
        .collect();
    Held {
        order,
        oldest: before,
        pages,
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

/// Whether `vox room read` on `dir` shows `text` now. A read that fails is a red, never silence.
fn reads(dir: &Path, room: &str, text: &str) -> bool {
    let (ok, out, err) = vox(dir, &["room", "read", room], None);
    assert!(ok, "PRODUCT: `vox room read` refused: {out}{err}");
    out.contains(text)
}

/// How long after `since` each side first read the other: alice `to_alice`, bob `to_bob`
/// (`None` = not within `limit`).
fn arrivals(
    since: Instant,
    (alice, to_alice): (&Path, &str),
    (bob, to_bob): (&Path, &str),
    room: &str,
    limit: Duration,
) -> (Option<Duration>, Option<Duration>) {
    let (mut a, mut b) = (None, None);
    while (a.is_none() || b.is_none()) && since.elapsed() < limit {
        if a.is_none() && reads(alice, room, to_alice) {
            a = Some(since.elapsed());
        }
        if b.is_none() && reads(bob, room, to_bob) {
            b = Some(since.elapsed());
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    (a, b)
}

/// The blocking arm: a backlog past the live window, read over several pages, the part below the
/// window on demand.
#[test]
#[ignore = "real vox daemons and production Argon2id; CI runs it in release"]
fn a_newcomer_reads_a_short_history_once_each_in_order() {
    watchdog::arm_for_setup(1, 7);
    let tmp = tempfile::tempdir().unwrap_or_else(|e| panic!("APPARATUS: no temp dir: {e}"));
    newcomer_reads_the_whole_history(tmp.path(), BACKLOG, PAGE);
}

/// The optional arm: half again past one sender-key generation (1,000 messages), from one author.
#[cfg(feature = "optional-proofs")]
#[test]
#[ignore = "real vox daemons, 1,500 CLI posts and production Argon2id; optional, run it in release"]
fn a_newcomer_trusted_before_every_post_reads_all_of_them() {
    watchdog::arm_for_setup(1, 7);
    let tmp = tempfile::tempdir().unwrap_or_else(|e| panic!("APPARATUS: no temp dir: {e}"));
    newcomer_reads_the_whole_history(tmp.path(), 1_500, 500);
}

/// **One wait, fresh or behind** (ADR-037 R1, #958): the same two rooms as above, an empty one
/// and one carrying [`BACKLOG`], joined cold in turn; from each join's return, both directions
/// are read within [`READY_WITHIN`]. The constant is one, asserted on each.
#[cfg(feature = "optional-proofs")]
#[test]
#[ignore = "a timing bound a person feels; real vox daemons; optional, run it in release on a real machine"]
fn a_newcomer_talks_both_ways_at_one_wait_fresh_or_behind_a_backlog() {
    watchdog::arm_for_setup(2, 14);
    let tmp = tempfile::tempdir().unwrap_or_else(|e| panic!("APPARATUS: no temp dir: {e}"));
    let mut measured = Vec::new();
    for (name, posts) in [("fresh", 0usize), ("backlog", BACKLOG)] {
        let root = tmp.path().join(name);
        std::fs::create_dir_all(&root)
            .unwrap_or_else(|e| panic!("APPARATUS: could not create {}: {e}", root.display()));
        let (to_alice, to_bob) = newcomer_reads_the_whole_history(&root, posts, PAGE);
        println!(
            "[proof] {name} room ({posts} posts before the join): from the join's return, alice \
             read bob after {to_alice:?}, bob read alice after {to_bob:?} (bound {READY_WITHIN:?})"
        );
        measured.push((name, posts, to_alice, to_bob));
    }
    let late: Vec<String> = measured
        .iter()
        .filter(|(_, _, a, b)| *a > READY_WITHIN || *b > READY_WITHIN)
        .map(|(name, posts, a, b)| {
            format!("the {name} room ({posts} posts): alice read bob after {a:?}, bob read alice after {b:?}")
        })
        .collect();
    assert!(
        late.is_empty(),
        "PRODUCT: from the join's return, a newcomer must be read and must read within \
         {READY_WITHIN:?} whether the room is fresh or carrying a backlog (ADR-037 R1); over the \
         bound: {late:?}; every room: {measured:?}"
    );
}

/// How long the converged room idles while its sync rounds are counted.
const IDLE: Duration = Duration::from_secs(60);

/// **A quiet room costs nothing and says when it last synced** (ADR-038 FX-15, FX-16; #979,
/// #980): alice and bob, each on a daemon of their own, read each other once and then nobody
/// posts. Over [`IDLE`] seconds each profile completes no more sync rounds than the periodic
/// request allows (one per [`SYNC_INTERVAL_SECS`](vox_core::node::syncstream::SYNC_INTERVAL_SECS)
/// plus the follow-up each may raise), and `vox status --json` names a last completed sync for
/// the room and for the member. Measured before the fix: one round per peer per second, the
/// settlement tick re-offering the own head; "last sync never" on every room.
///
/// Mutants: the own-head hint offered to every peer on every tick again (`offer_own_head`
/// ignoring who acknowledged) turns claim 1 red on its own count; the lane's completion no longer
/// recording the sync (`note_lane_sync` removed) turns claim 2 red on `last_sync_ms`.
#[cfg(feature = "optional-proofs")]
#[test]
#[ignore = "an idle minute on two real vox daemons; optional, run it in release"]
fn a_quiet_room_costs_no_rounds_and_says_when_it_last_synced() {
    watchdog::arm_for_setup(1, 6);
    let tmp = tempfile::tempdir().unwrap_or_else(|e| panic!("APPARATUS: no temp dir: {e}"));
    let root = tmp.path();
    let alice = root.join("alice");
    let bob = root.join("bob");
    for d in [&alice, &bob] {
        std::fs::create_dir_all(d.join("cfg"))
            .unwrap_or_else(|e| panic!("APPARATUS: could not create {}: {e}", d.display()));
    }
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
    let _alice_daemon = daemon(&alice, "alice");
    attached(&alice, "alice");
    let (ok, _, err) = vox(
        &alice,
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
    assert!(ok, "PRODUCT: `vox room create` failed: {err}");
    let listed = attached(&alice, "alice");
    let room = listed
        .split_whitespace()
        .find(|w| w.len() >= 8 && w.chars().all(|c| c.is_ascii_alphanumeric()))
        .unwrap_or_else(|| panic!("PRODUCT: `vox room list` shows no room id: {listed}"))
        .to_owned();
    let (ok, link, err) = vox(&alice, &["room", "link", &room], None);
    assert!(ok, "PRODUCT: `vox room link` failed: {err}");
    let link = link.trim().to_owned();
    let _bob_daemon = daemon(&bob, "bob");
    attached(&bob, "bob");
    let (ok, _, err) = vox(
        &bob,
        &["room", "join", "--passphrase-file", "-", &link],
        Some(&format!("{ROOMPASS}\n")),
    );
    assert!(ok, "PRODUCT: bob's `vox room join` was refused: {err}");
    let joined = Instant::now();
    let (ok, out, err) = vox(&alice, &["room", "post", &room, "post 1"], None);
    assert!(ok, "PRODUCT: alice's post was refused: {out}{err}");
    let (ok, out, err) = vox(&bob, &["room", "post", &room, "bob is here"], None);
    assert!(ok, "PRODUCT: bob's first post was refused: {out}{err}");
    let (to_alice, to_bob) = arrivals(
        joined,
        (&alice, "bob is here"),
        (&bob, "post 1"),
        &room,
        BOUND,
    );
    assert!(
        to_alice.is_some() && to_bob.is_some(),
        "PRODUCT: within {BOUND:?} of the join, alice read bob: {to_alice:?}; bob read alice: \
         {to_bob:?} (None = never)\nbob's daemon said: {}\nalice's daemon said: {}",
        said(&bob, "bob"),
        said(&alice, "alice")
    );

    // ---- the room is quiet: acknowledgements settle, then the rounds are counted ----------
    std::thread::sleep(Duration::from_secs(20));
    let before = [synced(&alice), synced(&bob)];
    let counted = Instant::now();
    std::thread::sleep(IDLE);
    let after = [synced(&alice), synced(&bob)];
    let idled = counted.elapsed();
    let allowed = 2 * (idled.as_secs() / vox_core::node::syncstream::SYNC_INTERVAL_SECS + 1);
    let grown: Vec<u64> = (0..2)
        .map(|i| after[i].0.saturating_sub(before[i].0))
        .collect();
    println!(
        "[proof] over {idled:?} of quiet: alice completed {} rounds, bob {} (allowed {allowed}: \
         one periodic every {} s and its follow-up); last sync recorded: alice {}, bob {}",
        grown[0],
        grown[1],
        vox_core::node::syncstream::SYNC_INTERVAL_SECS,
        after[0].1,
        after[1].1
    );
    assert!(
        grown.iter().all(|g| *g <= allowed),
        "PRODUCT: a quiet room ran sync rounds with nothing to sync (ADR-038 FX-15): over \
         {idled:?}, alice completed {} and bob {} (allowed {allowed}, one per periodic request \
         of {} s plus its follow-up)\nalice's status: {}\nbob's status: {}",
        grown[0],
        grown[1],
        vox_core::node::syncstream::SYNC_INTERVAL_SECS,
        after[0].2,
        after[1].2
    );
    assert!(
        after[0].1 && after[1].1,
        "PRODUCT: `vox status` does not say when the room and the member last completed a sync \
         (ADR-038 FX-16): alice {}, bob {}\nalice's status: {}\nbob's status: {}",
        after[0].1,
        after[1].1,
        after[0].2,
        after[1].2
    );
}

/// `vox status --json` of one profile: completed sync rounds summed over its ports, whether the
/// room and every other member carry a last completed sync, and the raw status for a red.
fn synced(dir: &Path) -> (u64, bool, String) {
    let (ok, out, err) = vox(dir, &["status", "--json"], None);
    assert!(ok, "PRODUCT: `vox status --json` failed: {err}");
    let v: serde_json::Value = serde_json::from_str(&out)
        .unwrap_or_else(|e| panic!("PRODUCT: `vox status --json` is not JSON: {e}: {out}"));
    let completed = v["sync"]
        .as_array()
        .map(|ports| {
            ports
                .iter()
                .map(|p| p["completed"].as_u64().unwrap_or(0))
                .sum()
        })
        .unwrap_or(0);
    let recorded = v["rooms"].as_array().is_some_and(|rooms| {
        !rooms.is_empty()
            && rooms.iter().all(|r| {
                !r["last_sync_ms"].is_null()
                    && r["members"].as_array().is_some_and(|members| {
                        members
                            .iter()
                            .filter(|m| m["me"] != serde_json::Value::Bool(true))
                            .all(|m| !m["last_sync_ms"].is_null())
                    })
            })
    });
    (completed, recorded, out)
}

/// Alice posts `posts` times under `root`; bob, trusted before any of them and joining cold, is
/// read by her and reads her from the join's return (returned: how long each took, each within
/// [`BOUND`] or a red), and then reads every post exactly once and in order, `page` rows at a
/// time, asking for each page below what he holds.
fn newcomer_reads_the_whole_history(
    root: &Path,
    posts: usize,
    page: usize,
) -> (Duration, Duration) {
    let alice = root.join("alice");
    let bob = root.join("bob");
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
        &["room", "create", "--passphrase-file", "-", "--name", "long"],
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
    let mine = held(&alice, &room, page);
    println!(
        "[proof] alice posted {posts} in {:?}; her own paged read shows {} rows over {} pages",
        started.elapsed(),
        mine.order.len(),
        mine.pages
    );
    // Every post was accepted above, so an author who cannot read them back once each, in
    // order, is the product's paged read failing, not a staging fault.
    assert!(
        first_out_of_turn(&mine.order).is_none() && mine.order.len() == posts,
        "PRODUCT: the author's own paged read of her {posts} accepted posts is not each once in \
         order: {} rows; first out of turn (index, post): {:?}",
        mine.order.len(),
        first_out_of_turn(&mine.order)
    );

    // ---- bob joins cold -------------------------------------------------------------------
    let (ok, link, err) = vox(&alice, &["room", "link", &room], None);
    assert!(ok, "PRODUCT: `vox room link` failed: {err}");
    let link = link.trim().to_owned();
    let bob_daemon = daemon(&bob, "bob");
    attached(&bob, "bob");
    let (ok, _, err) = vox(
        &bob,
        &["room", "join", "--passphrase-file", "-", &link],
        Some(&format!("{ROOMPASS}\n")),
    );
    assert!(ok, "PRODUCT: bob's `vox room join` was refused: {err}");
    let joined = Instant::now();

    // ---- the wait: from the join's return, each reads the other's first word -------------
    // Alice's post after the join is the forward-only minimum bob must read in any case, and the
    // sign that his log and his key did arrive at all. Bob's first post is his first use of the
    // room: a joiner is never refused for a backlog it has yet to fetch (ADR-037 R1).
    let after_join = format!("post {}", posts + 1);
    let (ok, out, err) = vox(&alice, &["room", "post", &room, &after_join], None);
    assert!(
        ok,
        "PRODUCT: alice's post after bob joined was refused: {out}{err}"
    );
    let bobs_first = "bob is here";
    let (ok, out, err) = vox(&bob, &["room", "post", &room, bobs_first], None);
    assert!(
        ok,
        "PRODUCT: bob's first post, {:?} after his join returned into a room of {posts} posts, \
         was refused: {out}{err}",
        joined.elapsed()
    );
    let (to_alice, to_bob) = arrivals(
        joined,
        (&alice, bobs_first),
        (&bob, &after_join),
        &room,
        BOUND,
    );
    println!(
        "[proof] {posts} posts before the join: from the join's return, alice read bob's first \
         post after {to_alice:?}, bob read alice's post {} after {to_bob:?}",
        posts + 1
    );
    let (Some(to_alice), Some(to_bob)) = (to_alice, to_bob) else {
        panic!(
            "PRODUCT: within {BOUND:?} of bob's join returning, alice read bob's first post: \
             {to_alice:?}; bob read alice's post made after his join: {to_bob:?} (None = never): \
             his log or his key never arrived, or his word never left\nbob's daemon said: {}\n\
             alice's daemon said: {}",
            said(&bob, "bob"),
            said(&alice, "alice")
        );
    };

    // ---- bob pages back, asking for each page below what he holds, until he has it all ----
    let mut demands = 0usize;
    let mut last_count = usize::MAX;
    let mut have;
    loop {
        have = held(&bob, &room, page);
        let history = have.order.iter().filter(|n| **n <= posts).count();
        if history != last_count {
            println!(
                "[proof] +{:?}: bob holds {history} of the {posts} pre-join posts over {} pages, \
                 after {demands} page(s) asked for",
                joined.elapsed(),
                have.pages
            );
            last_count = history;
        }
        if history >= posts || joined.elapsed() > BOUND {
            break;
        }
        let Some(oldest) = have.oldest.clone() else {
            // He holds no row yet: his log is still arriving.
            std::thread::sleep(Duration::from_millis(500));
            continue;
        };
        // The page below the oldest row he holds, on demand (R1).
        let (ok, out, err) = vox(
            &bob,
            &[
                "room",
                "read",
                &room,
                "--history",
                "older",
                "--before",
                &oldest,
            ],
            None,
        );
        assert!(
            ok,
            "PRODUCT: bob's `vox room read --history older --before {oldest}` was refused: {out}{err}"
        );
        demands += 1;
        println!(
            "[proof] bob asked for the page before {}…: {}",
            &oldest[..12],
            err.trim()
        );
        let asked = Instant::now();
        loop {
            std::thread::sleep(Duration::from_millis(500));
            let now = held(&bob, &room, page)
                .order
                .iter()
                .filter(|n| **n <= posts)
                .count();
            if now > history {
                break;
            }
            if asked.elapsed() > PAGE_WITHIN {
                let (_, status, status_err) =
                    vox(&bob, &["room", "read", &room, "--history", "status"], None);
                panic!(
                    "PRODUCT: the page below the oldest row bob holds, asked for with `vox room \
                     read --history older --before {oldest}`, never arrived within {PAGE_WITHIN:?}: \
                     he still holds {history} of {posts} pre-join posts; `--history status` says: \
                     {status}{status_err}\nbob's daemon said: {}\nalice's daemon said: {}",
                    said(&bob, "bob"),
                    said(&alice, "alice")
                );
            }
        }
    }
    let took = joined.elapsed();
    let history: Vec<usize> = have.order.iter().copied().filter(|n| *n <= posts).collect();
    let distinct: BTreeSet<usize> = history.iter().copied().collect();
    println!(
        "[proof] bob, {took:?} after his join: {} rows of pre-join posts, {} distinct, over {} \
         pages, {demands} page(s) asked for with --history older",
        history.len(),
        distinct.len(),
        have.pages
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
        "PRODUCT: bob's paged read is out of the room's order: at row {:?} (index, post), where \
         post index+1 belongs",
        first_out_of_turn(&history)
    );
    drop(bob_daemon);
    drop(alice_daemon);
    (to_alice, to_bob)
}
