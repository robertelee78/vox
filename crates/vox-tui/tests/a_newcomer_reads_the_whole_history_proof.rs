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
//! **Every participant is the shipped binary.** Nothing in this process runs a node or speaks a
//! wire protocol; each step is a `vox` process with its own `VOX_DATA_DIR`/`VOX_CONFIG_DIR`,
//! killed by its PID when dropped. The quiet-room proof reads each `store.redb` only at the two
//! edges of its measured window, as the user's direct no-write artifact verdict.
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
    a_quiet_room_costs_no_rounds_and_says_when_it_last_synced,
    hosted_nodes_read_each_other_and_the_flow_state_pool_holds_no_port,
);

#[path = "support/test_knobs.rs"]
mod test_knobs;
#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/attach.rs"]
mod attach;

#[path = "support/typed.rs"]
mod typed;

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
#[cfg(feature = "optional-proofs")]
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime};

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

impl Daemon {
    fn stop_in_place(&mut self) {
        let _ = Command::new("kill")
            .args(["-TERM", &self.0.id().to_string()])
            .status();
        let t0 = Instant::now();
        while t0.elapsed() < Duration::from_secs(15) {
            if let Ok(Some(_)) = self.0.try_wait() {
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// Stop it as a person does (SIGTERM, ADR-012: a clean stop), waiting for it to exit.
    fn stop(mut self) {
        self.stop_in_place();
        // Drop kills what did not stop.
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
    daemon_env(dir, tag, &[])
}

/// The same, with environment the daemon reads at its start (a test-only knob, for instance).
fn daemon_env(dir: &Path, tag: &str, env: &[(&str, &str)]) -> Daemon {
    daemon_with(dir, tag, &[], env)
}

/// The same, with more arguments (`--no-node`, say) after the listen address.
fn daemon_with(dir: &Path, tag: &str, args: &[&str], env: &[(&str, &str)]) -> Daemon {
    let file = |kind: &str| {
        let at = dir.join(format!("daemon-{tag}.{kind}"));
        std::fs::File::create(&at)
            .unwrap_or_else(|e| panic!("APPARATUS: could not create {}: {e}", at.display()))
    };
    let mut cmd = Command::new(VOX);
    cmd.args(["daemon", "--listen", "127.0.0.1:0"])
        .args(args)
        .env("VOX_DATA_DIR", dir)
        .env("VOX_CONFIG_DIR", dir.join("cfg"))
        .env_remove("VOX_ROOM");
    for (k, v) in env {
        cmd.env(k, v);
    }
    let mut child = cmd
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
    attached_as(dir, tag, None)
}

/// The same, as `node` (one of several a daemon hosts).
fn attached_as(dir: &Path, tag: &str, node: Option<&str>) -> String {
    loop {
        let (ok, out, err) = vox(dir, &as_node(&["room", "list"], node), None);
        if ok {
            return out;
        }
        eprintln!("[apparatus] waiting for {tag}'s daemon to answer: {err}");
        std::thread::sleep(Duration::from_millis(200));
    }
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
    /// Every row paged, whatever its text, as a person is shown them: the `post <i>` rows,
    /// alice's live rows, and the placeholder for a body not received yet.
    rows: usize,
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
    let rows = pages_newest_first.iter().map(Vec::len).sum();
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
        rows,
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

/// How long the converged rooms idle while their sync rounds, the hosting daemon's CPU time and
/// traffic, and its answers are measured.
const IDLE: Duration = Duration::from_secs(60);
/// The nodes one daemon hosts in the quiet rooms, as the decider's work Mac hosts a person's node
/// and the agents' beside it on one `vox daemon --no-node`, each made Ready with `vox node unlock`.
const HOSTED: [&str; 4] = ["robert", "claude", "codex", "opencode"];
/// One live round per hosted node plus every daemon archive job exceeds the pool floor by one.
/// This derives the required population from the product's two source-owned capacities.
const FX35_HOSTED_COUNT: usize = vox_core::node::history_budget::FLOW_STATE_MIN_CAPACITY
    - vox_core::node::history_budget::ARCHIVE_JOBS
    + 1;
const FX35_HOSTED: [&str; FX35_HOSTED_COUNT] = [
    "robert", "claude", "codex", "opencode", "kimi", "glm", "fable", "one", "two", "three", "four",
    "five", "six", "seven", "eight",
];
const FX35_WAKE_HOSTED: [&str; 2] = ["wake-one", "wake-two"];
const FX35_GENERATION_PANIC: &str = "fx35-generation-panic";
/// The rooms every node is in; the first hosted node makes them.
const QUIET_ROOMS: [&str; 2] = ["quiet-1", "quiet-2"];
/// CPU time a daemon in quiet rooms may spend over [`IDLE`]: Activity Monitor's number, the
/// issue's bound for the daemon hosting [`HOSTED`] (#986). Measured 2026-10-20 on the decider's
/// work Mac on v0.4.6: 150–168% of a core, 90–100 s a minute.
const IDLE_CPU: Duration = Duration::from_secs(6);
/// How often `vox status --json` is asked of every hosted node during the idle minute; each
/// answer is held to [`ANSWER_WITHIN`]. Measured on v0.4.6: 0.26–0.82 s.
const ASK_EVERY: Duration = Duration::from_secs(5);
/// How long a post is retried while the room says a previous change is still being applied:
/// two periodic sync intervals, the staging's patience, not a claim.
/// Bytes, in and out together, one sync round with nothing to fetch may cost the hosting daemon:
/// the traffic bound is its lanes times the rounds each is allowed times this. A round between
/// two nodes of one daemon crosses loopback and counts on both sides. 64 KiB is far above what
/// an empty frontier round carries (a `HAVE` and a `WANT` of a few authors, under 1 KiB each
/// way) and below what one re-fetched window costs; measured 2026-10-20 on main (v0.4.9 code,
/// this staging), the host's daemon moved 13.2 MB in and 13.2 MB out in the idle minute, about
/// 200 KiB per allowed round: the idle re-pull of a sparse author's hint (ADR-038 FX-29).
const ROUND_BYTES: u64 = 64 * 1024;
const INVENTORY_REARM_WITHIN: Duration =
    Duration::from_secs(2 * vox_core::node::syncstream::SYNC_INTERVAL_SECS);
/// A fifth node hosted by the same daemon. It is trusted before anyone posts, but joins only
/// after every holder has pruned those post bodies, leaving a real sparse history window.
const SPARSE: &str = "late";
/// Written to each holder's own retention file before the sparse member joins.
const HOLD_FOR: &str = "default 1\n";

/// Four nodes on one daemon and one on another, in two quiet rooms, as these proofs stage
/// them: the roots, every node (its root, its `--node`, its name, its fingerprint; the hosted
/// four first), the rooms, the two daemons (killed when dropped), when the posts were made and
/// the longest a post waited for a room applying its last change.
struct Staged {
    // The daemons first: they are killed before their directories go.
    host_daemon: Daemon,
    peer_daemon: Daemon,
    host: std::path::PathBuf,
    peer: std::path::PathBuf,
    everyone: Vec<(
        std::path::PathBuf,
        Option<&'static str>,
        &'static str,
        String,
    )>,
    rooms: Vec<String>,
    links: Vec<String>,
    late: Option<(
        std::path::PathBuf,
        Option<&'static str>,
        &'static str,
        String,
    )>,
    posted: Instant,
    waited: Duration,
    hosted: usize,
    live_hold: Option<std::path::PathBuf>,
    archive_hold: Option<std::path::PathBuf>,
    _tmp: Option<tempfile::TempDir>,
}

/// A setup post uses the bounded-sync round's own product contract as apparatus patience. A
/// different refusal is the product's exact output; an unchanged busy room is a failed staging
/// precondition, never left to the global watchdog.
fn stage_post(dir: &Path, node: Option<&str>, name: &str, room: &str, text: &str) -> Duration {
    let asked = Instant::now();
    loop {
        let (ok, out, err) = bounded_stage_post(dir, node, room, text, false, asked);
        if ok {
            return asked.elapsed();
        }
        let busy = err.contains("still being applied") || out.contains("still being applied");
        assert!(
            busy,
            "APPARATUS: {name}'s staging post in {room} was refused before the measured moment: \
             {out}{err}"
        );
        assert!(
            asked.elapsed() < vox_core::node::history_budget::BOUNDED_ROUND_PATIENCE,
            "APPARATUS NO RESULT: {name}'s staging post in {room} remained busy until the \
             operator deadman: {out}{err}"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
}

fn stage_large_post(
    dir: &Path,
    node: Option<&str>,
    name: &str,
    room: &str,
    text: &str,
) -> Duration {
    let asked = Instant::now();
    loop {
        let (ok, out, err) = bounded_stage_post(dir, node, room, text, true, asked);
        if ok {
            return asked.elapsed();
        }
        let busy = err.contains("still being applied") || out.contains("still being applied");
        assert!(
            busy,
            "APPARATUS: {name}'s large staging post in {room} was refused before the measured \
             moment: {out}{err}"
        );
        assert!(
            asked.elapsed() < vox_core::node::history_budget::BOUNDED_ROUND_PATIENCE,
            "APPARATUS NO RESULT: {name}'s large staging post in {room} remained busy until \
             the operator deadman: {out}{err}"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// Run one setup post under the bounded-round contract even if the client itself wedges. The
/// command is still the shipped binary; this only gives the apparatus its own named watchdog.
fn bounded_stage_post(
    dir: &Path,
    node: Option<&str>,
    room: &str,
    text: &str,
    stdin: bool,
    asked: Instant,
) -> (bool, String, String) {
    let deadman = asked + vox_core::node::history_budget::BOUNDED_ROUND_PATIENCE;
    let remaining = deadman.saturating_duration_since(Instant::now());
    assert!(
        !remaining.is_zero(),
        "APPARATUS NO RESULT: staging post in {room} exhausted the operator deadman before \
         its shipped client could start"
    );
    let dir = dir.to_owned();
    let node = node.map(str::to_owned);
    let room = room.to_owned();
    let text = text.to_owned();
    let room_for_error = room.clone();
    let (result_tx, result_rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut args = vec![
            "room".to_owned(),
            "post".to_owned(),
            room,
            if stdin { "-".to_owned() } else { text.clone() },
        ];
        if let Some(node) = node {
            args.extend(["--node".to_owned(), node]);
        }
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        let result = vox(&dir, &refs, stdin.then_some(text.as_str()));
        let _ = result_tx.send(result);
    });
    result_rx.recv_timeout(remaining).unwrap_or_else(|error| {
        panic!(
            "APPARATUS NO RESULT: shipped staging post in {room_for_error} did not return \
             before the operator deadman: {error}"
        )
    })
}

/// Create ordinary shipped archive demand on two hosted nodes. The peer posts beyond the live
/// window before either joins; each node then asks for the page below its oldest held row with
/// `vox room read --history older`. Returning means both shipped requests were accepted and the
/// daemon reported both archive jobs admitted together.
fn stage_two_archive_jobs(staged: &Staged) -> String {
    let (peer_dir, peer_node, peer_name, _) = &staged.everyone[staged.hosted];
    let (ok, _, err) = vox(
        peer_dir,
        &as_node(
            &[
                "room",
                "create",
                "--passphrase-file",
                "-",
                "--name",
                "pool-archive",
            ],
            *peer_node,
        ),
        Some(&format!("{ROOMPASS}\n")),
    );
    assert!(
        ok,
        "APPARATUS: archive-pressure room creation failed: {err}"
    );
    let listed = attached_as(peer_dir, "peer", *peer_node);
    let room = listed
        .lines()
        .find(|line| line.contains("pool-archive"))
        .and_then(|line| line.split_whitespace().next())
        .unwrap_or_else(|| panic!("APPARATUS: archive-pressure room is not listed: {listed}"))
        .to_owned();

    // More rows than the live window leaves a real older page. Source-owned sizes make this
    // pressure evolve with the product rather than copying today's 128/16 values.
    let archive_rows =
        vox_core::log::history::MAX_PAGE_ENTRIES + vox_core::node::history_budget::ARCHIVE_JOBS;
    let payload_bytes =
        vox_core::log::history::MAX_PAYLOAD_BYTES - vox_core::log::history::MAX_HEADER_BYTES;
    for index in 0..archive_rows {
        let mut body = format!("archive-pressure-{index} ");
        if index < vox_core::node::history_budget::ARCHIVE_JOBS {
            body.push_str(&"a".repeat(payload_bytes.saturating_sub(body.len())));
            stage_large_post(peer_dir, *peer_node, peer_name, &room, &body);
        } else {
            stage_post(peer_dir, *peer_node, peer_name, &room, &body);
        }
    }
    let (ok, link, err) = vox(
        peer_dir,
        &as_node(&["room", "link", &room], *peer_node),
        None,
    );
    assert!(ok, "APPARATUS: archive-pressure link failed: {err}");
    let link = link
        .lines()
        .find(|line| line.starts_with("vox://"))
        .unwrap_or(link.trim())
        .to_owned();
    for (dir, node, name, _) in &staged.everyone[..vox_core::node::history_budget::ARCHIVE_JOBS] {
        let (ok, out, err) = vox(
            dir,
            &as_node(&["room", "join", "--passphrase-file", "-", &link], *node),
            Some(&format!("{ROOMPASS}\n")),
        );
        assert!(
            ok,
            "APPARATUS: {name}'s archive-pressure join was refused: {out}{err}"
        );
    }

    let page = vox_core::log::history::MAX_PAGE_ENTRIES.to_string();
    for (dir, node, name, _) in &staged.everyone[..vox_core::node::history_budget::ARCHIVE_JOBS] {
        let ready_deadman = Instant::now() + vox_core::node::history_budget::BOUNDED_ROUND_PATIENCE;
        let oldest = loop {
            let (ok, out, err) = vox(
                dir,
                &as_node(&["room", "read", &room, "--json", "--limit", &page], *node),
                None,
            );
            assert!(
                ok,
                "APPARATUS: {name}'s archive-pressure staging read refused: {out}{err}"
            );
            let rows = out
                .lines()
                .filter(|line| !line.trim().is_empty())
                .map(serde_json::from_str::<serde_json::Value>)
                .collect::<Result<Vec<_>, _>>()
                .unwrap_or_else(|error| {
                    panic!(
                        "APPARATUS: {name}'s archive-pressure staging read was not JSON: \
                         {error}: {out}"
                    )
                });
            if rows.len() == vox_core::log::history::MAX_PAGE_ENTRIES {
                break rows[0]["entry_hash"]
                    .as_str()
                    .unwrap_or_else(|| {
                        panic!("APPARATUS: {name}'s oldest archive-pressure row has no entry_hash")
                    })
                    .to_owned();
            }
            assert!(
                Instant::now() < ready_deadman,
                "APPARATUS NO RESULT: {name} did not hold the source-sized live window needed \
                 to stage an older-history request before the operator deadman; held {} rows",
                rows.len()
            );
            std::thread::sleep(Duration::from_millis(200));
        };
        let (ok, out, err) = vox(
            dir,
            &as_node(
                &[
                    "room",
                    "read",
                    &room,
                    "--history",
                    "older",
                    "--before",
                    &oldest,
                ],
                *node,
            ),
            None,
        );
        assert!(
            ok,
            "APPARATUS: {name}'s shipped older-history request was refused: {out}{err}"
        );
    }

    let admitted_deadman = Instant::now() + vox_core::node::history_budget::BOUNDED_ROUND_PATIENCE;
    let expected: BTreeSet<&str> = staged.everyone[..vox_core::node::history_budget::ARCHIVE_JOBS]
        .iter()
        .map(|(_, _, _, fingerprint)| fingerprint.as_str())
        .collect();
    loop {
        let shown = synced(&staged.host, Some(FX35_HOSTED[0]));
        let value: serde_json::Value = serde_json::from_str(&shown.status).unwrap_or_default();
        let archives: BTreeSet<&str> = value["lanes"]["budget"]["archive_nodes"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(serde_json::Value::as_str)
            .collect();
        if archives == expected {
            return room;
        }
        assert!(
            Instant::now() < admitted_deadman,
            "APPARATUS NO RESULT: the two shipped older-history requests did not occupy both \
             source-owned archive jobs together before the operator deadman (expected \
             {expected:?}, saw {archives:?}): {}",
            shown.status
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Stage [`HOSTED`] on one `vox daemon --no-node` (each made Ready with `vox node unlock`) and
/// bob on a daemon of his own; trust in every direction before anyone posts; [`QUIET_ROOMS`]
/// made by the first hosted node and joined by every other node; one post each in each room.
fn stage_hosted_nodes(
    hosted: &'static [&'static str],
    hold_live_jobs: bool,
    single_foreground_job: bool,
    disable_tick_schedule: bool,
    late: Option<&'static str>,
) -> Staged {
    let tmp = tempfile::tempdir().unwrap_or_else(|e| panic!("APPARATUS: no temp dir: {e}"));
    let root = tmp.path();
    let host = root.join("host");
    let peer = root.join("peer");
    for d in [&host, &peer] {
        std::fs::create_dir_all(d.join("cfg"))
            .unwrap_or_else(|e| panic!("APPARATUS: could not create {}: {e}", d.display()));
    }
    // Every node: its data root, its `--node` (none for the peer root's one node), its name and
    // its fingerprint.
    let mut everyone: Vec<(
        std::path::PathBuf,
        Option<&'static str>,
        &'static str,
        String,
    )> = Vec::new();
    for name in hosted {
        let (ok, out, err) = vox(&host, &["id", "--node", name], None);
        assert!(
            ok,
            "APPARATUS: `vox id --node {name}` failed while staging: {err}"
        );
        everyone.push((host.clone(), Some(name), name, out.trim().to_owned()));
    }
    let (ok, out, err) = vox(&peer, &["id"], None);
    assert!(ok, "APPARATUS: `vox id` failed while staging: {err}");
    everyone.push((peer.clone(), None, "bob", out.trim().to_owned()));
    let late = late.map(|name| {
        let (ok, out, err) = vox(&host, &["id", "--node", name], None);
        assert!(
            ok,
            "APPARATUS: `vox id --node {name}` failed while staging: {err}"
        );
        (host.clone(), Some(name), name, out.trim().to_owned())
    });

    // One daemon for the host's nodes, as the decider's Mac runs it: `vox daemon --no-node`, each
    // node made Ready in it with `vox node unlock`. The passphrases it remembers go to the proof's
    // own Keychain file, never the login Keychain.
    let keychain = attach::keychain(&host).to_string_lossy().into_owned();
    let live_hold = hold_live_jobs.then(|| root.join("hold-live-job"));
    let archive_hold = hold_live_jobs.then(|| root.join("hold-archive-job"));
    let live_hold_text = live_hold
        .as_ref()
        .map(|path| path.to_string_lossy().into_owned());
    let archive_hold_text = archive_hold
        .as_ref()
        .map(|path| path.to_string_lossy().into_owned());
    let mut env: Vec<(&str, &str)> = vec![("VOX_TEST_KEYCHAIN", keychain.as_str())];
    if disable_tick_schedule {
        env.push(("VOX_TEST_DISABLE_TICK_SCHEDULE", "1"));
    }
    if let Some(path) = live_hold_text.as_deref() {
        env.push(("VOX_TEST_HOLD_LIVE_JOB_FILE", path));
    }
    if let Some(path) = archive_hold_text.as_deref() {
        env.push(("VOX_TEST_HOLD_ARCHIVE_JOB_FILE", path));
    }
    if single_foreground_job {
        env.push(("VOX_TEST_FOREGROUND_JOBS", "1"));
    }
    if hold_live_jobs {
        env.push(("VOX_TEST_PANIC_ON_TEXT", FX35_GENERATION_PANIC));
    }
    let host_daemon = daemon_with(&host, "host", &["--no-node"], &env);
    while !attach::Root::at(&host, IDENTITY).daemon_running() {
        std::thread::sleep(Duration::from_millis(200));
    }
    for name in hosted {
        unlock(&host, name);
        attached_as(&host, "host", Some(name));
    }
    if let Some((_, Some(name), _, _)) = &late {
        unlock(&host, name);
        attached_as(&host, "host", Some(name));
    }
    let peer_daemon = if disable_tick_schedule {
        daemon_env(&peer, "peer", &[("VOX_TEST_DISABLE_TICK_SCHEDULE", "1")])
    } else {
        daemon(&peer, "peer")
    };
    attached_as(&peer, "peer", None);

    // Trust in every direction before anyone posts.
    let mut trusting = everyone.clone();
    trusting.extend(late.iter().cloned());
    for (dir, node, name, _) in &trusting {
        for (_, _, other, fp) in &trusting {
            if other == name {
                continue;
            }
            let (ok, _, err) = vox(
                dir,
                &as_node(&["trust", "add", fp.as_str(), "--name", other], *node),
                None,
            );
            assert!(
                ok,
                "APPARATUS: staging trust from {name} to {other} failed: {err}"
            );
        }
    }
    // The rooms: the first hosted node makes each, and every other node joins by its link.
    let maker = Some(hosted[0]);
    let mut rooms = Vec::with_capacity(QUIET_ROOMS.len());
    let mut links = Vec::with_capacity(QUIET_ROOMS.len());
    for name in QUIET_ROOMS {
        let (ok, _, err) = vox(
            &host,
            &as_node(
                &["room", "create", "--passphrase-file", "-", "--name", name],
                maker,
            ),
            Some(&format!("{ROOMPASS}\n")),
        );
        assert!(ok, "APPARATUS: staging room {name} failed: {err}");
        let listed = attached_as(&host, "host", maker);
        let room = listed
            .lines()
            .find(|l| l.contains(name))
            .and_then(|l| l.split_whitespace().next())
            .unwrap_or_else(|| panic!("APPARATUS: staged room {name} is not listed: {listed}"))
            .to_owned();
        let (ok, link, err) = vox(&host, &as_node(&["room", "link", &room], maker), None);
        assert!(ok, "APPARATUS: staging room link failed: {err}");
        let link = link
            .lines()
            .find(|l| l.starts_with("vox://"))
            .unwrap_or(link.trim())
            .to_owned();
        for (dir, node, who, _) in &everyone {
            if *node == maker {
                continue;
            }
            let (ok, _, err) = vox(
                dir,
                &as_node(&["room", "join", "--passphrase-file", "-", &link], *node),
                Some(&format!("{ROOMPASS}\n")),
            );
            assert!(
                ok,
                "APPARATUS: {who}'s staging join of {name} was refused: {err}"
            );
        }
        rooms.push(room);
        links.push(link);
    }
    // One post each in each room; `converged` later judges delivery by exact terminal cycles. A post the
    // room turns away because its last change is still being applied ("this request made no
    // change") is retried for up to [`POST_WAIT`], as the person told so does; the longest such
    // wait is reported.
    let posted = Instant::now();
    let mut waited = Duration::ZERO;
    for room in &rooms {
        for (dir, node, name, _) in &everyone {
            let text = format!("{name} is here");
            waited = waited.max(stage_post(dir, *node, name, room, &text));
        }
    }
    Staged {
        host_daemon,
        peer_daemon,
        host,
        peer,
        everyone,
        rooms,
        links,
        late,
        posted,
        waited,
        hosted: hosted.len(),
        live_hold,
        archive_hold,
        _tmp: Some(tmp),
    }
}

/// Every member reads every other's post. Two terminal cycles on the exact reader/author lane
/// without the earlier post are a structural wedge: the first cycle may have overlapped the post,
/// but the next began after that cycle ended. No elapsed clock decides the verdict. While waiting,
/// the product's own pool account must also remain exact (ADR-038 FX-35).
fn converged(staged: &Staged) {
    let Staged {
        everyone, rooms, ..
    } = staged;
    let cycle0: Vec<Synced> = everyone
        .iter()
        .map(|(dir, node, _, _)| synced(dir, *node))
        .collect();
    let mut unread: Vec<String> = Vec::new();
    loop {
        unread.clear();
        for room in rooms {
            for (reader_index, (dir, node, reader, _)) in everyone.iter().enumerate() {
                let (ok, out, err) = vox(dir, &as_node(&["room", "read", room], *node), None);
                assert!(
                    ok,
                    "PRODUCT: {reader}'s `vox room read` refused: {out}{err}"
                );
                let mut missing = Vec::new();
                for (_, _, author, fingerprint) in everyone {
                    if author != reader && !out.contains(&format!("{author} is here")) {
                        unread.push(format!("{reader} has not read {author} in {room}"));
                        missing.push((*author, fingerprint));
                    }
                }
                if !missing.is_empty() {
                    let now = synced(dir, *node);
                    for (author, fingerprint) in missing {
                        let before = lane_rounds(&cycle0[reader_index], room, fingerprint)
                            .unwrap_or_default();
                        let grown = lane_rounds(&now, room, fingerprint)
                            .map(|lane| lane.since(before))
                            .unwrap_or_default();
                        assert!(
                            grown.rounds() < 2,
                            "PRODUCT: {reader}'s exact lane for {author} completed two terminal \
                             cycles after the post but still did not show `{author} is here` in \
                             {room}; this is a structural sync wedge, not an elapsed-time verdict: \
                             {grown:?}; {}",
                            now.status
                        );
                    }
                }
            }
        }
        if unread.is_empty() {
            break;
        }
        // FX-35's park mutant must fail a structural product assertion: in the same shipped
        // status document, this node's charge count is exactly its running ports and the daemon
        // total is exactly the by-node sum.
        for (dir, node, name, fingerprint) in everyone {
            let shown = synced(dir, *node);
            let value: serde_json::Value =
                serde_json::from_str(&shown.status).unwrap_or_else(|error| {
                    panic!(
                        "PRODUCT: {name}'s flow-state status was not JSON during convergence: \
                         {error}: {}",
                        shown.status
                    )
                });
            let pool = &value["lanes"]["budget"]["flow_state"];
            // The controller's actual worker slots are independent of the budget pool's charge
            // ledger. Comparing those catches `Flow::park` retaining a charge; port
            // `round_running` cannot, because it is deliberately projected from that ledger.
            let running = value["lanes"]["bounded"]["running"]
                .as_array()
                .into_iter()
                .flatten()
                .filter(|slot| !slot.is_null())
                .count() as u64;
            let charged = pool["by_node"][fingerprint].as_u64().unwrap_or(u64::MAX);
            let by_node = pool["by_node"]
                .as_object()
                .map(|counts| counts.values().filter_map(serde_json::Value::as_u64).sum())
                .unwrap_or(u64::MAX);
            assert!(
                charged <= running,
                "PRODUCT: {name}'s flow-state pool charged a parked/non-running flow during \
                 convergence (charged {charged}, controller worker slots {running}): {}",
                shown.status
            );
            assert_eq!(
                pool["in_use"].as_u64(),
                Some(by_node),
                "PRODUCT: {name}'s flow-state pool total was not the exact by-node sum during \
                 convergence: {}",
                shown.status
            );
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}

/// A pool charge can disappear before the actor consumes a finished worker, so equality is not
/// required. The reverse is impossible: more charges than this controller's actual worker slots
/// means a parked flow retained one. At the structural quiet edge, no Control job may remain
/// without a worker owner. The clock is only an operator deadman and cannot decide either claim.
#[cfg(feature = "optional-proofs")]
fn parked_flow_charge_discriminator(staged: &Staged) {
    let quiet_deadman = Instant::now() + vox_core::node::history_budget::BOUNDED_ROUND_PATIENCE;
    loop {
        let mut active = Vec::new();
        let mut retained_control = Vec::new();
        for (dir, node, name, fingerprint) in &staged.everyone {
            let shown = synced(dir, *node);
            let value: serde_json::Value =
                serde_json::from_str(&shown.status).unwrap_or_else(|e| {
                    panic!(
                        "PRODUCT: {name}'s flow-state status was not JSON: {e}: {}",
                        shown.status
                    )
                });
            let charged = value["lanes"]["budget"]["flow_state"]["by_node"][fingerprint]
                .as_u64()
                .unwrap_or(u64::MAX);
            let running = value["lanes"]["bounded"]["running"]
                .as_array()
                .into_iter()
                .flatten()
                .filter(|slot| !slot.is_null())
                .count() as u64;
            assert!(
                charged <= running,
                "PRODUCT: {name}'s flow-state pool retained a parked charge with no controller \
                 worker owner (charged {charged}, controller slots {running}): {}",
                shown.status
            );
            if running != 0 {
                active.push(format!("{name}: {running}"));
            }
            let control = value["lanes"]["budget"]["control"]
                .as_u64()
                .unwrap_or(u64::MAX);
            if control != 0 {
                retained_control.push(format!("{name}: {control}"));
            }
        }
        if active.is_empty() {
            assert!(
                retained_control.is_empty(),
                "PRODUCT: bounded controllers had no running worker at the structural quiet \
                 edge, but parked flows still retained admitted Control jobs: \
                 {retained_control:?}"
            );
            return;
        }
        assert!(
            Instant::now() < quiet_deadman,
            "APPARATUS NO RESULT: actual bounded workers did not reach the structural quiet \
             precondition before the operator deadman: {active:?}"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// The gates a start attempt can end at, in the order the daemon tests them (ADR-038 FX-35).
const START_REASONS: [&str; 9] = [
    "room_busy",
    "retained_flow_limit",
    "archive_budget_busy",
    "identity_busy",
    "control_budget_busy",
    "live_lane_busy",
    "no_outbound_slot",
    "flow_state_node_busy",
    "flow_state_pool_full",
];

/// What `vox status --json` must say of every port's last start attempt (ADR-038 FX-35), judged
/// on one status document of `name`: `start_outcome` is `never_attempted`, `started` or
/// `not_started`; `start_reason` is present if and only if the outcome is `not_started`, and
/// names one of [`START_REASONS`]; `start_age_ms` is present if and only if an attempt has
/// ended; `round_running` is a boolean; and the outcome has moved with the port: a port with a
/// round running on its attempt out ended that attempt `started`. Each breach, in words.
fn start_words(name: &str, v: &serde_json::Value) -> Vec<String> {
    let mut broken = Vec::new();
    for port in v["lanes"]["ports"].as_array().into_iter().flatten() {
        let id = format!(
            "{}/{}",
            port["room"]
                .as_str()
                .and_then(|s| s.get(..8))
                .unwrap_or("?"),
            port["peer"]
                .as_str()
                .and_then(|s| s.get(..8))
                .unwrap_or("?")
        );
        let outcome = port["start_outcome"].as_str();
        let reason = port["start_reason"].as_str();
        let aged = port["start_age_ms"].as_u64().is_some();
        let said = format!(
            "start_outcome {} start_reason {} start_age_ms {}",
            port["start_outcome"], port["start_reason"], port["start_age_ms"]
        );
        let sound = match outcome {
            Some("never_attempted") => reason.is_none() && !aged,
            Some("started") => reason.is_none() && aged,
            Some("not_started") => reason.is_some_and(|r| START_REASONS.contains(&r)) && aged,
            _ => false,
        };
        if !sound {
            broken.push(format!("{name}: port {id}: {said}"));
        }
        let running = port["round_running"].as_bool();
        if running.is_none() {
            broken.push(format!(
                "{name}: port {id}: round_running {}",
                port["round_running"]
            ));
        }
        // A round running on this port's attempt out (a port made anew while an earlier
        // port's round still runs has no attempt out, and no outcome yet).
        if running == Some(true) && port["out_age_ms"].is_u64() && outcome != Some("started") {
            broken.push(format!("{name}: port {id}: a round runs, yet {said}"));
        }
    }
    broken
}

#[cfg(feature = "optional-proofs")]
struct TailObserver {
    child: Child,
    reader: Option<std::thread::JoinHandle<()>>,
    lines: std::sync::mpsc::Receiver<(Instant, Result<String, String>)>,
}

#[cfg(feature = "optional-proofs")]
impl TailObserver {
    fn attach(dir: &Path, node: Option<&str>, room: &str, since: Option<&str>) -> Self {
        let mut command = Command::new(VOX);
        let mut args = vec!["room", "tail", room];
        if let Some(since) = since {
            args.extend(["--since", since]);
        }
        command
            .args(as_node(&args, node))
            .env("VOX_DATA_DIR", dir)
            .env("VOX_CONFIG_DIR", dir.join("cfg"))
            .env("VOX_IDENTITY_PASSPHRASE", IDENTITY)
            .env_remove("VOX_ROOM")
            .env_remove("VOX_SESSION")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        let mut child = command
            .spawn()
            .unwrap_or_else(|error| panic!("APPARATUS: could not start room tail: {error}"));
        let stdout = child
            .stdout
            .take()
            .expect("APPARATUS: room tail has no stdout");
        let (send, lines) = std::sync::mpsc::channel();
        let reader = std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                match line {
                    Ok(line) => {
                        if send.send((Instant::now(), Ok(line))).is_err() {
                            return;
                        }
                    }
                    Err(error) => {
                        let _ = send.send((Instant::now(), Err(error.to_string())));
                        return;
                    }
                }
            }
        });
        Self {
            child,
            reader: Some(reader),
            lines,
        }
    }

    fn wait_for(&self, target: &str, who: &str, product: bool) {
        self.wait_for_after(target, who, product, None);
    }

    fn wait_for_after(&self, target: &str, who: &str, product: bool, after: Option<Instant>) {
        let deadman = Instant::now() + vox_core::node::history_budget::BOUNDED_ROUND_PATIENCE;
        loop {
            let left = deadman.saturating_duration_since(Instant::now());
            match self.lines.recv_timeout(left) {
                Ok((seen, Ok(line)))
                    if line.contains(target) && after.is_none_or(|after| seen >= after) =>
                {
                    return;
                }
                Ok((seen, Ok(line))) if line.contains(target) => panic!(
                    "APPARATUS: {who}'s causal target {target:?} was already visible at \
                     {seen:?}, before the observed admission's release edge"
                ),
                Ok((_, Ok(_))) => {}
                Ok((_, Err(error))) if product => {
                    panic!("PRODUCT: {who}'s shipped room tail failed: {error}")
                }
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) if product => panic!(
                    "PRODUCT: {who}'s already-running shipped room tail ended before showing \
                     {target:?} from the exact release edge"
                ),
                Ok((_, Err(error))) => {
                    panic!("APPARATUS: {who}'s staging room tail failed: {error}")
                }
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                    panic!("APPARATUS: {who}'s staging room tail ended before showing {target:?}")
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => panic!(
                    "APPARATUS NO RESULT: {who}'s room tail did not show {target:?} before the \
                     operator deadman"
                ),
            }
        }
    }
}

#[cfg(feature = "optional-proofs")]
impl Drop for TailObserver {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}

#[cfg(feature = "optional-proofs")]
fn charged_flow_hold_entries(hold: &Path) -> Vec<(u64, String, std::path::PathBuf)> {
    let Some(parent) = hold.parent() else {
        return Vec::new();
    };
    let Some(file) = hold.file_name().and_then(|name| name.to_str()) else {
        return Vec::new();
    };
    let prefix = format!("{file}.entered.");
    std::fs::read_dir(parent)
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let name = entry.file_name();
            let actor = name
                .to_str()?
                .strip_prefix(&prefix)?
                .split('.')
                .next()?
                .parse()
                .ok()?;
            let node = std::fs::read_to_string(entry.path()).ok()?;
            Some((actor, node.trim().to_owned(), entry.path()))
        })
        .collect()
}

#[cfg(feature = "optional-proofs")]
fn generation_accounting_keeps_actor_incarnations_exact(staged: &Staged) {
    let hold = staged
        .live_hold
        .as_ref()
        .expect("APPARATUS: generation-accounting hold path was not staged");
    // Earlier pool-pressure workers used the same compiled-out lane barrier. Only a marker
    // created after this point can prove that the generation we retire owns the Flow mutex as
    // well as a running charge.
    for (_, _, marker) in charged_flow_hold_entries(hold) {
        std::fs::remove_file(&marker).unwrap_or_else(|error| {
            panic!(
                "APPARATUS: could not clear prior charged-flow marker {}: {error}",
                marker.display()
            )
        });
    }
    std::fs::File::create(hold)
        .unwrap_or_else(|error| panic!("APPARATUS: could not create {}: {error}", hold.display()));
    let room = &staged.rooms[0];
    let target = "generation-accounting-target";
    let (peer_dir, peer_node, peer_name, _) = &staged.everyone[staged.hosted];
    stage_post(peer_dir, *peer_node, peer_name, room, target);

    let entered_deadman = Instant::now() + vox_core::node::history_budget::BOUNDED_ROUND_PATIENCE;
    let (old_actor, running_name, running_fingerprint) = loop {
        let entered = charged_flow_hold_entries(hold);
        let held = entered.into_iter().find_map(|(actor, fingerprint, _)| {
            // Keep the first two nodes free to create two independent successor needs after
            // this actor is replaced. The population itself is source-derived above.
            staged.everyone[vox_core::node::history_budget::ARCHIVE_JOBS..staged.hosted]
                .iter()
                .find(|(_, _, _, candidate)| *candidate == fingerprint)
                .map(|(_, _, name, _)| (actor, *name, fingerprint))
        });
        if let Some(held) = held {
            break held;
        }
        assert!(
            Instant::now() < entered_deadman,
            "APPARATUS NO RESULT: no eligible shipped worker reached the charged-Flow barrier \
             before the operator deadman"
        );
        std::thread::sleep(Duration::from_millis(20));
    };

    let (ok, out, err) = vox(
        &staged.host,
        &as_node(
            &["room", "post", room, FX35_GENERATION_PANIC],
            Some(running_name),
        ),
        None,
    );
    assert!(
        !ok,
        "APPARATUS: the proof-only marker did not panic held actor {running_name}: {out}{err}"
    );
    let retiring_deadman = Instant::now() + vox_core::node::history_budget::BOUNDED_ROUND_PATIENCE;
    loop {
        let shown = synced(&staged.host, Some(FX35_HOSTED[0]));
        let value: serde_json::Value = serde_json::from_str(&shown.status)
            .expect("PRODUCT: post-panic generation status was not JSON");
        let old_retiring = value["lanes"]["budget"]["flow_state"]["actors"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|actor| {
                actor["node"] == running_fingerprint
                    && actor["actor"] == old_actor
                    && actor["registered"] == false
                    && actor["in_use"] == 1
            });
        if old_retiring {
            break;
        }
        assert!(
            Instant::now() < retiring_deadman,
            "APPARATUS NO RESULT: shipped status did not expose actor {old_actor}'s retiring \
             generation before the operator deadman; last status: {}",
            shown.status
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    unlock(&staged.host, running_name);
    attached_as(&staged.host, "host", Some(running_name));
    // Two independent authors now give the replacement more than the one remaining shared
    // slot. Its first worker reaches the charged-flow barrier; the second exact port must say
    // NodeBusy. Replacing the actor may neither create two more slots nor misname this PoolFull.
    let successors = [
        (
            staged.rooms[0].as_str(),
            staged.everyone[0].3.as_str(),
            "generation-accounting-successor-one",
        ),
        (
            staged.rooms[1].as_str(),
            staged.everyone[1].3.as_str(),
            "generation-accounting-successor-two",
        ),
    ];
    let tail_ready: Vec<(String, String)> = successors
        .iter()
        .map(|(room, _, _)| {
            let (ok, out, err) = vox(
                &staged.host,
                &as_node(&["room", "read", room, "--json"], Some(running_name)),
                None,
            );
            assert!(
                ok,
                "APPARATUS: could not choose a causal tail cursor in {room}: {out}{err}"
            );
            let rows: Vec<serde_json::Value> = out
                .lines()
                .filter(|line| !line.trim().is_empty())
                .map(|line| {
                    serde_json::from_str(line).unwrap_or_else(|error| {
                        panic!("APPARATUS: tail cursor row is not JSON ({error}): {line}")
                    })
                })
                .collect();
            assert!(
                rows.len() >= 2,
                "APPARATUS: {room} has fewer than two rows for a causal tail cursor: {out}"
            );
            (
                rows[0]["entry_hash"]
                    .as_str()
                    .expect("APPARATUS: tail cursor row omitted entry_hash")
                    .to_owned(),
                rows[1]["text"]
                    .as_str()
                    .expect("APPARATUS: tail readiness row omitted text")
                    .to_owned(),
            )
        })
        .collect();
    let successor_tails = [
        TailObserver::attach(
            &staged.host,
            Some(running_name),
            successors[0].0,
            Some(&tail_ready[0].0),
        ),
        TailObserver::attach(
            &staged.host,
            Some(running_name),
            successors[1].0,
            Some(&tail_ready[1].0),
        ),
    ];
    // Establish both shipped tails before either successor exists. This is apparatus readiness,
    // and happens before the admission under verdict; after release, no command may schedule it.
    for (index, tail) in successor_tails.iter().enumerate() {
        tail.wait_for(&tail_ready[index].1, running_name, false);
        let (dir, node, name, _) = &staged.everyone[index];
        stage_post(dir, *node, name, successors[index].0, successors[index].2);
    }

    let replacement_deadman =
        Instant::now() + vox_core::node::history_budget::BOUNDED_ROUND_PATIENCE;
    let refused = loop {
        let replacement = synced(&staged.host, Some(running_name));
        let replacement: serde_json::Value = serde_json::from_str(&replacement.status)
            .expect("PRODUCT: generation-accounting status was not JSON");
        let pool = &replacement["lanes"]["budget"]["flow_state"];
        let generations: Vec<&serde_json::Value> = pool["actors"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|actor| actor["node"] == running_fingerprint)
            .collect();
        let old = generations.iter().find(|actor| {
            actor["actor"] == old_actor && actor["registered"] == false && actor["in_use"] == 1
        });
        let new = generations
            .iter()
            .find(|actor| actor["registered"] == true && actor["in_use"] == 1);
        let new_actor = new.and_then(|actor| actor["actor"].as_u64());
        let retiring = pool["retiring_nodes"]
            .as_array()
            .is_some_and(|nodes| nodes.iter().any(|node| node == &running_fingerprint));
        let running_old = pool["running"].as_array().is_some_and(|rounds| {
            rounds
                .iter()
                .any(|round| round["node"] == running_fingerprint && round["actor"] == old_actor)
        });
        let running_new = pool["running"].as_array().is_some_and(|rounds| {
            rounds.iter().any(|round| {
                round["node"] == running_fingerprint
                    && new_actor.is_some_and(|actor| round["actor"] == actor)
            })
        });
        // Bind the refusal to one expected successor port and the retained controller flow and
        // pool admission that name its exact room, peer, root and lane. A refusal on some other
        // port cannot satisfy this claim.
        let bounded = &replacement["lanes"]["bounded"];
        let bound_refusals: Vec<(usize, String, String, u64)> = successors
            .iter()
            .enumerate()
            .filter_map(|(index, (room, peer, _))| {
                let port = replacement["lanes"]["ports"]
                    .as_array()?
                    .iter()
                    .find(|port| {
                        port["room"] == *room
                            && port["peer"] == *peer
                            && port["start_reason"] == "flow_state_node_busy"
                    })?;
                let _ = port;
                let admission = bounded["admissions"].as_array()?.iter().find(|admission| {
                    admission["gate"] == "node_slots"
                        && admission["room"] == *room
                        && admission["peer"] == *peer
                })?;
                let root = admission["root"].as_str()?.to_owned();
                let lane = admission["lane"].as_str()?.to_owned();
                let token = admission["admission"].as_u64()?;
                bounded["ready"].as_array()?.iter().find(|flow| {
                    flow["room"] == *room
                        && flow["peer"] == *peer
                        && flow["root"].as_str() == Some(root.as_str())
                        && flow["lane"].as_str() == Some(lane.as_str())
                })?;
                Some((index, root, lane, token))
            })
            .collect();
        let exact_refusal = (bound_refusals.len() == 1).then(|| bound_refusals[0].clone());
        let pool_full = replacement["lanes"]["ports"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|port| port["start_reason"] == "flow_state_pool_full");
        let by_node = pool["by_node"]
            .as_object()
            .expect("PRODUCT: generation-accounting status omitted by_node");
        let expected_limit = vox_core::node::history_budget::FLOW_STATE_MIN_CAPACITY
            .max(vox_core::node::history_budget::BOUNDED_SYNC_RUNNING_SLOTS * staged.hosted)
            as u64;
        let actor_sum: u64 = pool["actors"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|actor| actor["in_use"].as_u64())
            .sum();
        let running_count = pool["running"].as_array().map_or(0, Vec::len) as u64;
        if let Some(exact_refusal) =
            exact_refusal.filter(|_| old.is_some() && new.is_some() && running_old && running_new)
        {
            assert!(
                generations.len() == 2
                    && retiring
                    && !pool_full
                    && by_node.len() == staged.hosted
                    && by_node
                        .get(&running_fingerprint)
                        .and_then(serde_json::Value::as_u64)
                        == Some(1)
                    && pool["in_use"].as_u64() == Some(actor_sum)
                    && running_count == actor_sum
                    && pool["in_use"]
                        .as_u64()
                        .zip(pool["limit"].as_u64())
                        .is_some_and(|(in_use, limit)| in_use < limit)
                    && pool["limit"] == expected_limit,
                "PRODUCT: `vox status --json` did not aggregate the retired and replacement \
                 actor into the same two node slots, or named the refusal PoolFull: {}",
                pool
            );
            break exact_refusal;
        }
        assert!(
            !pool_full,
            "PRODUCT: a replacement actor reached PoolFull while its retired generation shared \
             the same node's source-owned slots: {}",
            replacement["lanes"]
        );
        assert!(
            Instant::now() < replacement_deadman,
            "APPARATUS NO RESULT: status did not expose the replacement, retired generation, \
             and exact room/peer/root/lane NodeBusy refusal before the operator deadman: {}",
            replacement["lanes"]
        );
        std::thread::sleep(Duration::from_millis(20));
    };

    let release_started = Instant::now();
    std::fs::remove_file(hold)
        .unwrap_or_else(|error| panic!("APPARATUS: could not release {}: {error}", hold.display()));
    let (refused_index, refused_root, refused_lane, refused_admission) = refused;
    successor_tails[refused_index].wait_for_after(
        successors[refused_index].2,
        running_name,
        true,
        Some(release_started),
    );
    println!(
        "[proof] NodeBusy admission {refused_admission} retained {}/{} ({refused_root}, \
         {refused_lane}) and its already-attached tail received {:?} from the charge-release wake",
        successors[refused_index].0, successors[refused_index].1, successors[refused_index].2
    );

    // The causal refused-flow verdict is complete before these ordinary reads. They retain the
    // broader generation-control claim, but cannot revive or substitute for the refused flow.
    let released_deadman = Instant::now() + vox_core::node::history_budget::BOUNDED_ROUND_PATIENCE;
    for (room, text) in [
        (&staged.rooms[0], target),
        (&staged.rooms[0], "generation-accounting-successor-one"),
        (&staged.rooms[1], "generation-accounting-successor-two"),
    ] {
        loop {
            let (ok, out, err) = vox(
                &staged.host,
                &as_node(&["room", "read", room], Some(running_name)),
                None,
            );
            assert!(
                ok,
                "PRODUCT: generation-accounting read refused: {out}{err}"
            );
            if out.contains(text) {
                break;
            }
            assert!(
                Instant::now() < released_deadman,
                "APPARATUS NO RESULT: generation-accounting control did not expose {text:?} \
                 before the operator deadman"
            );
            std::thread::sleep(Duration::from_millis(200));
        }
    }
}

/// **More than eight hosted nodes read each other, and the flow-state pool holds no port**
/// (ADR-038 FX-35; #986): [`FX35_HOSTED`] on one daemon and bob on another, two rooms, trust in every
/// direction, one post each. Every member MUST eventually read every other; causal and structural
/// observations decide the product verdict, while operator deadmen can only return NO RESULT.
/// Then `vox status --json` on every node
/// MUST show `lanes.budget.flow_state` with
/// `by_node` holding one member per node its daemon hosts, the asked node's member equal to its
/// ports with `round_running` and `in_use` the sum; and every port's last start in the contract's
/// words ([`start_words`]). Its limit is exactly the shared source constants'
/// `max(floor, running slots × hosted nodes)`, not a copied count, so it is never full.
///
/// Measured before the fix (main, 2026-10-20, four runs of five): the four hosted nodes' parked
/// hinted flows held all sixteen flow states, the inventory round that would have let them
/// resume could never start, and the four nodes read nobody's post in 300 s while the peer read
/// everyone; or a post was refused for 60 s while the room applied its last change.
///
/// Mutants, one per claim: `Flow::park` keeping its charge turns convergence PRODUCT red;
/// `scratchpad/mutant_fx35_undersized.py` obstructs the seventeenth reservation while still
/// reporting the right limit, turning the unused-capacity PoolFull PRODUCT assertion red;
/// `scratchpad/mutant_fx35_required.py` disposes the exact required root at an admission
/// refusal, turning the retained-required-root PRODUCT assertion red at the PoolFull snapshot;
/// `scratchpad/mutant_fx35_release_wake.py` drops both exact release wakes and leaves the shipped
/// tail short of its target with periodic scheduling disabled and no post-release request; silence
/// alone is NO RESULT, never a PRODUCT red. Dropping archive ownership instead turns the exact
/// shipped archive request's structural ownership assertion red;
/// `scratchpad/mutant_fx35_node_release.py` drops the charged worker's pool, lane and completion
/// release notifications, so the exact room/peer/root/lane NodeBusy admission remains visible
/// but its already-attached tail cannot supply positive causal evidence; a connected silent tail
/// reaches only the operator's APPARATUS NO RESULT deadman;
/// giving a replacement generation two new node slots instead of sharing the retired actor's
/// source-owned pair may directly return PoolFull, which names that separate PRODUCT defect;
/// absence of the expected NodeBusy observation is NO RESULT. Removing the post-quiet need re-arm
/// leaves the positive observation incomplete and therefore also reaches only NO RESULT.
#[cfg(feature = "optional-proofs")]
#[test]
#[ignore = "two real vox daemons, one hosting more than eight nodes; optional, run it in release"]
fn hosted_nodes_read_each_other_and_the_flow_state_pool_holds_no_port() {
    test_knobs::require(&[
        "VOX_TEST_FOREGROUND_JOBS",
        "VOX_TEST_HOLD_LIVE_JOB_FILE",
        "VOX_TEST_HOLD_ARCHIVE_JOB_FILE",
        "VOX_TEST_DISABLE_TICK_SCHEDULE",
        "VOX_TEST_PANIC_ON_TEXT",
    ]);
    watchdog::arm_for_setup(
        u32::try_from(
            QUIET_ROOMS.len() * (FX35_HOSTED.len() + FX35_WAKE_HOSTED.len())
                + vox_core::node::history_budget::ARCHIVE_JOBS,
        )
        .expect("APPARATUS: join count does not fit the watchdog"),
        u32::try_from(FX35_HOSTED.len() + FX35_WAKE_HOSTED.len() + 2)
            .expect("APPARATUS: unlock count does not fit the watchdog"),
    );
    let staged = stage_hosted_nodes(&FX35_HOSTED, true, false, true, None);
    converged(&staged);
    parked_flow_charge_discriminator(&staged);
    let converged_after = staged.posted.elapsed();
    // Attach before pressure. After a PoolFull snapshot no command is sent until this already
    // running shipped observer sees the exact room's target, so a tick or a status/read request
    // cannot stand in for the release/completion wake.
    let pressure_room = &staged.rooms[0];
    let pressure_tails: BTreeMap<&str, TailObserver> = staged.everyone[..staged.hosted]
        .iter()
        .map(|(dir, node, name, _)| (*name, TailObserver::attach(dir, *node, pressure_room, None)))
        .collect();
    let ready = "pool-release-tails-attached";
    let (pressure_dir, pressure_node, pressure_name, pressure_fingerprint) =
        &staged.everyone[staged.hosted];
    stage_post(
        pressure_dir,
        *pressure_node,
        pressure_name,
        pressure_room,
        ready,
    );
    for (_, _, name, _) in &staged.everyone[..staged.hosted] {
        pressure_tails
            .get(name)
            .expect("APPARATUS: pressure tail disappeared")
            .wait_for(ready, name, false);
    }
    // Two real shipped archive requests are already running. The separate proof-only archive
    // barrier is installed before either request is made, so observing both admissions proves
    // they cannot finish before live pressure reaches the seventeenth reservation. A near-maximum
    // post by the peer in the shared room then makes one live round eligible on every hosted node.
    // The barriers hold already-admitted jobs without changing product capacity: fifteen live plus
    // the daemon's two source-owned archive jobs is the first legal population above the floor.
    let archive_hold = staged
        .archive_hold
        .as_ref()
        .expect("APPARATUS: archive-pressure hold path was not staged");
    std::fs::File::create(archive_hold).unwrap_or_else(|error| {
        panic!(
            "APPARATUS: could not create {}: {error}",
            archive_hold.display()
        )
    });
    let archive_room = stage_two_archive_jobs(&staged);
    let hold = staged
        .live_hold
        .as_ref()
        .expect("APPARATUS: flow-state pressure hold path was not staged");
    std::fs::File::create(hold)
        .unwrap_or_else(|error| panic!("APPARATUS: could not create {}: {error}", hold.display()));
    let pressure_body = "x".repeat(
        vox_core::log::history::MAX_PAYLOAD_BYTES - vox_core::log::history::MAX_HEADER_BYTES,
    );
    stage_large_post(
        pressure_dir,
        *pressure_node,
        pressure_name,
        pressure_room,
        &pressure_body,
    );
    let pressure_target = "pool-pressure-landed";
    stage_post(
        pressure_dir,
        *pressure_node,
        pressure_name,
        pressure_room,
        pressure_target,
    );
    let mut pool_full_seen = false;
    let mut required_pool_full_seen = false;
    let mut live_pool_full: Option<(&str, Instant)> = None;
    let mut most_pressure = 0;
    let mut pressure_staged = false;
    let pressure_snapshot_deadman =
        Instant::now() + vox_core::node::history_budget::BOUNDED_ROUND_PATIENCE;
    let observed = 'pressure: loop {
        for (dir, node, name, _) in &staged.everyone[..staged.hosted] {
            let shown = synced(dir, *node);
            let v: serde_json::Value = serde_json::from_str(&shown.status).unwrap_or_default();
            let pool = &v["lanes"]["budget"]["flow_state"];
            let in_use = pool["in_use"].as_u64().unwrap_or(0);
            let archives = v["lanes"]["budget"]["archive_nodes"]
                .as_array()
                .map_or(0, Vec::len);
            let full_ports: BTreeSet<(String, String)> = v["lanes"]["ports"]
                .as_array()
                .into_iter()
                .flatten()
                .filter(|port| port["start_reason"] == "flow_state_pool_full")
                .filter_map(|port| {
                    Some((
                        port["room"].as_str()?.to_owned(),
                        port["peer"].as_str()?.to_owned(),
                    ))
                })
                .collect();
            if !full_ports.is_empty() {
                assert_eq!(
                    pool["in_use"], pool["limit"],
                    "PRODUCT: {name} refused a legal flow-state reservation as PoolFull while \
                     shipped status reported unused capacity: {}",
                    shown.status
                );
                pool_full_seen = true;
            }
            if !pressure_staged {
                assert_eq!(
                    archives,
                    vox_core::node::history_budget::ARCHIVE_JOBS,
                    "APPARATUS: both source-owned archive jobs were not still admitted when \
                     flow-state pressure was staged (archive room {archive_room}): {}",
                    shown.status
                );
                pressure_staged = in_use
                    > vox_core::node::history_budget::FLOW_STATE_MIN_CAPACITY as u64
                    || !full_ports.is_empty();
            }
            let bounded = &v["lanes"]["bounded"];
            let retained_required_ports: BTreeSet<(String, String)> = bounded["ready"]
                .as_array()
                .into_iter()
                .flatten()
                .chain(bounded["admissions"].as_array().into_iter().flatten())
                .filter_map(|flow| {
                    (flow["root"] == "required").then_some(())?;
                    Some((
                        flow["room"].as_str()?.to_owned(),
                        flow["peer"].as_str()?.to_owned(),
                    ))
                })
                .collect();
            let unowned_full: Vec<_> = full_ports
                .difference(&retained_required_ports)
                .cloned()
                .collect();
            assert!(
                unowned_full.is_empty(),
                "PRODUCT: {name}'s PoolFull ports had no exact retained required flow in the \
                 same shipped status document: {unowned_full:?}: {}",
                shown.status
            );
            required_pool_full_seen |= !full_ports.is_empty();
            if full_ports.contains(&(pressure_room.to_string(), pressure_fingerprint.to_string())) {
                live_pool_full = Some((*name, Instant::now()));
                most_pressure = most_pressure.max(in_use);
                break 'pressure most_pressure;
            }
            most_pressure = most_pressure.max(in_use);
        }
        if most_pressure > vox_core::node::history_budget::FLOW_STATE_MIN_CAPACITY as u64 {
            break most_pressure;
        }
        if Instant::now() >= pressure_snapshot_deadman {
            panic!(
                "APPARATUS NO RESULT: the source-derived legal population did not stage more \
                 than the flow-state floor before the operator deadman (most {most_pressure}, \
                 PoolFull observed {pool_full_seen})"
            );
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    std::fs::remove_file(hold)
        .unwrap_or_else(|error| panic!("APPARATUS: could not release {}: {error}", hold.display()));
    std::fs::remove_file(archive_hold).unwrap_or_else(|error| {
        panic!(
            "APPARATUS: could not release {}: {error}",
            archive_hold.display()
        )
    });
    if pool_full_seen {
        assert!(
            required_pool_full_seen,
            "PRODUCT: a shipped bounded start reached PoolFull but status did not retain its \
             exact required root; the dependency was discarded instead of re-armed"
        );
        let (name, observed_at) = live_pool_full.unwrap_or_else(|| {
            panic!(
                "PRODUCT: a shipped bounded start reached PoolFull but no exact shared-room \
                 required admission remained for the release edge"
            )
        });
        pressure_tails
            .get(name)
            .expect("APPARATUS: PoolFull node lost its pre-attached observer")
            .wait_for_after(pressure_target, name, true, Some(observed_at));
    }
    drop(pressure_tails);
    let pressure_deadman = Instant::now() + vox_core::node::history_budget::BOUNDED_ROUND_PATIENCE;
    loop {
        let mut missing = Vec::new();
        for (dir, node, name, _) in &staged.everyone[..staged.hosted] {
            let (ok, out, err) = vox(
                dir,
                &as_node(&["room", "read", pressure_room, "--limit", "3"], *node),
                None,
            );
            assert!(ok, "PRODUCT: {name}'s pressure read refused: {out}{err}");
            if !out.contains(pressure_target) {
                missing.push(format!("{name}/{pressure_name}"));
            }
        }
        if missing.is_empty() {
            break;
        }
        assert!(
            Instant::now() < pressure_deadman,
            "APPARATUS NO RESULT: after exact pool capacity was released, the shipped pressure \
             post did not reach every retained port before the operator deadman: {missing:?}"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
    // The two consumed archive dispatches must also finish. Under the undersized mutant, this
    // observes the full-pool branch retain and retry exact archive work before the invariant red
    // is judged; a lost dispatch fails here on the shipped request's own status.
    for (dir, node, name, fingerprint) in
        &staged.everyone[..vox_core::node::history_budget::ARCHIVE_JOBS]
    {
        let archive_deadman =
            Instant::now() + vox_core::node::history_budget::BOUNDED_ROUND_PATIENCE;
        loop {
            let shown = synced(dir, *node);
            let status: serde_json::Value =
                serde_json::from_str(&shown.status).unwrap_or_else(|error| {
                    panic!(
                        "PRODUCT: {name}'s status was not JSON while its archive request ran: \
                         {error}: {}",
                        shown.status
                    )
                });
            let history = &status["lanes"]["history"];
            if matches!(history["phase"].as_str(), Some("Complete" | "More")) {
                break;
            }
            if matches!(
                history["phase"].as_str(),
                Some("Paused" | "Unavailable" | "Cancelled" | "Busy")
            ) {
                panic!(
                    "PRODUCT: {name}'s exact shipped archive request ended without its quantum \
                     after pool pressure: {history}"
                );
            }
            let bounded = &status["lanes"]["bounded"];
            let retained_archive = bounded["ready"]
                .as_array()
                .into_iter()
                .flatten()
                .any(|flow| flow["root"] == "archive");
            let running = bounded["running"]
                .as_array()
                .into_iter()
                .flatten()
                .filter(|slot| !slot.is_null())
                .any(|running| running["archive"] == true);
            let admission = bounded["admissions"]
                .as_array()
                .into_iter()
                .flatten()
                .any(|admission| admission["root"] == "archive");
            let charged = status["lanes"]["budget"]["flow_state"]["by_node"][fingerprint]
                .as_u64()
                .unwrap_or(0);
            assert!(
                history["running"] != true || running || retained_archive || admission,
                "PRODUCT: {name}'s shipped archive request remains running, but after a status \
                 request scheduled its work no exact archive round, retained archive flow, or \
                 archive admission owns its next step (node charge {charged} cannot stand in for \
                 archive ownership): {}",
                shown.status
            );
            assert!(
                Instant::now() < archive_deadman,
                "APPARATUS NO RESULT: {name}'s shipped archive request did not expose a \
                 terminal phase before the operator deadman after pool capacity returned: {}",
                shown.status
            );
            std::thread::sleep(Duration::from_millis(200));
        }
    }
    generation_accounting_keeps_actor_incarnations_exact(&staged);
    // The product's account of the pool, now that everyone has read everyone.
    let hosted_fps: BTreeSet<&str> = staged.everyone[..staged.hosted]
        .iter()
        .map(|(_, _, _, fp)| fp.as_str())
        .collect();
    let mut most = 0u64;
    let mut limit: Option<u64> = None;
    let mut broken: Vec<String> = Vec::new();
    if pool_full_seen {
        broken.push(
            "a legal round reached flow_state_pool_full; its retained work recovered before this \
             invariant verdict"
                .to_owned(),
        );
    }
    for (dir, node, name, fp) in &staged.everyone {
        let shown = synced(dir, *node);
        let v: serde_json::Value = serde_json::from_str(&shown.status).unwrap_or_default();
        let pool = &v["lanes"]["budget"]["flow_state"];
        let ports = v["lanes"]["ports"].as_array().cloned().unwrap_or_default();
        let running_here = ports
            .iter()
            .filter(|p| p["round_running"] == serde_json::Value::Bool(true))
            .count() as u64;
        // The nodes this node's daemon hosts: the source-derived pressure population on the host,
        // bob alone on the peer.
        let expected: BTreeSet<&str> = if hosted_fps.contains(fp.as_str()) {
            hosted_fps.clone()
        } else {
            BTreeSet::from([fp.as_str()])
        };
        match (pool["in_use"].as_u64(), pool["limit"].as_u64()) {
            (Some(in_use), Some(l)) => {
                most = most.max(in_use);
                limit = Some(l);
                let by_node = pool["by_node"].as_object();
                let keys: BTreeSet<&str> = by_node
                    .map(|m| m.keys().map(String::as_str).collect())
                    .unwrap_or_default();
                let sum: u64 = by_node
                    .map(|m| m.values().filter_map(serde_json::Value::as_u64).sum())
                    .unwrap_or(0);
                let actors = pool["actors"].as_array().cloned().unwrap_or_default();
                let actor_sum: u64 = actors
                    .iter()
                    .filter_map(|actor| actor["in_use"].as_u64())
                    .sum();
                let registered: BTreeMap<&str, u64> = actors
                    .iter()
                    .filter(|actor| actor["registered"] == true)
                    .filter_map(|actor| Some((actor["node"].as_str()?, actor["in_use"].as_u64()?)))
                    .collect();
                let retiring_sum: u64 = actors
                    .iter()
                    .filter(|actor| actor["registered"] == false)
                    .filter_map(|actor| actor["in_use"].as_u64())
                    .sum();
                let retiring_expected: BTreeSet<&str> = actors
                    .iter()
                    .filter(|actor| {
                        actor["registered"] == false
                            && actor["in_use"].as_u64().is_some_and(|count| count > 0)
                    })
                    .filter_map(|actor| actor["node"].as_str())
                    .collect();
                let retiring_said: BTreeSet<&str> = pool["retiring_nodes"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(serde_json::Value::as_str)
                    .collect();
                let running = pool["running"].as_array().cloned().unwrap_or_default();
                let actor_ids: BTreeSet<u64> = actors
                    .iter()
                    .filter_map(|actor| actor["actor"].as_u64())
                    .collect();
                let running_exact = running.iter().all(|round| {
                    round["actor"]
                        .as_u64()
                        .is_some_and(|actor| actor_ids.contains(&actor))
                        && round["node"].as_str().is_some()
                        && round["room"].as_str().is_some()
                        && round["peer"].as_str().is_some()
                });
                let mine = by_node
                    .and_then(|m| m.get(fp.as_str()))
                    .and_then(serde_json::Value::as_u64);
                if keys != expected
                    || actors
                        .iter()
                        .filter(|actor| actor["registered"] == true)
                        .count()
                        != expected.len()
                    || registered.keys().copied().collect::<BTreeSet<_>>() != expected
                    || registered.iter().any(|(node, count)| {
                        by_node.and_then(|values| values[*node].as_u64()) != Some(*count)
                    })
                    || actor_sum != in_use
                    || sum.saturating_add(retiring_sum) != in_use
                    || running.len() as u64 != in_use
                    || !running_exact
                    || retiring_said != retiring_expected
                {
                    broken.push(format!(
                        "{name}: flow-state generations do not account exactly for in_use \
                         {in_use} (by_node {}, actors {}, running {}, retiring_nodes {})",
                        pool["by_node"], pool["actors"], pool["running"], pool["retiring_nodes"]
                    ));
                }
                if mine != Some(running_here) {
                    broken.push(format!(
                        "{name}: by_node says {mine:?} for this node but {running_here} of its \
                         ports have a round running"
                    ));
                }
                let expected_limit = vox_core::node::history_budget::FLOW_STATE_MIN_CAPACITY
                    .max(vox_core::node::history_budget::BOUNDED_SYNC_RUNNING_SLOTS * keys.len())
                    as u64;
                if l != expected_limit || in_use > l {
                    broken.push(format!(
                        "{name}: the pool allows {l}, not exactly {expected_limit}, flow states \
                         for {} hosted nodes; {in_use} in use",
                        keys.len(),
                    ));
                }
            }
            _ => broken.push(format!(
                "{name}: `vox status --json` names no flow-state pool (lanes.budget.flow_state)"
            )),
        }
        broken.extend(start_words(name, &v));
    }
    println!(
        "[proof] {} hosted nodes and a peer each read every other member within \
         {converged_after:?} of the posts (a post waited at most {:?} for a room applying its \
         last change); {observed} legal flow states overlapped; flow-state pool at \
         most {most} of {} in use, one member per \
         hosted node; the pool's account or a port's last start said wrong: {}",
        staged.hosted,
        staged.waited,
        limit.map_or_else(|| "?".to_owned(), |l| l.to_string()),
        broken.len()
    );
    assert!(
        broken.is_empty(),
        "PRODUCT: `vox status --json` did not account for the flow-state pool or for a port's \
         last start, although every member read every other (ADR-038 FX-35): {broken:?}"
    );
    drop(staged);
    foreground_release_wakes_without_a_tick();
}

/// Stage the exact foreground-release claim separately from pool pressure. The product's tick
/// scheduler is disabled and the foreground lane is one job only. Before the hold begins, every
/// product status must show no running round and no retained admission, so the held job's release
/// is the only event that can wake the named waiter.
#[cfg(feature = "optional-proofs")]
fn foreground_release_wakes_without_a_tick() {
    let staged = stage_hosted_nodes(&FX35_WAKE_HOSTED, true, true, true, None);
    converged(&staged);
    let quiet_deadman = Instant::now() + vox_core::node::history_budget::BOUNDED_ROUND_PATIENCE;
    loop {
        let mut busy = Vec::new();
        for (dir, node, name, _) in &staged.everyone[..staged.hosted] {
            let shown = synced(dir, *node);
            let v: serde_json::Value = serde_json::from_str(&shown.status).unwrap_or_default();
            let bounded = &v["lanes"]["bounded"];
            let running = bounded["running"]
                .as_array()
                .into_iter()
                .flatten()
                .filter(|slot| !slot.is_null())
                .count();
            let admissions = bounded["admissions"]
                .as_array()
                .map_or(0, |admissions| admissions.len());
            let pending = bounded["ready"]
                .as_array()
                .into_iter()
                .flatten()
                .filter(|slot| !slot.is_null())
                .count() as u64
                + ["deferred", "retiring", "required"]
                    .into_iter()
                    .filter_map(|key| bounded[key].as_u64())
                    .sum::<u64>()
                + u64::from(bounded["cleanup"] == true);
            let in_use = v["lanes"]["budget"]["flow_state"]["in_use"]
                .as_u64()
                .unwrap_or(u64::MAX);
            if running != 0 || admissions != 0 || pending != 0 || in_use != 0 {
                busy.push(format!(
                    "{name}: running {running}, admissions {admissions}, pending {pending}, pool {in_use}"
                ));
            }
        }
        if busy.is_empty() {
            break;
        }
        assert!(
            Instant::now() < quiet_deadman,
            "APPARATUS NO RESULT: could not establish the no-running/no-admission \
             foreground-wake precondition before the operator deadman: {busy:?}"
        );
        std::thread::sleep(Duration::from_millis(20));
    }

    let hold = staged
        .live_hold
        .as_ref()
        .expect("APPARATUS: exact-admission hold path was not staged");
    std::fs::File::create(hold)
        .unwrap_or_else(|e| panic!("APPARATUS: could not create {}: {e}", hold.display()));
    let room = &staged.rooms[0];
    for (dir, node, name, _) in &staged.everyone[..staged.hosted] {
        let text = format!("{name} re-armed");
        stage_post(dir, *node, name, room, &text);
    }
    let staged_deadman = Instant::now() + vox_core::node::history_budget::BOUNDED_ROUND_PATIENCE;
    let (waiting_dir, waiting_node, waiting_name, parked) = loop {
        let mut found = None;
        let mut running = 0u64;
        for (dir, node, name, _) in &staged.everyone[..staged.hosted] {
            let shown = synced(dir, *node);
            let v: serde_json::Value = serde_json::from_str(&shown.status).unwrap_or_default();
            running = running.max(
                v["lanes"]["budget"]["flow_state"]["in_use"]
                    .as_u64()
                    .unwrap_or(0),
            );
            if let Some(admission) = v["lanes"]["bounded"]["admissions"]
                .as_array()
                .into_iter()
                .flatten()
                .find(|admission| {
                    admission["gate"] == "foreground"
                        && admission["room"] == *room
                        && admission["lane"] == "live"
                })
            {
                found = Some((dir.clone(), *node, *name, admission.clone()));
            }
        }
        let has_waiter = found.is_some();
        if running == 1 {
            if let Some(waiter) = found {
                break waiter;
            }
        }
        assert!(
            Instant::now() < staged_deadman,
            "APPARATUS NO RESULT: exactly one held round and its foreground waiter were not \
             visible before the operator deadman (running {running}, waiter {})",
            has_waiter
        );
        std::thread::sleep(Duration::from_millis(20));
    };

    // Create one remote result the retained waiter can reveal. It must still be absent before
    // release. The read and the tail subscription may schedule while capacity is held; neither
    // can be the event that starts the waiter after capacity changes.
    let parked_peer = parked["peer"]
        .as_str()
        .expect("APPARATUS: exact foreground admission did not name its peer");
    let (peer_dir, peer_node, peer_name, _) = staged
        .everyone
        .iter()
        .find(|(_, _, _, fingerprint)| fingerprint == parked_peer)
        .unwrap_or_else(|| {
            panic!(
                "APPARATUS: exact foreground admission named peer {parked_peer}, which is not a \
                 staged participant: {parked}"
            )
        });
    let target = format!("release-event-target-for-{waiting_name}");
    stage_post(peer_dir, *peer_node, peer_name, room, &target);
    let (ok, before, err) = vox(
        &waiting_dir,
        &as_node(&["room", "read", room], waiting_node),
        None,
    );
    assert!(
        ok,
        "APPARATUS: {waiting_name}'s pre-release staging read refused: {before}{err}"
    );
    assert!(
        !before.contains(&target),
        "APPARATUS: the retained waiter already held the release target before capacity was \
         released: {before}"
    );

    let mut command = Command::new(VOX);
    command
        .args(as_node(&["room", "tail", room], waiting_node))
        .env("VOX_DATA_DIR", &waiting_dir)
        .env("VOX_CONFIG_DIR", waiting_dir.join("cfg"))
        .env("VOX_IDENTITY_PASSPHRASE", IDENTITY)
        .env_remove("VOX_ROOM")
        .env_remove("VOX_SESSION")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut tail = command.spawn().unwrap_or_else(|error| {
        panic!("APPARATUS: could not start release-observer tail: {error}")
    });
    let stdout = tail
        .stdout
        .take()
        .expect("APPARATUS: release-observer tail has no stdout");
    let (lines_tx, lines_rx) = std::sync::mpsc::channel();
    let reader = std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            match line {
                Ok(line) => {
                    if lines_tx.send(Ok(line)).is_err() {
                        return;
                    }
                }
                Err(error) => {
                    let _ = lines_tx.send(Err(error.to_string()));
                    return;
                }
            }
        }
    });
    let ready = format!("tail-attached-for-{waiting_name}");
    stage_post(&waiting_dir, waiting_node, waiting_name, room, &ready);
    let attached_deadman = Instant::now() + vox_core::node::history_budget::BOUNDED_ROUND_PATIENCE;
    loop {
        let left = attached_deadman.saturating_duration_since(Instant::now());
        match lines_rx.recv_timeout(left) {
            Ok(Ok(line)) if line.contains(&ready) => break,
            Ok(Ok(_)) => {}
            Ok(Err(error)) => {
                panic!("APPARATUS: release-observer tail could not read stdout: {error}")
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => panic!(
                "APPARATUS: release-observer tail ended before showing its pre-release ready \
                 marker"
            ),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => panic!(
                "APPARATUS NO RESULT: release-observer tail did not show its pre-release ready \
                 marker before the operator deadman"
            ),
        }
    }

    // Bind the decisive release to the same exact admission observed before any staging command.
    // This status request may schedule ports, but the held foreground job still owns capacity;
    // the original admission (same token, gate, room, peer, root and lane) must remain parked.
    let shown = synced(&waiting_dir, waiting_node);
    let value: serde_json::Value = serde_json::from_str(&shown.status).unwrap_or_else(|error| {
        panic!(
            "PRODUCT: {waiting_name}'s final pre-release status was not JSON: {error}: {}",
            shown.status
        )
    });
    let still_parked = value["lanes"]["bounded"]["admissions"]
        .as_array()
        .into_iter()
        .flatten()
        .any(|admission| admission == &parked);
    assert!(
        still_parked,
        "PRODUCT: {waiting_name}'s exact parked foreground admission changed or disappeared \
         before its held capacity was released; originally {parked}, now {}",
        value["lanes"]["bounded"]["admissions"]
    );
    assert_eq!(
        value["lanes"]["budget"]["flow_state"]["in_use"], 1,
        "PRODUCT: {waiting_name}'s held round was not still the only running flow immediately \
         before the exact admission release: {}",
        shown.status
    );

    std::fs::remove_file(hold)
        .unwrap_or_else(|e| panic!("APPARATUS: could not release {}: {e}", hold.display()));
    // No status, read, post, or other actor request occurs after this point. The retained lane's
    // exact capacity-release notification is the only product event that can expose `target` to
    // the already-running shipped tail while periodic scheduling is disabled.
    let released_deadman = Instant::now() + vox_core::node::history_budget::BOUNDED_ROUND_PATIENCE;
    loop {
        let left = released_deadman.saturating_duration_since(Instant::now());
        match lines_rx.recv_timeout(left) {
            Ok(Ok(line)) if line.contains(&target) => break,
            Ok(Ok(_)) => {}
            Ok(Err(error)) => panic!(
                "PRODUCT: {waiting_name}'s shipped room tail failed after foreground release: {error}"
            ),
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => panic!(
                "PRODUCT: {waiting_name}'s shipped room tail ended after foreground release \
                 before exposing the retained target; admission {parked}"
            ),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => panic!(
                "APPARATUS NO RESULT: {waiting_name}'s shipped room tail did not expose the \
                 retained target after the exact foreground release edge before the operator \
                 deadman; admission {parked}"
            ),
        }
    }
    let rearmed_deadman = Instant::now() + vox_core::node::history_budget::BOUNDED_ROUND_PATIENCE;
    loop {
        let (ok, out, err) = vox(
            &waiting_dir,
            &as_node(&["room", "read", room], waiting_node),
            None,
        );
        assert!(
            ok,
            "PRODUCT: {waiting_name}'s shipped read refused while judging re-armed ports: \
             {out}{err}"
        );
        let missing: Vec<_> = staged.everyone[..staged.hosted]
            .iter()
            .map(|(_, _, name, _)| format!("{name} re-armed"))
            .filter(|text| !out.contains(text))
            .collect();
        if missing.is_empty() {
            break;
        }
        assert!(
            Instant::now() < rearmed_deadman,
            "APPARATUS NO RESULT: {waiting_name} did not read every post that re-armed an exact \
             port before the operator deadman after capacity released: {missing:?}"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
    let _ = tail.kill();
    let _ = tail.wait();
    let _ = reader.join();
}

/// Prune the holders' already-read post bodies, then join the identity that was trusted before
/// those posts. Its first walk records the declined missing bodies that FX-29 must leave quiet.
fn stage_sparse_member(staged: &mut Staged) {
    let late = staged
        .late
        .take()
        .expect("APPARATUS: quiet-room staging has no sparse identity");
    for (dir, node, name, _) in &staged.everyone {
        let node_dir = node_dir_of(dir, *node);
        let config = node_dir.join("config");
        std::fs::create_dir_all(&config)
            .unwrap_or_else(|e| panic!("APPARATUS: could not create {}: {e}", config.display()));
        std::fs::write(config.join("retention"), HOLD_FOR)
            .unwrap_or_else(|e| panic!("APPARATUS: could not write {name}'s retention file: {e}"));
        let (ok, out, err) = vox(
            dir,
            &as_node(
                &["room", "retention", &staged.rooms[0], "--steps", "7d"],
                *node,
            ),
            None,
        );
        assert!(
            ok,
            "PRODUCT (staging): {name}'s shipped `vox room retention --steps 7d` was refused: \
             {out}{err}"
        );
    }
    let pruning = Instant::now();
    let mut kept = Vec::new();
    loop {
        kept.clear();
        for room in &staged.rooms {
            for (dir, node, reader, _) in &staged.everyone {
                let (ok, out, err) = vox(dir, &as_node(&["room", "read", room], *node), None);
                assert!(
                    ok,
                    "PRODUCT: {reader}'s `vox room read` refused while staging sparse history: \
                     {out}{err}"
                );
                for (_, _, author, _) in &staged.everyone {
                    if out.contains(&format!("{author} is here")) {
                        kept.push(format!("{reader} still shows {author} in {room}"));
                    }
                }
            }
        }
        if kept.is_empty() {
            break;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    for (link, name) in staged.links.iter().zip(QUIET_ROOMS) {
        let (ok, out, err) = vox(
            &late.0,
            &as_node(&["room", "join", "--passphrase-file", "-", link], late.1),
            Some(&format!("{ROOMPASS}\n")),
        );
        assert!(
            ok,
            "PRODUCT: {}'s `vox room join {name}` was refused: {out}{err}",
            late.2
        );
    }
    let joined = Instant::now();
    staged.everyone.push(late);
    loop {
        let sparse = synced(&staged.host, Some(SPARSE));
        if sparse.recorded {
            break;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    println!(
        "[proof] every holder pruned the posts' bodies after {:?}; {SPARSE} recorded its sparse \
         first walk {:?} after joining",
        pruning.elapsed(),
        joined.elapsed()
    );
}

/// Prove that the sparse member's exact refusal survives both an ordinary transport reconnect
/// and reconstruction after its daemon restarts. The product verdict is causal: a returned lane
/// either completes empty or two of its own terminal cycles prove it is making the wrong progress.
fn prove_refusal_survives_reconnect_and_restart(staged: &mut Staged) {
    let bob_fp = staged
        .everyone
        .iter()
        .find(|(_, _, name, _)| *name == "bob")
        .map(|(_, _, _, fingerprint)| fingerprint.clone())
        .expect("APPARATUS: quiet staging has no bob identity");
    let sparse_fp = staged
        .everyone
        .iter()
        .find(|(_, _, name, _)| *name == SPARSE)
        .map(|(_, _, _, fingerprint)| fingerprint.clone())
        .expect("APPARATUS: quiet staging has no sparse identity");
    let reconnect0 = synced(&staged.host, Some(SPARSE));
    let reconnect_lane0 =
        lane_rounds(&reconnect0, &staged.rooms[0], &bob_fp).unwrap_or_else(|| {
            panic!(
            "PRODUCT: `vox status --json` did not show {SPARSE}'s lane for bob before reconnect"
        )
        });
    staged.peer_daemon.stop_in_place();
    staged.peer_daemon = daemon(&staged.peer, "peer-reconnected");
    attached_as(&staged.peer, "peer-reconnected", None);
    let (reconnected, reconnect_served) = loop {
        let now = synced(&staged.host, Some(SPARSE));
        let bob_now = synced(&staged.peer, None);
        let grown = lane_rounds(&now, &staged.rooms[0], &bob_fp)
            .map(|rounds| rounds.since(reconnect_lane0))
            .unwrap_or_default();
        let served = lane_rounds(&bob_now, &staged.rooms[0], &sparse_fp).unwrap_or_default();
        if grown.fetched_completed > 0 && served.served_completed > 0 {
            break (grown, served);
        }
        assert!(
            grown.rounds() < 2 && served.rounds() < 2,
            "PRODUCT: reconnecting unchanged inventory completed two exact lane cycles without \
             one empty fetched and served completion (ADR-038 FX-29): fetched {grown:?}; served \
             {served:?}"
        );
        std::thread::sleep(Duration::from_millis(200));
    };
    assert!(
        reconnected.fetched_completed == reconnected.fetched_empty
            && reconnected.history_fetched == 0
            && reconnected.history_declined == 0
            && reconnected.partial == 0
            && reconnected.failed == 0,
        "PRODUCT: reconnecting bob with unchanged inventory retried work on {SPARSE}'s lane \
         instead of completing empty (ADR-038 FX-29): {reconnected:?}"
    );
    assert!(
        reconnect_served.served_completed == reconnect_served.served_empty
            && reconnect_served.history_served == 0
            && reconnect_served.partial == 0
            && reconnect_served.failed == 0,
        "PRODUCT: after bob's reconnect, `vox status --json` says bob served repeated history \
         to {SPARSE} from unchanged inventory (ADR-038 FX-29): {reconnect_served:?}"
    );

    // Stop every source before the sparse node returns. Its first round with each unchanged
    // inventory must be empty and write-free, proving durable reconstruction rather than a
    // lucky in-process cache.
    staged.peer_daemon.stop_in_place();
    staged.host_daemon.stop_in_place();
    let keychain = attach::keychain(&staged.host)
        .to_string_lossy()
        .into_owned();
    staged.host_daemon = daemon_with(
        &staged.host,
        "host-restarted",
        &["--no-node"],
        &[("VOX_TEST_KEYCHAIN", keychain.as_str())],
    );
    while !attach::Root::at(&staged.host, IDENTITY).daemon_running() {
        std::thread::sleep(Duration::from_millis(200));
    }
    unlock(&staged.host, SPARSE);
    attached_as(&staged.host, "host-restarted", Some(SPARSE));
    let restart0 = synced(&staged.host, Some(SPARSE));
    for name in HOSTED {
        unlock(&staged.host, name);
        attached_as(&staged.host, "host-restarted", Some(name));
    }
    staged.peer_daemon = daemon(&staged.peer, "peer-after-host-restart");
    attached_as(&staged.peer, "peer-after-host-restart", None);
    let expected_late_lanes = staged.rooms.len() * (staged.hosted + 1);
    let (restarted, restart_served) = loop {
        let now = synced(&staged.host, Some(SPARSE));
        let bob_now = synced(&staged.peer, None);
        let lanes: Vec<LaneRounds> = now
            .lanes
            .iter()
            .map(|(key, rounds)| rounds.since(restart0.lanes.get(key).copied().unwrap_or_default()))
            .collect();
        let served: Vec<LaneRounds> = staged
            .rooms
            .iter()
            .map(|room| lane_rounds(&bob_now, room, &sparse_fp).unwrap_or_default())
            .collect();
        if lanes.len() == expected_late_lanes
            && lanes.iter().all(|lane| lane.fetched_completed > 0)
            && served.iter().all(|lane| lane.served_completed > 0)
        {
            break (lanes, served);
        }
        let cycled_wrong: Vec<_> = lanes
            .iter()
            .chain(&served)
            .filter(|lane| lane.rounds() >= 2 && lane.completed == 0)
            .collect();
        assert!(
            cycled_wrong.is_empty(),
            "PRODUCT: after restart, unchanged inventory completed two terminal cycles on a lane \
             without one completed round (ADR-038 FX-29): {cycled_wrong:?}"
        );
        std::thread::sleep(Duration::from_millis(200));
    };
    let restarted_nonempty: Vec<_> = restarted
        .iter()
        .filter(|lane| {
            lane.fetched_completed != lane.fetched_empty
                || lane.history_fetched != 0
                || lane.history_declined != 0
                || lane.partial != 0
                || lane.failed != 0
        })
        .collect();
    assert!(
        restarted_nonempty.is_empty(),
        "PRODUCT: after {SPARSE}'s restart, unchanged inventories retried work instead of each \
         first lane round completing empty (ADR-038 FX-29): {restarted_nonempty:?}"
    );
    let restart_served_nonempty: Vec<_> = restart_served
        .iter()
        .filter(|lane| {
            lane.served_completed != lane.served_empty
                || lane.history_served != 0
                || lane.partial != 0
                || lane.failed != 0
        })
        .collect();
    assert!(
        restart_served_nonempty.is_empty(),
        "PRODUCT: after process restart, bob served repeated history to {SPARSE} from unchanged \
         inventory instead of completing empty (ADR-038 FX-29): {restart_served_nonempty:?}"
    );

    // Every restarted node reaches the same observable empty-round edge before measurement.
    let settling: Vec<Synced> = staged
        .everyone
        .iter()
        .map(|(dir, node, _, _)| synced(dir, *node))
        .collect();
    loop {
        let settled = staged
            .everyone
            .iter()
            .enumerate()
            .all(|(i, (dir, node, _, _))| {
                let now = synced(dir, *node);
                !settling[i].lanes.is_empty()
                    && settling[i].lanes.iter().all(|(key, before)| {
                        let grown = now
                            .lanes
                            .get(key)
                            .copied()
                            .unwrap_or_default()
                            .since(*before);
                        grown.completed > 0 && grown.completed == grown.empty
                    })
            });
        if settled {
            break;
        }
        let cycled_wrong: Vec<String> = staged
            .everyone
            .iter()
            .enumerate()
            .flat_map(|(i, (dir, node, name, _))| {
                let now = synced(dir, *node);
                settling[i].lanes.iter().filter_map(move |(key, before)| {
                    let grown = now
                        .lanes
                        .get(key)
                        .copied()
                        .unwrap_or_default()
                        .since(*before);
                    (grown.rounds() >= 2
                        && (grown.completed == 0 || grown.completed != grown.empty))
                        .then(|| format!("{name} {key:?}: {grown:?}"))
                })
            })
            .collect();
        assert!(
            cycled_wrong.is_empty(),
            "PRODUCT: a lane completed two terminal cycles after restart without completing \
             empty; quiet staging is structurally wedged: {cycled_wrong:?}"
        );
        std::thread::sleep(Duration::from_millis(500));
    }
}

/// **Quiet rooms cost no rounds, no CPU or repeated history, answer at once, and say
/// when they last synced** (ADR-038 FX-15, FX-16, FX-17, FX-29; #979, #980, #986, #1021): one
/// daemon hosts [`HOSTED`], four
/// nodes as the decider's work Mac does, and a second daemon hosts bob; every node is in both
/// [`QUIET_ROOMS`], trusts every other before anyone posts (a member trusted after a post never
/// reads it), posts once in each room, and reads every other's post. Then nobody posts, and the
/// minute begins after every exact lane has completed an empty post-restart cycle. That causal
/// edge, rather than elapsed silence, establishes quiet. Over [`IDLE`]:
///
/// 1. **No rounds beyond the periodic ones** (FX-15): no lane (a room with a peer) of any node
///    runs more sync rounds than the periodic request allows, one per
///    [`SYNC_INTERVAL_SECS`](vox_core::node::syncstream::SYNC_INTERVAL_SECS) from each side plus
///    the follow-up each may raise. A round counts however it ended (`completed`, `partial` or
///    `failed` in `vox status --json`): a round that ends partial, its requested entries
///    unreceived, is the one that runs again a second later. Measured before the fix: one round
///    per peer per second, the settlement tick re-offering the own head.
/// 2. **The last sync is named** (FX-16): `vox status --json` on every node lists both rooms,
///    every member of each, a lane for each room and peer (32 on the host's nodes, 8 on the
///    peer's: a missing row must not read as quiet), and names a last completed sync for every
///    room and every other member. Before: "last sync never".
/// 3. **No CPU** (FX-15, #986): each daemon's CPU time, as Activity Monitor shows it, grows by at
///    most [`IDLE_CPU`]; the hosting daemon's is the number the issue bounds.
/// 4. **Answers at once** (FX-17, #986): every `vox status --json` asked of a hosted node, every
///    [`ASK_EVERY`], answers within [`ANSWER_WITHIN`], and says every port's last start in the
///    contract's words ([`start_words`], FX-35).
/// 5. **No bytes beyond the periodic rounds** (FX-15, #986): the hosting daemon's network bytes,
///    in and out as Activity Monitor counts them (`nettop`, unprivileged, read per socket and
///    summed by [`NetMeter`], which keeps a closed socket's bytes), grow by at most the rounds
///    its lanes are allowed times [`ROUND_BYTES`]: no window of entries is fetched again.
///    Measured on v0.4.6: 27 GiB in and 20 GiB out over 4.9 hours of quiet rooms; on main
///    2026-10-20 with the stall fixed, 13.7 MB in and 12.7 MB out a minute at 4 rounds per lane:
///    every inventory round reads the peer's whole board (`RecordKinds::ALL`), which no clause
///    yet bounds, so this red stands until one does. Off a Mac the bytes are not read and the
///    proof says so; the rounds and the CPU stand.
/// 6. **No store writes** (FX-29): every node's complete `store.redb` bytes and mtime are identical
///    at the two edges of the quiet minute. This is the user's artifact, not a private database
///    field or a status counter standing in for it.
/// 7. **No repeated history work** (FX-29): `vox status --json` says no quiet lane fetched,
///    served or re-declined history.
/// 8. **Every completed round is empty** (FX-29): every lane's `empty` increase equals its
///    `completed` increase in shipped status.
/// 9. **Every lane ran**: each lane completes at least one periodic round, so quiet cannot pass
///    merely because the pool stopped all work.
///
/// The staging is shared with
/// [`hosted_nodes_read_each_other_and_the_flow_state_pool_holds_no_port`], FX-35's own
/// journey; this one measures the quiet minute after it.
///
/// Mutants: the own-head hint offered to every connected peer on every settlement tick again
/// (the `held_through` filter in `settle_room` removed, #979's fix reverted) turns claims 1, 3
/// and 5 red on their own numbers; the lane's completion no longer recording the sync
/// (`note_lane_sync` removed) turns claim 2 red on `last_sync_ms`; offering a declined missing
/// hint to that peer again turns claims 6 and 7 red. The isolated `held-inventory-write` mutant
/// commits the already-filtered inventory without marking a status counter, so only claim 6's
/// direct store artifact verdict turns red.
#[cfg(feature = "optional-proofs")]
#[test]
#[ignore = "an idle minute of two real vox daemons, one hosting four nodes; optional, run it in release"]
fn a_quiet_room_costs_no_rounds_and_says_when_it_last_synced() {
    // Two rooms joined by four nodes each; four unlocks on the host and the peer daemon's own.
    watchdog::arm_for_setup(8, 10);
    let mut staged = stage_hosted_nodes(&HOSTED, false, false, false, Some(SPARSE));
    converged(&staged);
    stage_sparse_member(&mut staged);
    prove_refusal_survives_reconnect_and_restart(&mut staged);
    // Keep the complete shipped profiles and daemon output if a verdict below goes red. A green
    // removes them explicitly at the end.
    let root = staged
        ._tmp
        .take()
        .expect("APPARATUS: quiet-room staging lost its scratch root")
        .keep();
    let Staged {
        host,
        peer,
        everyone,
        rooms,
        host_daemon,
        peer_daemon,
        waited,
        ..
    } = &staged;

    // ---- the minute is measured ------------------------------------------------------------
    // `prove_refusal_survives_reconnect_and_restart` returned only after every exact lane
    // completed one empty post-restart cycle. Snapshot every complete store now. Until the second
    // edge below, the proof process performs no filesystem access to a store.
    let before: Vec<Synced> = everyone
        .iter()
        .map(|(dir, node, _, _)| synced(dir, *node))
        .collect();
    let stores0 = store_snapshots(everyone);
    let cpu0 = (cpu_time(host_daemon.0.id()), cpu_time(peer_daemon.0.id()));
    let mut meter = NetMeter::default();
    meter.sample(host_daemon.0.id());
    let counted = Instant::now();
    let mut answers: Vec<(&str, Duration)> = Vec::new();
    // The flow-state pool as every status in the minute shows it: the most in use and its limit,
    // printed with the numbers (its claims are the FX-35 journey's).
    let mut pool_most = 0u64;
    let mut pool_limit: Option<u64> = None;
    let mut start_breaches: Vec<String> = Vec::new();
    while counted.elapsed() < IDLE {
        std::thread::sleep(ASK_EVERY.min(IDLE.saturating_sub(counted.elapsed())));
        for name in HOSTED.iter().chain([&SPARSE]) {
            let asked = Instant::now();
            let (ok, out, err) = vox(host, &["status", "--json", "--node", name], None);
            assert!(
                ok,
                "PRODUCT: `vox status --json --node {name}` refused in the quiet minute: {err}"
            );
            answers.push((name, asked.elapsed()));
            let v: serde_json::Value = serde_json::from_str(&out).unwrap_or_default();
            let pool = &v["lanes"]["budget"]["flow_state"];
            if let (Some(in_use), Some(limit)) = (pool["in_use"].as_u64(), pool["limit"].as_u64()) {
                pool_most = pool_most.max(in_use);
                pool_limit = Some(limit);
            }
            start_breaches.extend(start_words(name, &v));
        }
        meter.sample(host_daemon.0.id());
    }
    let idled = counted.elapsed();
    let stores1 = store_snapshots(everyone);
    let after: Vec<Synced> = everyone
        .iter()
        .map(|(dir, node, _, _)| synced(dir, *node))
        .collect();
    let cpu1 = (cpu_time(host_daemon.0.id()), cpu_time(peer_daemon.0.id()));
    meter.sample(host_daemon.0.id());

    // ---- the numbers ---------------------------------------------------------------------------
    let interval = vox_core::node::syncstream::SYNC_INTERVAL_SECS;
    let allowed = 2 * (idled.as_secs() / interval + 1);
    let mut over: Vec<String> = Vec::new();
    let mut most = LaneRounds::default();
    let mut not_empty: Vec<String> = Vec::new();
    let mut repeated_history: Vec<String> = Vec::new();
    let mut idle_lanes: Vec<String> = Vec::new();
    for (i, (_, _, name, _)) in everyone.iter().enumerate() {
        for ((room, peer), n) in &after[i].lanes {
            let was = before[i]
                .lanes
                .get(&(room.clone(), peer.clone()))
                .copied()
                .unwrap_or_default();
            let grown = n.since(was);
            if grown.rounds() > most.rounds() {
                most = grown;
            }
            if grown.rounds() > allowed {
                over.push(format!(
                    "{name}'s lane {}/{}: {} rounds ({} completed, {} partial, {} failed)",
                    &room[..room.len().min(8)],
                    &peer[..peer.len().min(8)],
                    grown.rounds(),
                    grown.completed,
                    grown.partial,
                    grown.failed
                ));
            }
            if grown.completed != grown.empty {
                not_empty.push(format!(
                    "{name}'s lane {}/{}: {} completed, {} empty",
                    &room[..room.len().min(8)],
                    &peer[..peer.len().min(8)],
                    grown.completed,
                    grown.empty
                ));
            }
            if grown.history_fetched != 0
                || grown.history_served != 0
                || grown.history_declined != 0
            {
                repeated_history.push(format!(
                    "{name}'s lane {}/{}: {} fetched, {} served, {} declined",
                    &room[..room.len().min(8)],
                    &peer[..peer.len().min(8)],
                    grown.history_fetched,
                    grown.history_served,
                    grown.history_declined
                ));
            }
            if grown.completed == 0 {
                idle_lanes.push(format!(
                    "{name}'s lane {}/{} ({} rounds)",
                    &room[..room.len().min(8)],
                    &peer[..peer.len().min(8)],
                    grown.rounds()
                ));
            }
        }
    }
    let wrote: Vec<String> = stores0
        .iter()
        .filter_map(|(name, before)| {
            let after = stores1
                .get(name)
                .unwrap_or_else(|| panic!("APPARATUS: {name}'s second store snapshot disappeared"));
            (before.bytes != after.bytes || before.modified != after.modified).then(|| {
                format!(
                    "{name}: bytes changed {} ({} -> {} bytes), mtime changed {} ({:?} -> {:?}), \
                     store {}",
                    before.bytes != after.bytes,
                    before.bytes.len(),
                    after.bytes.len(),
                    before.modified != after.modified,
                    before.modified,
                    after.modified,
                    before.path.display()
                )
            })
        })
        .collect();
    let host_lanes: usize = everyone
        .iter()
        .zip(&after)
        .filter(|((dir, _, _, _), _)| dir == host)
        .map(|(_, status)| status.lanes.len())
        .sum();
    let traffic_bound = host_lanes as u64 * allowed * ROUND_BYTES;
    // The bytes moved, or why they are not known; judged after every number is printed.
    let moved: Result<(u64, u64), String> = meter.moved();
    // Every room, member and lane expected is shown: a missing `sync` row or member must not
    // read as quiet.
    let mut absent: Vec<String> = Vec::new();
    for (i, (_, _, name, _)) in everyone.iter().enumerate() {
        let shown = &after[i];
        if shown.rooms.len() != rooms.len() {
            absent.push(format!(
                "{name}'s status lists {} rooms, not {}: {:?}",
                shown.rooms.len(),
                rooms.len(),
                shown.rooms.keys().collect::<Vec<_>>()
            ));
        }
        for room in rooms {
            let Some(full) = shown.rooms.keys().find(|r| r.starts_with(room.as_str())) else {
                absent.push(format!("{name}'s status does not list room {room}"));
                continue;
            };
            let members = &shown.rooms[full];
            for (_, _, other, fp) in everyone {
                if !members.contains(fp) {
                    absent.push(format!(
                        "{name}'s status lists no member {other} in room {room}"
                    ));
                }
                if other != name && !shown.lanes.contains_key(&(full.clone(), fp.clone())) {
                    absent.push(format!(
                        "{name}'s status shows no lane for {other} in room {room}"
                    ));
                }
            }
        }
    }
    let peer_lanes = everyone
        .iter()
        .zip(&after)
        .filter(|((dir, _, _, _), _)| dir == peer)
        .map(|(_, status)| status.lanes.len())
        .sum::<usize>();
    let spent = (cpu1.0.saturating_sub(cpu0.0), cpu1.1.saturating_sub(cpu0.1));
    let slowest = answers.iter().map(|(_, d)| *d).max().unwrap_or_default();
    let not_recorded: Vec<&str> = everyone
        .iter()
        .enumerate()
        .filter(|(i, _)| !after[*i].recorded)
        .map(|(_, (_, _, name, _))| *name)
        .collect();
    println!(
        "[proof] over {idled:?} of quiet with {} nodes on the host's daemon and one on the peer's, \
         in {} rooms (a post waited at most {waited:?} for a room applying its last change; the \
         minute began after every lane completed an empty post-restart cycle): a lane \
         ran at most {} rounds ({} completed, {} partial, {} failed; \
         allowed {allowed}: one periodic every {interval} s from each side and its follow-up; \
         lanes shown: {host_lanes} on the host's nodes, {peer_lanes} on the peer's; rooms, \
         members or lanes missing: {}); last sync \
         recorded on every node: {}; CPU time: the host's daemon +{:?}, the peer's +{:?} (bound \
         {IDLE_CPU:?}); {} status answers, slowest {slowest:?} (bound {ANSWER_WITHIN:?}); the \
         host's daemon moved {} over {} nettop samples (bound {traffic_bound} bytes = \
         {host_lanes} lanes x {allowed} rounds x {ROUND_BYTES} bytes); flow-state pool at most \
         {pool_most} of {} in use; stores changed: {}; repeated history outcomes: {}; non-empty \
         completed lanes: {}; lanes with no completed round: {}",
        HOSTED.len() + 1,
        rooms.len(),
        most.rounds(),
        most.completed,
        most.partial,
        most.failed,
        absent.len(),
        not_recorded.is_empty(),
        spent.0,
        spent.1,
        answers.len(),
        match &moved {
            Ok((i, o)) => format!("{i} bytes in and {o} bytes out"),
            Err(why) => format!("bytes not measured: {why}"),
        },
        meter.samples,
        pool_limit.map_or_else(|| "?".to_owned(), |l| l.to_string()),
        if wrote.is_empty() {
            "none".to_owned()
        } else {
            wrote.join("; ")
        },
        if repeated_history.is_empty() {
            "none".to_owned()
        } else {
            repeated_history.join("; ")
        },
        if not_empty.is_empty() {
            "none".to_owned()
        } else {
            not_empty.join("; ")
        },
        if idle_lanes.is_empty() {
            "none".to_owned()
        } else {
            idle_lanes.join("; ")
        }
    );
    // Each node's lanes over the minute: what `vox status --json` counted per room and peer.
    for (i, (_, _, name, _)) in everyone.iter().enumerate() {
        let lanes: Vec<String> = after[i]
            .lanes
            .iter()
            .map(|((room, peer), n)| {
                let g = n.since(
                    before[i]
                        .lanes
                        .get(&(room.clone(), peer.clone()))
                        .copied()
                        .unwrap_or_default(),
                );
                format!(
                    "{}/{}: +{} rounds ({} completed, {} empty, {} partial, {} failed; {} completed in all)",
                    &room[..room.len().min(8)],
                    &peer[..peer.len().min(8)],
                    g.rounds(),
                    g.completed,
                    g.empty,
                    g.partial,
                    g.failed,
                    n.completed
                )
            })
            .collect();
        println!(
            "[proof] {name}'s lanes over the minute: {}",
            lanes.join("; ")
        );
    }
    // Every claim is judged, so a run that breaks several names each on its own number.
    let mut reds: Vec<String> = Vec::new();
    if !absent.is_empty() {
        reds.push(format!(
            "PRODUCT: `vox status --json` does not show every room, member and lane (ADR-038 \
             FX-16): {absent:?}"
        ));
    }
    if !wrote.is_empty() {
        reds.push(format!(
            "PRODUCT: sync rounds that brought nothing wrote to the nodes' store artifacts \
             (ADR-038 FX-29, #1021): {}",
            wrote.join("; ")
        ));
    }
    if !over.is_empty() {
        reds.push(format!(
            "PRODUCT: a quiet room ran sync rounds with nothing to sync (ADR-038 FX-15): over \
             {idled:?} these lanes ran more rounds than the {allowed} allowed (one periodic \
             request of {interval} s from each side plus the follow-up each may raise; a partial \
             or failed round is a round): {over:?}"
        ));
    }
    if !not_recorded.is_empty() {
        let statuses: Vec<String> = everyone
            .iter()
            .enumerate()
            .filter(|(i, _)| !after[*i].recorded)
            .map(|(i, (_, _, name, _))| format!("{name}'s status: {}", after[i].status))
            .collect();
        reds.push(format!(
            "PRODUCT: `vox status` does not say when the room and the member last completed a \
             sync (ADR-038 FX-16) on {not_recorded:?}\n{}",
            statuses.join("\n")
        ));
    }
    if spent.0 > IDLE_CPU || spent.1 > IDLE_CPU {
        reds.push(format!(
            "PRODUCT: a daemon in quiet rooms spent CPU with nothing to sync (ADR-038 FX-15, \
             #986): the host's daemon ({} nodes) +{:?}, the peer's +{:?} over {idled:?} (bound \
             {IDLE_CPU:?})",
            HOSTED.len(),
            spent.0,
            spent.1
        ));
    }
    if slowest > ANSWER_WITHIN {
        reds.push(format!(
            "PRODUCT: `vox status --json` answered in {slowest:?} in quiet rooms, over \
             {ANSWER_WITHIN:?} (ADR-038 FX-17, #986); every answer: {answers:?}"
        ));
    }
    if !start_breaches.is_empty() {
        reds.push(format!(
            "PRODUCT: `vox status --json` said a port's last start in other than the contract's \
             words (ADR-038 FX-35) in the quiet minute: {start_breaches:?}"
        ));
    }
    if !repeated_history.is_empty() {
        reds.push(format!(
            "PRODUCT: `vox status --json` says quiet lanes fetched, served or re-declined \
             repeated history (ADR-038 FX-29, #1021): {}",
            repeated_history.join("; ")
        ));
    }
    if !not_empty.is_empty() {
        reds.push(format!(
            "PRODUCT: shipped status says completed quiet rounds fetched something new \
             (ADR-038 FX-29, #1021): {}",
            not_empty.join("; ")
        ));
    }
    if !idle_lanes.is_empty() {
        reds.push(format!(
            "PRODUCT: these lanes completed no periodic round in the quiet minute: {}",
            idle_lanes.join("; ")
        ));
    }
    match moved {
        Ok((i, o)) if i + o > traffic_bound => reds.push(format!(
            "PRODUCT: a daemon in quiet rooms moved bytes beyond its periodic rounds \
             (ADR-038 FX-15, #986): {i} in and {o} out over {idled:?}, more than its \
             {host_lanes} lanes' {allowed} allowed rounds at {ROUND_BYTES} bytes each \
             ({traffic_bound}): a window of entries, or the peer's whole board (every \
             inventory round reads it with RecordKinds::ALL), was fetched again"
        )),
        Ok(_) => {}
        // On a Mac the bytes are what Activity Monitor shows, and not reading them is a
        // fault of the apparatus; elsewhere there is no `nettop`, and the claim is not made.
        Err(why) if cfg!(target_os = "macos") => reds.push(format!(
            "APPARATUS: the host daemon's network bytes could not be read: {why}"
        )),
        Err(why) => eprintln!(
            "[proof] NOT MEASURED: the host daemon's network bytes ({why}); claim 5 rests on \
             the lanes' rounds here"
        ),
    }

    // A changed inventory must retire the exact declined record and wake once. Restore Bob's
    // ordinary retention, append one successor through the shipped command, and require both
    // sides' status to name a non-empty completion while the sparse member reads it.
    let bob_fp = everyone
        .iter()
        .find(|(_, _, name, _)| *name == "bob")
        .map(|(_, _, _, fingerprint)| fingerprint.clone())
        .expect("APPARATUS: quiet staging has no bob identity");
    let sparse_fp = everyone
        .iter()
        .find(|(_, _, name, _)| *name == SPARSE)
        .map(|(_, _, _, fingerprint)| fingerprint.clone())
        .expect("APPARATUS: quiet staging has no sparse identity");
    let bob_config = node_dir_of(peer, None).join("config");
    std::fs::write(bob_config.join("retention"), "default forever\n")
        .unwrap_or_else(|e| panic!("APPARATUS: could not restore bob's retention file: {e}"));
    let (ok, out, err) = vox(
        peer,
        &["room", "retention", &rooms[0], "--steps", "7d"],
        None,
    );
    assert!(
        ok,
        "PRODUCT (staging): bob's shipped retention reload was refused: {out}{err}"
    );
    let late0 = synced(host, Some(SPARSE));
    let bob0 = synced(peer, None);
    let late_lane0 = lane_rounds(&late0, &rooms[0], &bob_fp);
    let bob_lane0 = lane_rounds(&bob0, &rooms[0], &sparse_fp);
    if late_lane0.is_none() {
        reds.push(format!(
            "PRODUCT: status showed no {SPARSE} fetched lane for bob in {} before changed \
             inventory",
            rooms[0]
        ));
    }
    if bob_lane0.is_none() {
        reds.push(format!(
            "PRODUCT: status showed no bob served lane for {SPARSE} in {} before changed \
             inventory",
            rooms[0]
        ));
    }
    let fresh = "bob changed his quiet inventory";
    stage_post(peer, None, "bob", &rooms[0], fresh);
    let changed = Instant::now();
    let mut read = false;
    let (fetched, served) = loop {
        let (ok, out, err) = vox(host, &["room", "read", &rooms[0], "--node", SPARSE], None);
        assert!(
            ok,
            "PRODUCT: {SPARSE}'s post-quiet read was refused: {out}{err}"
        );
        read |= out.contains(fresh);
        let late_now = synced(host, Some(SPARSE));
        let bob_now = synced(peer, None);
        let fetched = late_lane0
            .and_then(|before| {
                lane_rounds(&late_now, &rooms[0], &bob_fp).map(|now| now.since(before))
            })
            .unwrap_or_default();
        let served = bob_lane0
            .and_then(|before| {
                lane_rounds(&bob_now, &rooms[0], &sparse_fp).map(|now| now.since(before))
            })
            .unwrap_or_default();
        if read {
            break (fetched, served);
        }
        // The first terminal cycle may have already been in flight when Bob appended. If either
        // exact lane completes a second cycle without exposing the earlier successor, later wall
        // time cannot repair the lost causal work.
        if fetched.rounds() >= 2 || served.rounds() >= 2 {
            reds.push(format!(
                "PRODUCT: after two exact terminal lane cycles, {SPARSE} did not read bob's \
                 changed inventory successor; fetched {fetched:?}; served {served:?}"
            ));
            break (fetched, served);
        }
        std::thread::sleep(Duration::from_millis(200));
    };
    println!(
        "[proof] changed inventory reached {SPARSE} in {:?}; fetched {fetched:?}; served \
         {served:?}",
        changed.elapsed()
    );
    if fetched.fetched_completed <= fetched.fetched_empty || fetched.history_fetched == 0 {
        reds.push(format!(
            "PRODUCT: {SPARSE}'s fetched lane did not name the non-empty completion that delivered \
             bob's changed inventory: {fetched:?}"
        ));
    }
    if served.served_completed <= served.served_empty || served.history_served == 0 {
        reds.push(format!(
            "PRODUCT: bob's served lane did not name the non-empty completion that delivered its \
             changed inventory to {SPARSE}: {served:?}"
        ));
    }
    assert!(
        fetched.history_rearmed > 0,
        "PRODUCT: bob's successor head was read, but `vox status --json` did not say the old \
         refusal was re-armed (ADR-038 FX-29): {fetched:?}"
    );

    // The first later completion must be empty in both directions. This proves the successor
    // replaced the refusal rather than bypassing a stale record once. A second terminal cycle on
    // either exact lane while the other has not completed is a structural wedge.
    let successor_fetched0 = lane_rounds(&synced(host, Some(SPARSE)), &rooms[0], &bob_fp)
        .unwrap_or_else(|| panic!("PRODUCT: status lost {SPARSE}'s successor lane for bob"));
    let successor_served0 = lane_rounds(&synced(peer, None), &rooms[0], &sparse_fp)
        .unwrap_or_else(|| panic!("PRODUCT: status lost bob's successor lane for {SPARSE}"));
    let (successor_quiet_fetched, successor_quiet_served) = loop {
        let fetched = lane_rounds(&synced(host, Some(SPARSE)), &rooms[0], &bob_fp)
            .map(|now| now.since(successor_fetched0))
            .unwrap_or_default();
        let served = lane_rounds(&synced(peer, None), &rooms[0], &sparse_fp)
            .map(|now| now.since(successor_served0))
            .unwrap_or_default();
        if fetched.fetched_completed > 0 && served.served_completed > 0 {
            break (fetched, served);
        }
        assert!(
            fetched.rounds() < 2 && served.rounds() < 2,
            "PRODUCT: after bob's successor was read, two exact terminal cycles completed without \
             the next fetched and served completion: fetched {fetched:?}; served {served:?}"
        );
        std::thread::sleep(Duration::from_millis(200));
    };
    assert!(
        successor_quiet_fetched.fetched_completed == successor_quiet_fetched.fetched_empty
            && successor_quiet_fetched.history_fetched == 0
            && successor_quiet_fetched.history_declined == 0
            && successor_quiet_fetched.history_rearmed == 0
            && successor_quiet_fetched.partial == 0
            && successor_quiet_fetched.failed == 0,
        "PRODUCT: after bob's successor was read, {SPARSE}'s next completed fetch repeated or \
         re-armed that unchanged history (ADR-038 FX-29): {successor_quiet_fetched:?}"
    );
    assert!(
        successor_quiet_served.served_completed == successor_quiet_served.served_empty
            && successor_quiet_served.history_served == 0
            && successor_quiet_served.partial == 0
            && successor_quiet_served.failed == 0,
        "PRODUCT: after bob's successor was read, bob's next completed serve transferred that \
         unchanged history again (ADR-038 FX-29): {successor_quiet_served:?}"
    );

    let pictures = if reds.is_empty() {
        String::new()
    } else {
        let mut lines = Vec::new();
        for (dir, node, name, _) in everyone {
            let shown = synced(dir, *node);
            let value: serde_json::Value = serde_json::from_str(&shown.status).unwrap_or_default();
            let mut starts: BTreeMap<String, usize> = BTreeMap::new();
            for port in value["lanes"]["ports"].as_array().into_iter().flatten() {
                let key = format!(
                    "{}/{}",
                    port["start_outcome"].as_str().unwrap_or("?"),
                    port["start_reason"].as_str().unwrap_or("-")
                );
                *starts.entry(key).or_insert(0) += 1;
            }
            lines.push(format!(
                "{name}: ports by last start {starts:?}; flow-state pool {}; lanes {}",
                value["lanes"]["budget"]["flow_state"],
                lanes_of(&shown.status)
            ));
        }
        lines.push(format!(
            "staging root kept at {} (node stores under */nodes/*/store.redb; daemon output under \
             daemon-*.out and daemon-*.err)",
            root.display()
        ));
        lines.join("\n")
    };
    assert!(
        reds.is_empty(),
        "{}\n{pictures}\nthe host's daemon said: {}\nthe peer's daemon said: {}",
        reds.join("\n\n"),
        said(host, "host"),
        said(peer, "peer")
    );
    let _ = std::fs::remove_dir_all(root);
}

/// How long the two agents work: a post a second from each into each of [`WORK_ROOMS`] rooms in
/// turn, what harness hooks at work append.
const AT_WORK: Duration = Duration::from_secs(60);
/// Rooms the two agents share while they work: each publication of the daemon's status covers
/// every open room, so the cost under test grows with this.
const WORK_ROOMS: usize = 3;
/// CPU time a daemon may spend over [`AT_WORK`] of two agents posting into [`WORK_ROOMS`] rooms:
/// Activity Monitor's number. Measured 2026-10-20 on the decider's work Mac (v0.4.7, four nodes,
/// four rooms, agents working): ~180% of a core, that is 108 s per minute. In this staging the
/// v0.4.7 code spent 17.5 s per daemon per minute; with each room's trust picture reused across
/// publications (#990) it spends 8 s, the rest being the rounds the posts themselves run (~9 per
/// post, #996). The bound is what #990 delivers; #996 lowers it again.
const WORK_CPU: Duration = Duration::from_secs(10);
/// Every `vox status --json` during the work answers within this: the control socket is what the
/// app, the TUI and the harness hook (500 ms of patience) wait on. Measured before this: 0.5 s.
const ANSWER_WITHIN: Duration = Duration::from_millis(200);

/// **A daemon whose agents are working stays cheap and answers at once** (ADR-038 FX-15, FX-17;
/// #990): alice and bob, each on a daemon of their own, share [`WORK_ROOMS`] rooms; for
/// [`AT_WORK`] each posts once a second, round-robin over the rooms, as two harness sessions at
/// work do. Over that minute each daemon's CPU time MUST grow by at most [`WORK_CPU`], every
/// `vox status --json` asked meanwhile MUST answer within [`ANSWER_WITHIN`], and the work MUST be
/// real: each reads the other's last post within [`READY_WITHIN`] of the end.
///
/// Mutant: every status publication deriving every room's trust picture again (the reuse in
/// `detail_of` removed) turns the CPU claim red on its own number.
#[cfg(feature = "optional-proofs")]
#[test]
#[ignore = "a minute of two real vox daemons at work; optional, run it in release"]
fn a_daemon_with_agents_at_work_stays_cheap_and_answers_at_once() {
    watchdog::arm_for_setup(1, 8);
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
    let alice_daemon = daemon(&alice, "alice");
    attached(&alice, "alice");
    let bob_daemon = daemon(&bob, "bob");
    attached(&bob, "bob");
    let mut rooms = Vec::with_capacity(WORK_ROOMS);
    for i in 1..=WORK_ROOMS {
        let name = format!("work-{i}");
        let (ok, _, err) = vox(
            &alice,
            &["room", "create", "--passphrase-file", "-", "--name", &name],
            Some(&format!("{ROOMPASS}\n")),
        );
        assert!(ok, "PRODUCT: `vox room create {name}` failed: {err}");
        let listed = attached(&alice, "alice");
        let room = listed
            .lines()
            .find(|l| l.contains(&name))
            .and_then(|l| l.split_whitespace().next())
            .unwrap_or_else(|| panic!("PRODUCT: `vox room list` shows no room {name}: {listed}"))
            .to_owned();
        let (ok, link, err) = vox(&alice, &["room", "link", &room], None);
        assert!(ok, "PRODUCT: `vox room link` failed: {err}");
        let (ok, _, err) = vox(
            &bob,
            &["room", "join", "--passphrase-file", "-", link.trim()],
            Some(&format!("{ROOMPASS}\n")),
        );
        assert!(
            ok,
            "PRODUCT: bob's `vox room join {name}` was refused: {err}"
        );
        rooms.push(room);
    }
    // Both have read each other in every room before the clock starts.
    let joined = Instant::now();
    for room in &rooms {
        let (ok, out, err) = vox(&alice, &["room", "post", room, "ready, alice"], None);
        assert!(ok, "PRODUCT: alice's post was refused: {out}{err}");
        let (ok, out, err) = vox(&bob, &["room", "post", room, "ready, bob"], None);
        assert!(ok, "PRODUCT: bob's post was refused: {out}{err}");
        let (to_alice, to_bob) = arrivals(
            joined,
            (&alice, "ready, bob"),
            (&bob, "ready, alice"),
            room,
            BOUND,
        );
        assert!(
            to_alice.is_some() && to_bob.is_some(),
            "PRODUCT: within {BOUND:?} of the join, alice read bob: {to_alice:?}; bob read alice: \
             {to_bob:?} (None = never) in room {room}\nbob's daemon said: {}\nalice's daemon \
             said: {}",
            said(&bob, "bob"),
            said(&alice, "alice")
        );
    }
    std::thread::sleep(Duration::from_secs(5));

    // ---- the agents work -----------------------------------------------------------------------
    let cpu0 = (cpu_time(alice_daemon.0.id()), cpu_time(bob_daemon.0.id()));
    let started = Instant::now();
    let worker = |dir: std::path::PathBuf, who: &'static str, rooms: Vec<String>| {
        std::thread::spawn(move || {
            let mut refused = 0usize;
            let mut i = 0usize;
            while started.elapsed() < AT_WORK {
                let room = &rooms[i % rooms.len()];
                let (ok, _, _) = vox(
                    &dir,
                    &["room", "post", room, &format!("{who} step {i}")],
                    None,
                );
                if !ok {
                    refused += 1;
                }
                i += 1;
                std::thread::sleep(Duration::from_secs(1));
            }
            (i, refused)
        })
    };
    let a = worker(alice.clone(), "alice", rooms.clone());
    let b = worker(bob.clone(), "bob", rooms.clone());
    let mut answers: Vec<Duration> = Vec::new();
    while started.elapsed() < AT_WORK {
        std::thread::sleep(Duration::from_secs(5));
        for dir in [&alice, &bob] {
            let asked = Instant::now();
            let (ok, _, err) = vox(dir, &["status", "--json"], None);
            assert!(
                ok,
                "PRODUCT: `vox status --json` refused while agents worked: {err}"
            );
            answers.push(asked.elapsed());
        }
    }
    let (posted_a, refused_a) = a
        .join()
        .unwrap_or_else(|_| panic!("APPARATUS: alice's worker panicked"));
    let (posted_b, refused_b) = b
        .join()
        .unwrap_or_else(|_| panic!("APPARATUS: bob's worker panicked"));
    let worked = started.elapsed();
    let cpu1 = (cpu_time(alice_daemon.0.id()), cpu_time(bob_daemon.0.id()));
    let spent = (cpu1.0.saturating_sub(cpu0.0), cpu1.1.saturating_sub(cpu0.1));
    let slowest = answers.iter().copied().max().unwrap_or_default();
    // The work was real: each reads the other's last post, in the room it went to.
    let alice_last = format!("alice step {}", posted_a.saturating_sub(1));
    let bob_last = format!("bob step {}", posted_b.saturating_sub(1));
    let (to_alice, _) = arrivals(
        started,
        (&alice, &bob_last),
        (&bob, &bob_last),
        &rooms[(posted_b.saturating_sub(1)) % rooms.len()],
        READY_WITHIN + worked,
    );
    let (_, to_bob) = arrivals(
        started,
        (&alice, &alice_last),
        (&bob, &alice_last),
        &rooms[(posted_a.saturating_sub(1)) % rooms.len()],
        READY_WITHIN + worked,
    );
    let (_, alice_status, _) = vox(&alice, &["status", "--json"], None);
    let (_, bob_status, _) = vox(&bob, &["status", "--json"], None);
    println!(
        "[proof] over {worked:?} alice posted {posted_a} ({refused_a} refused) and bob {posted_b} \
         ({refused_b} refused) into {WORK_ROOMS} rooms; CPU time: alice's daemon +{:?}, bob's \
         +{:?} (bound {WORK_CPU:?}); {} status answers, slowest {slowest:?} (bound \
         {ANSWER_WITHIN:?}); last posts read: alice {to_alice:?}, bob {to_bob:?}; alice's lanes: {}; \
         bob's lanes: {}",
        spent.0,
        spent.1,
        answers.len(),
        lanes_of(&alice_status),
        lanes_of(&bob_status)
    );
    assert!(
        refused_a == 0 && refused_b == 0 && posted_a >= 30 && posted_b >= 30,
        "APPARATUS: the agents did not work as staged: alice posted {posted_a} ({refused_a} \
         refused), bob {posted_b} ({refused_b} refused)\nalice's daemon said: {}\nbob's daemon \
         said: {}",
        said(&alice, "alice"),
        said(&bob, "bob")
    );
    assert!(
        to_alice.is_some() && to_bob.is_some(),
        "PRODUCT: the agents' last posts were not read within {READY_WITHIN:?} of the end: alice \
         read bob's: {to_alice:?}, bob read alice's: {to_bob:?}\nalice's lanes: {}\nbob's lanes: \
         {}\nalice's daemon said: {}\nbob's daemon said: {}",
        lanes_of(&alice_status),
        lanes_of(&bob_status),
        said(&alice, "alice"),
        said(&bob, "bob")
    );
    assert!(
        spent.0 <= WORK_CPU && spent.1 <= WORK_CPU,
        "PRODUCT: a daemon with agents at work spent more CPU than a person should pay (ADR-038 \
         FX-15, #990): alice's daemon +{:?}, bob's +{:?} over {worked:?} (bound {WORK_CPU:?})\n\
         alice's daemon said: {}\nbob's daemon said: {}",
        spent.0,
        spent.1,
        said(&alice, "alice"),
        said(&bob, "bob")
    );
    assert!(
        slowest <= ANSWER_WITHIN,
        "PRODUCT: `vox status --json` answered in {slowest:?} while agents worked, over \
         {ANSWER_WITHIN:?} (ADR-038 FX-17); every answer: {answers:?}"
    );
}

/// How long one run of the shipped hook (`vox agent hook`) has to finish, news printed, the way a
/// harness waits for it. Inside, the hook gives the daemon's control socket 500 ms for its
/// greeting (`HOOK_WITHIN`, `daemon_client.rs`) and says "the vox daemon here did not answer
/// promptly" past that; this proof reads that sentence, never the constant.
const HOOK_RUN_WITHIN: Duration = Duration::from_secs(2);
/// The hook's own words for a daemon that did not answer within its wait.
const HOOK_UNANSWERED: &str = "did not answer promptly";
/// Hook runs during the load, a quarter second apart: about a minute of a harness at work, the
/// time a late joiner's live window and the pages below it take to arrive (ADR-037 R1).
const HOOK_RUNS: usize = 200;
/// How long the room's count in `vox status --json` must have held still (every reading the same)
/// before it is compared with a paged read: the pages bob asked for last are let land. Apparatus
/// only: the count is read from the status, never waited into agreement with the rows.
const COUNT_STILL_FOR: Duration = Duration::from_secs(1);
/// Within this of the hook runs' end the count MUST have held still for [`COUNT_STILL_FOR`]; a
/// count that never holds still is staging not achieved, not a verdict.
const COUNT_STILL_WITHIN: Duration = Duration::from_secs(10);

/// **The daemon answers the harness hook while it syncs** (ADR-038 FX-17; #981): alice holds a
/// room with a [`BACKLOG`] of posts; bob joins, asks for the pages below his window as a reader
/// paging back does (`--history older`, ADR-037 R1: history on demand), and his daemon fetches
/// them while alice keeps posting; during that fetch bob's harness hook (`vox agent hook`, the
/// shipped binary, fed a Claude Code `UserPromptSubmit` event) runs [`HOOK_RUNS`] times. Every run MUST finish within
/// [`HOOK_RUN_WITHIN`] and MUST NOT say the daemon did not answer promptly; the fetch MUST be
/// real (bob's held entries grow across the runs) and alice's posts MUST all be accepted, so the
/// load is the product's, not a refusal's. Measured 2026-10-20 on the decider's work Mac
/// (v0.4.7, four nodes working): `vox status` answered in 0.5 s and the hook said "did not
/// answer promptly" twice in one session.
///
/// **`vox status` counts the rows bob reads** (ADR-038 FX-16; #995): once the runs are over and
/// the room's count in bob's `vox status --json` has held still for [`COUNT_STILL_FOR`],
/// `rooms[].entries` MUST equal, exactly, the rows one paged `vox room read --json` of the room
/// then pages. Found 2026-10-20 in this staging: bob read 14, 32, …, 115 rows as the minute went
/// on while `vox status` said 2, then 5: the length of his contiguous feed, which a late
/// joiner's rows lie below.
///
/// Mutants: the control acceptor made to wait on the actor's turn (a sleep past 500 ms in the
/// hook's greeting path) turns the first assertion red on the hook's own sentence; the
/// contiguous feed's length restored as the room's count (`entry_count()` in `summary_of`)
/// turns the FX-16 claim red on its two numbers.
#[cfg(feature = "optional-proofs")]
#[test]
#[ignore = "a timing bound a person feels; two real vox daemons; optional, run it in release"]
fn a_daemon_answers_the_hook_while_syncing() {
    watchdog::arm_for_setup(1, 8);
    let tmp = tempfile::tempdir().unwrap_or_else(|e| panic!("APPARATUS: no temp dir: {e}"));
    let root = tmp.path();
    let alice = root.join("alice");
    let bob = root.join("bob");
    let work = root.join("work");
    for d in [&alice, &bob, &work] {
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
        &["room", "create", "--passphrase-file", "-", "--name", "busy"],
        Some(&format!("{ROOMPASS}\n")),
    );
    assert!(
        ok,
        "PRODUCT: `vox room create` failed: {err}\nalice's daemon said: {}",
        said(&alice, "alice")
    );
    let listed = attached(&alice, "alice");
    let room = listed
        .split_whitespace()
        .find(|w| w.len() >= 8 && w.chars().all(|c| c.is_ascii_alphanumeric()))
        .unwrap_or_else(|| panic!("PRODUCT: `vox room list` shows no room id: {listed}"))
        .to_owned();
    // ---- the backlog bob will have to fetch ---------------------------------------------------
    for i in 1..=BACKLOG {
        let (ok, out, err) = vox(&alice, &["room", "post", &room, &format!("post {i}")], None);
        assert!(ok, "PRODUCT: alice's post {i} was refused: {out}{err}");
    }
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
    let held_at_join = held(&bob, &room, PAGE).order.len();
    // Bob pages back through the backlog while the hook runs: each page below his oldest row is
    // asked for on demand, as the TUI or a reader does, so his daemon's lane is fetching.
    let paging = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
    let pager = {
        let paging = paging.clone();
        let bob = bob.clone();
        let room = room.clone();
        std::thread::spawn(move || {
            let mut asked = 0usize;
            while paging.load(std::sync::atomic::Ordering::Relaxed) {
                if let Some(oldest) = held(&bob, &room, PAGE).oldest {
                    let _ = vox(
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
                    asked += 1;
                }
                std::thread::sleep(Duration::from_millis(500));
            }
            asked
        })
    };

    // ---- alice keeps posting while bob fetches, and bob's hook runs as a harness runs it --------
    let burst_room = room.clone();
    let burst_dir = alice.clone();
    let burst = std::thread::spawn(move || {
        let mut refused = Vec::new();
        for i in 1..=40 {
            let (ok, out, err) = vox(
                &burst_dir,
                &["room", "post", &burst_room, &format!("live {i}")],
                None,
            );
            if !ok {
                refused.push(format!("live {i}: {out}{err}"));
            }
        }
        refused
    });
    let event = serde_json::json!({
        "session_id": "hook-under-load",
        "transcript_path": work.join("transcript.jsonl").display().to_string(),
        "cwd": work.display().to_string(),
        "permission_mode": "default",
        "hook_event_name": "UserPromptSubmit",
        "prompt": "status?",
    })
    .to_string();
    let mut runs: Vec<(Duration, bool, String)> = Vec::new();
    let mut held_during = Vec::new();
    for _ in 0..HOOK_RUNS {
        let asked = Instant::now();
        let mut child = Command::new(VOX)
            // Bob's data root holds the node `vox id` made, the default one; the hook must name
            // it, or it answers with setup words without ever asking the daemon.
            .args(["agent", "hook", "--node", "default", "--room", &room])
            .env("VOX_DATA_DIR", &bob)
            .env("VOX_CONFIG_DIR", bob.join("cfg"))
            .env("CLAUDE_CODE_ENTRYPOINT", "cli")
            .env_remove("VOX_ROOM")
            .env_remove("VOX_NODE")
            .current_dir(&work)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap_or_else(|e| panic!("APPARATUS: cannot start `vox agent hook`: {e}"));
        if let Some(mut pipe) = child.stdin.take() {
            let _ = pipe.write_all(event.as_bytes());
        }
        let out = child
            .wait_with_output()
            .unwrap_or_else(|e| panic!("APPARATUS: `vox agent hook`: {e}"));
        let took = asked.elapsed();
        let said = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        runs.push((took, out.status.success(), said));
        if runs.len().is_multiple_of(20) {
            held_during.push(held(&bob, &room, PAGE).order.len());
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    paging.store(false, std::sync::atomic::Ordering::Relaxed);
    let pages_asked = pager
        .join()
        .unwrap_or_else(|_| panic!("APPARATUS: the paging thread panicked"));
    let refused = burst
        .join()
        .unwrap_or_else(|_| panic!("APPARATUS: the burst thread panicked"));
    let held_after = held(&bob, &room, PAGE).order.len();
    let slowest = runs.iter().map(|(d, _, _)| *d).max().unwrap_or_default();
    // The hook must have talked to the daemon: its output names the room or its news, never
    // nothing. Without this the timing claim could pass on a hook that never asked.
    let first_said = runs
        .first()
        .map(|(_, _, said)| said.trim().chars().take(240).collect::<String>())
        .unwrap_or_default();
    let last_said = runs
        .last()
        .map(|(_, _, said)| said.trim().chars().take(240).collect::<String>())
        .unwrap_or_default();
    println!("[proof] the first hook run said: {first_said:?}; the last: {last_said:?}");
    // A run with nothing new prints nothing, by design; so vacuity is caught by the words a
    // run does print (setup words mean it never asked) and by the room's news being named at
    // least once below, after the product claims.
    let setup_words = ["has no Vox node", "is Locked", "vox setup", "not attached"];
    let staged_wrong: Vec<&String> = runs
        .iter()
        .map(|(_, _, said)| said)
        .filter(|said| setup_words.iter().any(|w| said.contains(w)))
        .collect();
    assert!(
        staged_wrong.is_empty(),
        "APPARATUS: {} hook run(s) answered with setup words instead of asking bob's daemon, \
         so this proof measured nothing; the first: {:?}",
        staged_wrong.len(),
        staged_wrong[0].trim().chars().take(240).collect::<String>()
    );
    let unanswered: Vec<usize> = runs
        .iter()
        .enumerate()
        .filter(|(_, (_, _, said))| said.contains(HOOK_UNANSWERED))
        .map(|(i, _)| i)
        .collect();
    println!(
        "[proof] bob held {held_at_join} rows at his join, {held_after} after {HOOK_RUNS} hook runs \
         ({} during them, {pages_asked} pages asked for); alice's 40 live posts: {} refused; hook \
         runs: slowest {slowest:?} (bound {HOOK_RUN_WITHIN:?}), {} said \"{HOOK_UNANSWERED}\"",
        held_during
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(","),
        refused.len(),
        unanswered.len()
    );
    if held_after <= held_at_join + 32 {
        // Not the claim under test, but the red must say whose fault: what each daemon's lanes
        // did meanwhile, and whether bob's room is still preparing.
        let (_, bob_rooms, _) = vox(&bob, &["room", "list"], None);
        let status_rows = status_rows(&bob, &room);
        let (_, bob_status, _) = vox(&bob, &["status", "--json"], None);
        let (_, alice_status, _) = vox(&alice, &["status", "--json"], None);
        panic!(
            "PRODUCT: a late joiner's fetch did not run while the harness hook ran: bob held \
             {held_at_join} rows at his join and {held_after} after {HOOK_RUNS} hook runs over \
             {:?}, with {pages_asked} pages asked for and alice's 40 live posts accepted (needs 32 \
             more rows for the fetch to count as under way); `vox status` counts {status_rows:?} \
             rows\nbob's rooms: {}\nbob's lanes: {}\n\
             alice's lanes: {}\nbob's daemon said: {}\nalice's daemon said: {}",
            runs.iter().map(|(d, _, _)| *d).sum::<Duration>(),
            bob_rooms.trim(),
            lanes_of(&bob_status),
            lanes_of(&alice_status),
            said(&bob, "bob"),
            said(&alice, "alice")
        );
    }
    assert!(
        refused.is_empty(),
        "PRODUCT: alice's live posts were refused while bob fetched: {refused:?}\nalice's daemon \
         said: {}",
        said(&alice, "alice")
    );
    assert!(
        unanswered.is_empty(),
        "PRODUCT: the harness hook said the daemon \"{HOOK_UNANSWERED}\" while it synced (ADR-038 \
         FX-17), runs {unanswered:?} of {HOOK_RUNS}: {}\nbob's daemon said: {}",
        runs[unanswered[0]].2.trim(),
        said(&bob, "bob")
    );
    assert!(
        runs.iter()
            .any(|(_, _, said)| said.contains(&format!("In room busy ({room})"))),
        "APPARATUS: no hook run named the room's news, so the hook never read bob's room; \
         the first said {first_said:?}"
    );
    let failed: Vec<String> = runs
        .iter()
        .filter(|(_, ok, _)| !ok)
        .map(|(_, _, said)| said.trim().to_owned())
        .collect();
    assert!(
        failed.is_empty(),
        "PRODUCT: the harness hook exited non-zero while the daemon synced: {failed:?}"
    );
    assert!(
        slowest <= HOOK_RUN_WITHIN,
        "PRODUCT: a harness hook run took {slowest:?} while the daemon synced, over \
         {HOOK_RUN_WITHIN:?}; every run: {:?}\nbob's daemon said: {}",
        runs.iter().map(|(d, _, _)| *d).collect::<Vec<_>>(),
        said(&bob, "bob")
    );

    // ---- `vox status` counts the rows bob reads (ADR-038 FX-16; #995) ------------------------
    // The fetch is let settle first: the room's count is read until every reading over
    // [`COUNT_STILL_FOR`] is the same, within [`COUNT_STILL_WITHIN`] (else staging not
    // achieved). Then the room is paged once, and the still count MUST equal the rows paged,
    // exactly. One more reading after the page tells a page that landed between the still count
    // and the read (apparatus) from a count that is not the rows (product).
    let settling = Instant::now();
    let mut still_since = Instant::now();
    let mut counted = status_rows(&bob, &room);
    loop {
        let Some(count) = counted else {
            let (_, status, err) = vox(&bob, &["status", "--json"], None);
            panic!(
                "PRODUCT: bob's `vox status --json` does not count the room's rows under \
                 rooms[].entries (ADR-038 FX-16, #995); it said: {status}{err}"
            );
        };
        if still_since.elapsed() >= COUNT_STILL_FOR {
            break;
        }
        assert!(
            settling.elapsed() < COUNT_STILL_WITHIN,
            "APPARATUS: staging not achieved: bob's `vox status --json` count for the room did \
             not hold still for {COUNT_STILL_FOR:?} within {COUNT_STILL_WITHIN:?} of the hook \
             runs' end; it last said {count}"
        );
        std::thread::sleep(Duration::from_millis(250));
        let again = status_rows(&bob, &room);
        if again != counted {
            counted = again;
            still_since = Instant::now();
        }
    }
    let counted = counted.unwrap_or(0);
    let paged = held(&bob, &room, PAGE).rows as u64;
    let counted_after = status_rows(&bob, &room);
    println!(
        "[proof] ADR-038 FX-16 / #995: bob's `vox status --json` counted {counted} rows for the \
         room, still for {COUNT_STILL_FOR:?}; `vox room read --json` then paged {paged}; the \
         count read again: {counted_after:?}"
    );
    if paged != counted && counted_after == Some(paged) {
        panic!(
            "APPARATUS: staging not achieved: a page landed between the still count and the \
             read: bob's `vox status --json` counted {counted} rows, `vox room read --json` paged \
             {paged}, and the count read again was {paged}"
        );
    }
    assert!(
        paged == counted,
        "PRODUCT: `vox status --json` does not count the rows bob reads (ADR-038 FX-16, #995): \
         rooms[].entries said {counted} (still for {COUNT_STILL_FOR:?}) and {counted_after:?} \
         after, while `vox room read --json` paged {paged} rows of the room"
    );
}

/// What `vox status --json` counts for the room under `rooms[].entries`: the rows the node shows
/// of it (ADR-038 FX-16, #995). `None` when the status cannot be read or does not list the room.
fn status_rows(dir: &Path, room: &str) -> Option<u64> {
    let (ok, out, _) = vox(dir, &["status", "--json"], None);
    if !ok {
        return None;
    }
    serde_json::from_str::<serde_json::Value>(&out).ok()?["rooms"]
        .as_array()?
        .iter()
        .find(|r| r["id"].as_str().is_some_and(|id| id.starts_with(room)))?["entries"]
        .as_u64()
}

/// `vox room list` MUST name what a preparing room waits for within this of the daemon's start.
const WAIT_NAMED_WITHIN: Duration = Duration::from_secs(5);
/// How long the held room is watched doing nothing.
const PREPARING_IDLE: Duration = Duration::from_secs(60);
/// CPU time the daemon may spend over [`PREPARING_IDLE`] on a room that only waits: Activity
/// Monitor's number. Measured before (#991): the room was re-queued every 50 ms, for hours.
const PREPARING_CPU: Duration = Duration::from_secs(3);
/// Once the wait ends, the room MUST open within this (the retry is once a second).
const OPENS_WITHIN: Duration = Duration::from_secs(10);
/// Sync rounds the waiting room's daemon may complete toward one peer over [`PREPARING_IDLE`]:
/// the periodic request's, and nothing else (FX-15); measured 0.
const PREPARING_ROUNDS: u64 = 2;

/// A room that cannot finish preparing says what it waits for, costs nothing while it waits, and
/// opens once the wait ends (ADR-038 FX-15, FX-16; #991). Staged with the fold-hold knob: alice
/// posts into her room, the hold file appears, she posts three more rows (accepted, not folded),
/// her daemon is stopped and started again with the hold still in place, so the room cannot
/// finish preparing. Within [`WAIT_NAMED_WITHIN`] `vox room list` MUST say `[preparing history:
/// waiting for …]`, `vox status --json` MUST list the room under `preparing` with the same words,
/// and `vox room read` MUST refuse with them; over [`PREPARING_IDLE`] the daemon's CPU time MUST
/// grow by at most [`PREPARING_CPU`] and its log MUST say once what the room waited for; once the
/// hold file is removed the room MUST open within [`OPENS_WITHIN`] and its six rows read.
/// Found 2026-10-20 on the decider's work Mac (v0.4.7): a room stayed "[preparing history]" for
/// 20 hours with no words anywhere, re-queued every 50 ms, absent from `vox status`.
///
/// Mutant: the governance wait left unnamed (`wait_on` not called for it in
/// `retention_before_publication`, actor.rs) turns the first claim red on `vox room list`'s line.
#[cfg(feature = "optional-proofs")]
#[test]
#[ignore = "a minute of a real vox daemon holding a room, and a test-only knob; optional, run it in release"]
fn a_room_that_cannot_finish_preparing_says_why_and_costs_nothing() {
    test_knobs::require(&["VOX_TEST_FOLD_HOLD_FILE"]);
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap_or_else(|e| panic!("APPARATUS: no temp dir: {e}"));
    let root = tmp.path();
    let alice = root.join("alice");
    let bob = root.join("bob");
    for d in [&alice, &bob] {
        std::fs::create_dir_all(d.join("cfg"))
            .unwrap_or_else(|e| panic!("APPARATUS: could not create {}: {e}", d.display()));
    }
    let hold = root.join("fold-hold");
    let hold_path = hold
        .to_str()
        .expect("APPARATUS: a UTF-8 temp path")
        .to_owned();
    let knob = [("VOX_TEST_FOLD_HOLD_FILE", hold_path.as_str())];
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

    // ---- staging: alice's room with three rows; bob joins; three of bob's rows arrive while
    // alice's fold is held, so they are accepted but not folded (a node's own posts fold as
    // they are accepted, so only a peer's rows can leave governance unsettled) ---------------
    let first = daemon_env(&alice, "alice", &knob);
    attached(&alice, "alice");
    let (ok, _, err) = vox(
        &alice,
        &["room", "create", "--passphrase-file", "-", "--name", "held"],
        Some(&format!("{ROOMPASS}\n")),
    );
    assert!(
        ok,
        "PRODUCT: `vox room create` failed: {err}\nalice's daemon said: {}",
        said(&alice, "alice")
    );
    let listed = attached(&alice, "alice");
    let room = listed
        .split_whitespace()
        .find(|w| w.len() >= 8 && w.chars().all(|c| c.is_ascii_alphanumeric()))
        .unwrap_or_else(|| panic!("PRODUCT: `vox room list` shows no room id: {listed}"))
        .to_owned();
    for i in 1..=3 {
        let (ok, out, err) = vox(&alice, &["room", "post", &room, &format!("row {i}")], None);
        assert!(ok, "PRODUCT: alice's post {i} was refused: {out}{err}");
    }
    let (ok, link, err) = vox(&alice, &["room", "link", &room], None);
    assert!(ok, "PRODUCT: `vox room link` failed: {err}");
    let link = link.trim().to_owned();
    // The hold comes before bob joins: his admission is a governance record alice receives
    // but cannot fold while held (ordinary posts never go through the fold).
    std::fs::write(&hold, b"").expect("APPARATUS: write the hold file");
    let _bob_daemon = daemon(&bob, "bob");
    attached(&bob, "bob");
    let (ok, _, err) = vox(
        &bob,
        &["room", "join", "--passphrase-file", "-", &link],
        Some(&format!("{ROOMPASS}\n")),
    );
    assert!(ok, "PRODUCT: bob's `vox room join` was refused: {err}");
    for i in 4..=6 {
        let (ok, out, err) = vox(&bob, &["room", "post", &room, &format!("row {i}")], None);
        assert!(ok, "PRODUCT: bob's post {i} was refused: {out}{err}");
    }
    // Give alice's daemon time to receive bob's records (it cannot fold them while held).
    std::thread::sleep(Duration::from_secs(8));
    first.stop();

    // ---- the room cannot finish preparing: the daemon says what it waits for ----------------
    let restarted_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let second = daemon_env(&alice, "alice", &knob);
    let started = Instant::now();
    let line = loop {
        let (ok, out, _) = vox(&alice, &["room", "list"], None);
        let line = out
            .lines()
            .find(|l| l.trim_start().starts_with(&room))
            .map(str::to_owned)
            .unwrap_or_default();
        if ok && line.contains("[preparing history: waiting for ") {
            // The wait a held fold of a peer's records produces, in the words of this change.
            assert!(
                line.contains("waiting for governance records from its members"),
                "PRODUCT: `vox room list` names another wait than the held governance fold \
                 (#991): {line}"
            );
            break line;
        }
        if ok && !line.is_empty() && !line.contains("[preparing") {
            panic!(
                "APPARATUS: the fold-hold knob did not hold the room, it opened: `vox room list` says {line}"
            );
        }
        assert!(
            started.elapsed() < WAIT_NAMED_WITHIN,
            "PRODUCT: `vox room list` does not say what the preparing room waits for within \
             {WAIT_NAMED_WITHIN:?} (ADR-038 FX-16, #991): {line:?}\nalice's daemon said: {}",
            said(&alice, "alice")
        );
        std::thread::sleep(Duration::from_millis(200));
    };
    println!(
        "[proof] {:?} after the daemon's start, `vox room list` said: {line}",
        started.elapsed()
    );
    let (ok, status, err) = vox(&alice, &["status", "--json"], None);
    assert!(
        ok,
        "PRODUCT: `vox status --json` failed while a room prepared: {err}"
    );
    let status: serde_json::Value = serde_json::from_str(&status)
        .unwrap_or_else(|e| panic!("PRODUCT: `vox status --json` is not JSON: {e}: {status}"));
    let entry = status["preparing"]
        .as_array()
        .and_then(|rooms| {
            rooms
                .iter()
                .find(|r| r["id"].as_str().is_some_and(|id| id.starts_with(&room)))
        })
        .unwrap_or_else(|| {
            panic!(
                "PRODUCT: `vox status --json` does not list the preparing room under `preparing` \
                 (ADR-038 FX-16, #991): {}",
                status["preparing"]
            )
        });
    let what = entry["waiting"]
        .as_str()
        .unwrap_or_else(|| {
            panic!("PRODUCT: `vox status --json` names no wait for the room: {entry}")
        })
        .to_owned();
    let since_ms = entry["since_ms"].as_u64().unwrap_or_else(|| {
        panic!("PRODUCT: `vox status --json` dates no wait for the room: {entry}")
    });
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    assert!(
        line.contains(&what) && (restarted_ms..=now_ms).contains(&since_ms),
        "PRODUCT: `vox status --json` ({entry}) and `vox room list` ({line}) do not say the same \
         wait, or its start {since_ms} is not between the daemon's restart {restarted_ms} and now \
         {now_ms}"
    );
    let (ok, out, err) = vox(&alice, &["room", "read", &room], None);
    assert!(
        !ok && format!("{out}{err}").contains(&format!("it waits for {what}")),
        "PRODUCT: `vox room read` of a preparing room does not say the wait the status names \
         ({what:?}) (#991): ok={ok} {out}{err}"
    );
    // The daemon's own refusal says it too: a post, which the CLI does not pre-check.
    let (ok, out, err) = vox(
        &alice,
        &["room", "post", &room, "a word while it prepares"],
        None,
    );
    assert!(
        !ok && format!("{out}{err}").contains(&format!("it waits for {what}")),
        "PRODUCT: the daemon's refusal of a post into a preparing room does not say the wait the \
         status names ({what:?}) (#991): ok={ok} {out}{err}"
    );
    // Rounds per peer over the idle minute (FX-15): the periodic request is the only cadence.
    let rounds_before = completed_rounds(&alice);

    // ---- the wait costs nothing -------------------------------------------------------------
    let pid = second.0.id();
    let cpu0 = cpu_time(pid);
    std::thread::sleep(PREPARING_IDLE);
    let spent = cpu_time(pid).saturating_sub(cpu0);
    let rounds_after = completed_rounds(&alice);
    // A room that is not open has no lane: no round can run toward anyone while it waits, and
    // alice holds no other room. A lane here, or a round on it, is a round without a need.
    assert!(
        rounds_before.is_empty() && rounds_after.is_empty(),
        "PRODUCT: alice's daemon ran sync lanes while its only room waited to open (ADR-038 \
         FX-15, #991): before {rounds_before:?}, after {rounds_after:?}; lanes: {}",
        lanes_of(&vox(&alice, &["status", "--json"], None).1)
    );
    let per_peer: Vec<(String, u64)> = rounds_after
        .iter()
        .map(|(peer, after)| {
            (
                peer.clone(),
                after.saturating_sub(*rounds_before.get(peer).unwrap_or(&0)),
            )
        })
        .collect();
    let rounds: u64 = per_peer.iter().map(|(_, n)| *n).max().unwrap_or(0);
    let log = std::fs::read_to_string(alice.join(".daemon/log")).unwrap_or_default();
    let noted: Vec<&str> = log
        .lines()
        .filter(|l| l.contains("is still preparing: it waits for "))
        .collect();
    println!(
        "[proof] over {PREPARING_IDLE:?} the held room cost the daemon +{spent:?} of CPU (bound {PREPARING_CPU:?}) and {rounds} completed sync round(s) (bound {PREPARING_ROUNDS}); its log says: {noted:?}"
    );
    assert!(
        per_peer.iter().all(|(_, n)| *n <= PREPARING_ROUNDS),
        "PRODUCT: a room that only waited ran sync rounds toward a peer in {PREPARING_IDLE:?} beyond \
         the periodic request (ADR-038 FX-15, #991): {per_peer:?} (at most {PREPARING_ROUNDS} each); lanes: {}",
        lanes_of(&vox(&alice, &["status", "--json"], None).1)
    );
    assert!(
        spent <= PREPARING_CPU,
        "PRODUCT: a room that only waited cost the daemon {spent:?} of CPU over {PREPARING_IDLE:?} \
         (ADR-038 FX-15, #991; bound {PREPARING_CPU:?})"
    );
    assert!(
        noted.len() == 1 && noted[0].contains(&format!("it waits for {what}")),
        "PRODUCT: after {PREPARING_IDLE:?} the daemon's log must say exactly once what the room \
         waits for ({what:?}) (#991); it said {} time(s):\n{log}",
        noted.len()
    );

    // ---- the wait ends: the room opens and its six rows read ---------------------------------
    std::fs::remove_file(&hold).expect("APPARATUS: remove the hold file");
    let released = Instant::now();
    loop {
        let (ok, out, _) = vox(&alice, &["room", "list"], None);
        let line = out
            .lines()
            .find(|l| l.trim_start().starts_with(&room))
            .map(str::to_owned)
            .unwrap_or_default();
        if ok && !line.is_empty() && !line.contains("[preparing") {
            println!(
                "[proof] {:?} after the hold ended, `vox room list` said: {line}",
                released.elapsed()
            );
            break;
        }
        assert!(
            released.elapsed() < OPENS_WITHIN,
            "PRODUCT: the room did not open within {OPENS_WITHIN:?} after its wait ended (#991): {line:?}\nalice's daemon said: {}",
            said(&alice, "alice")
        );
        std::thread::sleep(Duration::from_millis(200));
    }
    // Bob's admission folds and his three rows arrive: alice reads all six.
    let opened = Instant::now();
    loop {
        let (ok, out, err) = vox(&alice, &["room", "read", &room], None);
        if ok && (1..=6).all(|i| out.contains(&format!("row {i}"))) {
            break;
        }
        assert!(
            opened.elapsed() < Duration::from_secs(60),
            "PRODUCT: the opened room does not read all six rows within 60 s: ok={ok}\n{out}{err}\nalice's daemon said: {}",
            said(&alice, "alice")
        );
        std::thread::sleep(Duration::from_millis(500));
    }
    // FX-16: the round that brought bob's rows is recorded as the room's and bob's last
    // completed sync.
    let synced = Instant::now();
    loop {
        let (ok, out, _) = vox(&alice, &["status", "--json"], None);
        let v: serde_json::Value = if ok {
            serde_json::from_str(&out).unwrap_or_default()
        } else {
            serde_json::Value::Null
        };
        // Newer than the restart: the round that brought bob's rows, not one from the staging;
        // and the lane toward bob now exists and completed it.
        let bobs_lane = v["sync"].as_array().is_some_and(|lanes| {
            lanes.iter().any(|l| {
                l["peer"]
                    .as_str()
                    .is_some_and(|p| p.starts_with(&fps[1][..12]))
                    && l["completed"].as_u64().is_some_and(|n| n > 0)
            })
        });
        let recorded = bobs_lane
            && v["rooms"].as_array().is_some_and(|rooms| {
                rooms.iter().any(|r| {
                    r["id"].as_str().is_some_and(|id| id.starts_with(&room))
                        && r["last_sync_ms"].as_u64().is_some_and(|t| t > restarted_ms)
                        && r["members"].as_array().is_some_and(|ms| {
                            ms.iter().any(|m| {
                                m["me"] == false
                                    && m["last_sync_ms"].as_u64().is_some_and(|t| t > restarted_ms)
                            })
                        })
                })
            });
        if recorded {
            break;
        }
        assert!(
            synced.elapsed() < Duration::from_secs(30),
            "PRODUCT: after the room opened and bob's rows arrived, `vox status --json` records no \
             last completed sync for the room and for bob (ADR-038 FX-16, #991): {}",
            lanes_of(&out)
        );
        std::thread::sleep(Duration::from_millis(500));
    }
    drop(second);
}

/// Completed sync rounds per peer, from `vox status --json`'s lanes; an unreadable status is
/// an apparatus fault, never a zero that reads as quiet.
fn completed_rounds(dir: &Path) -> std::collections::BTreeMap<String, u64> {
    let (ok, out, err) = vox(dir, &["status", "--json"], None);
    assert!(
        ok,
        "APPARATUS: `vox status --json` failed while counting rounds: {err}"
    );
    let v: serde_json::Value = serde_json::from_str(&out)
        .unwrap_or_else(|e| panic!("APPARATUS: `vox status --json` is not JSON: {e}: {out}"));
    let lanes = v["sync"]
        .as_array()
        .unwrap_or_else(|| panic!("APPARATUS: `vox status --json` has no `sync` lanes: {out}"));
    let mut rounds = std::collections::BTreeMap::new();
    for lane in lanes {
        let peer = lane["peer"]
            .as_str()
            .unwrap_or_else(|| panic!("APPARATUS: a lane names no peer: {lane}"))
            .to_owned();
        let completed = lane["completed"]
            .as_u64()
            .unwrap_or_else(|| panic!("APPARATUS: a lane counts no completed rounds: {lane}"));
        *rounds.entry(peer).or_insert(0) += completed;
    }
    rounds
}

/// A room with this node's own Session records opens again after a restart, within this.
const REOPENS_WITHIN: Duration = Duration::from_secs(20);

/// A room restored with pending private-Session work opens again after the daemon restarts
/// (ADR-038 FX-24, FX-26; #991). Staged as the decider's room was: bob is a member alice's
/// governance has folded; her private-Session policy is held not ready (the
/// `VOX_TEST_PRIVATE_POLICY_HOLD_FILE` knob, as a Session-floor index behind its authors' heads
/// holds it at a restart) while bob opens a Session through the shipped hook (an older prefix
/// of his controls reaches her) and lets her drive (his drive key arrives; the pass it schedules
/// is saved as pending and not run). Her daemon stops; his Session goes on while she is down
/// (newer controls she lacks); the hold is lifted; her daemon starts again. The room MUST open
/// within [`REOPENS_WITHIN`], `vox room read` MUST show her rows, within 30 s `vox room
/// sessions --json` MUST list bob's Session as one she can drive, and the daemon MUST stay quiet.
///
/// Mutant: the preparation and the refresh wait on every pending Session state again
/// (`needs_session_upgrade`, as v0.4.8 did); the run that pins it is reported with the proof.
#[cfg(feature = "optional-proofs")]
#[test]
#[ignore = "two starts of a real vox daemon, a second daemon, the shipped hook and a test-only knob; optional, run it in release"]
fn a_room_with_its_own_session_records_opens_after_a_restart() {
    test_knobs::require(&["VOX_TEST_PRIVATE_POLICY_HOLD_FILE"]);
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap_or_else(|e| panic!("APPARATUS: no temp dir: {e}"));
    let root = tmp.path();
    let alice = root.join("alice");
    let bob = root.join("bob");
    let work = root.join("work");
    for d in [&alice, &bob, &work] {
        std::fs::create_dir_all(d.join("cfg"))
            .unwrap_or_else(|e| panic!("APPARATUS: could not create {}: {e}", d.display()));
    }
    let hold = root.join("hold-policy");
    let hold_path = hold
        .to_str()
        .expect("APPARATUS: a UTF-8 temp path")
        .to_owned();
    let knob = [("VOX_TEST_PRIVATE_POLICY_HOLD_FILE", hold_path.as_str())];
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

    // ---- staging: alice's room with three rows; bob joins, his room opens, alice folds him in
    let first = daemon_env(&alice, "alice", &knob);
    attached(&alice, "alice");
    let (ok, _, err) = vox(
        &alice,
        &[
            "room",
            "create",
            "--passphrase-file",
            "-",
            "--name",
            "sessions",
        ],
        Some(&format!("{ROOMPASS}\n")),
    );
    assert!(
        ok,
        "PRODUCT: `vox room create` failed: {err}\nalice's daemon said: {}",
        said(&alice, "alice")
    );
    let listed = attached(&alice, "alice");
    let room = listed
        .split_whitespace()
        .find(|w| w.len() >= 8 && w.chars().all(|c| c.is_ascii_alphanumeric()))
        .unwrap_or_else(|| panic!("PRODUCT: `vox room list` shows no room id: {listed}"))
        .to_owned();
    for i in 1..=3 {
        let (ok, out, err) = vox(&alice, &["room", "post", &room, &format!("row {i}")], None);
        assert!(ok, "PRODUCT: alice's post {i} was refused: {out}{err}");
    }
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
    let staged = Instant::now();
    loop {
        let (ok, out, _) = vox(&bob, &["room", "list"], None);
        let line = out
            .lines()
            .find(|l| l.trim_start().starts_with(&room))
            .map(str::to_owned)
            .unwrap_or_default();
        let (ok2, roster, _) = vox(&alice, &["room", "roster", &room], None);
        if ok && !line.is_empty() && !line.contains("[preparing") && ok2 && roster.contains(&fps[1])
        {
            break;
        }
        assert!(
            staged.elapsed() < Duration::from_secs(30),
            "APPARATUS (staging): after 30 s bob's room is not open ({line:?}) or alice's \
             roster shows no bob ({roster:?})"
        );
        std::thread::sleep(Duration::from_millis(500));
    }
    // bob's harness session, through the shipped hook, with the prompt given.
    let hook = |prompt: &str| {
        let event = serde_json::json!({
            "session_id": "restart-proof",
            "transcript_path": work.join("transcript.jsonl").display().to_string(),
            "cwd": work.display().to_string(),
            "permission_mode": "default",
            "hook_event_name": "UserPromptSubmit",
            "prompt": prompt,
        })
        .to_string();
        let mut child = Command::new(VOX)
            .args(["agent", "hook", "--node", "default", "--room", &room])
            .env("VOX_DATA_DIR", &bob)
            .env("VOX_CONFIG_DIR", bob.join("cfg"))
            .env("CLAUDE_CODE_ENTRYPOINT", "cli")
            .env_remove("VOX_ROOM")
            .env_remove("VOX_NODE")
            .current_dir(&work)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap_or_else(|e| panic!("APPARATUS: cannot start `vox agent hook`: {e}"));
        if let Some(mut pipe) = child.stdin.take() {
            let _ = pipe.write_all(event.as_bytes());
        }
        let out = child
            .wait_with_output()
            .unwrap_or_else(|e| panic!("APPARATUS: `vox agent hook`: {e}"));
        let said = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            !["has no Vox node", "is Locked", "vox setup", "not attached"]
                .iter()
                .any(|w| said.contains(w)),
            "APPARATUS: bob's hook answered with setup words instead of joining the room: {said}"
        );
        std::thread::sleep(Duration::from_millis(500));
    };

    // ---- her private-Session policy is held not ready: bob's Session begins (an older prefix
    // of his controls reaches her, folded no further), then he lets her drive: his drive key
    // arrives and the pass it schedules is saved as pending and not run (the decider's daemon,
    // 2026-10-20: a peer's key at a restart, behind that peer's control receipts) ----------------
    std::fs::write(&hold, b"").expect("APPARATUS: write the hold file");
    std::thread::sleep(Duration::from_secs(1));
    hook("hello");
    hook("hello again");
    std::thread::sleep(Duration::from_secs(3));
    let (ok, _, err) = vox(&bob, &["trust", "drive", &fps[0]], None);
    assert!(
        ok,
        "PRODUCT: bob's `vox trust drive` of alice failed: {err}"
    );
    std::thread::sleep(Duration::from_secs(10));
    let drivable = |json: &str| json.lines().any(|l| l.contains("\"can_drive\":true"));
    // Precondition: alice's listing answers, and she drives no Session yet (the pass his key
    // scheduled did not run).
    let (ok, json, err) = vox(&alice, &["room", "sessions", &room, "--json"], None);
    assert!(
        ok,
        "APPARATUS (staging): `vox room sessions --json` refused while held: {json}{err}"
    );
    println!(
        "[proof] alice's Sessions while her policy is held: {}",
        json.trim()
    );
    assert!(
        !drivable(&json),
        "APPARATUS (staging): alice already drives a Session while her policy is held, so \
         nothing is left pending for the restart:\n{json}"
    );
    first.stop();
    std::fs::remove_file(&hold).expect("APPARATUS: remove the hold file");
    // While she is down, bob's Session goes on: newer control entries she will receive only once
    // her room is published again, so at her restart the pass his key scheduled waits behind a
    // receipt that preparation cannot fetch (ADR-037 R1).
    hook("and once more");
    std::thread::sleep(Duration::from_secs(2));

    // ---- the restart: the room prepares, says what it waits for, and opens ------------------
    let second = daemon_env(&alice, "alice", &knob);
    let started = Instant::now();
    let mut seen_waiting = Vec::new();
    loop {
        let (ok, out, _) = vox(&alice, &["room", "list"], None);
        let line = out
            .lines()
            .find(|l| l.trim_start().starts_with(&room))
            .map(str::to_owned)
            .unwrap_or_default();
        if ok && !line.is_empty() && !line.contains("[preparing") {
            println!(
                "[proof] {:?} after the restart the room is open: {line}; while it prepared it said: {seen_waiting:?}",
                started.elapsed()
            );
            break;
        }
        if line.contains("[preparing history: waiting for ") && seen_waiting.last() != Some(&line) {
            seen_waiting.push(line.clone());
        }
        assert!(
            started.elapsed() < REOPENS_WITHIN,
            "PRODUCT: a room restored with pending private-Session work did not open within \
             {REOPENS_WITHIN:?} of the restart (FX-24, FX-26; #991): {line:?}; it said while \
             preparing: {seen_waiting:?}\nalice's daemon said: {}",
            said(&alice, "alice")
        );
        std::thread::sleep(Duration::from_millis(200));
    }
    let (ok, out, err) = vox(&alice, &["room", "read", &room], None);
    assert!(
        ok && (1..=3).all(|i| out.contains(&format!("row {i}"))),
        "PRODUCT: the reopened room does not read its three rows: ok={ok}\n{out}{err}"
    );
    // Published, the room fetches bob's newer controls and runs the pending pass: his Session is
    // listed as one she can drive, within a person's patience.
    let opened = Instant::now();
    loop {
        let (ok, json, err) = vox(&alice, &["room", "sessions", &room, "--json"], None);
        if ok && drivable(&json) {
            println!(
                "[proof] {:?} after the room opened, alice can drive bob's Session",
                opened.elapsed()
            );
            break;
        }
        assert!(
            opened.elapsed() < Duration::from_secs(30),
            "PRODUCT: 30 s after the restart alice's room does not list bob's Session as one \
             she can drive (FX-26, #991): ok={ok}\n{json}{err}"
        );
        std::thread::sleep(Duration::from_millis(500));
    }
    let pid = second.0.id();
    let cpu0 = cpu_time(pid);
    std::thread::sleep(Duration::from_secs(10));
    let spent = cpu_time(pid).saturating_sub(cpu0);
    println!("[proof] 10 s after opening, the daemon's CPU grew by {spent:?}");
    assert!(
        spent <= Duration::from_secs(1),
        "PRODUCT: the daemon spent {spent:?} of CPU in 10 s with one open quiet room (FX-15, #991)"
    );
    drop(second);
}

/// Each lane of a `vox status --json`: peer, completed, partial, failed, running and its last failure.
fn lanes_of(status: &str) -> String {
    serde_json::from_str::<serde_json::Value>(status)
        .ok()
        .and_then(|v| {
            v["sync"].as_array().map(|lanes| {
                lanes
                    .iter()
                    .map(|l| {
                        format!(
                            "{}: completed {} partial {} failed {} running {} last_failure {}",
                            l["peer"]
                                .as_str()
                                .map(|p| &p[..p.len().min(12)])
                                .unwrap_or("?"),
                            l["completed"],
                            l["partial"],
                            l["failed"],
                            l["running"].as_array().map_or(0, Vec::len),
                            l["last_failure"]
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("; ")
            })
        })
        .unwrap_or_else(|| format!("(unreadable: {})", status.trim()))
}

/// A process's CPU time so far, as Activity Monitor shows it (`ps -o cputime`).
fn cpu_time(pid: u32) -> Duration {
    let out = Command::new("ps")
        .args(["-o", "cputime=", "-p", &pid.to_string()])
        .output()
        .unwrap_or_else(|e| panic!("APPARATUS: ps: {e}"));
    let text = String::from_utf8_lossy(&out.stdout).trim().to_owned();
    // MM:SS.ss or HH:MM:SS
    let mut parts: Vec<&str> = text.split(':').collect();
    let secs: f64 = parts.pop().and_then(|s| s.parse().ok()).unwrap_or(0.0);
    let mins: f64 = parts.pop().and_then(|s| s.parse().ok()).unwrap_or(0.0);
    let hours: f64 = parts.pop().and_then(|s| s.parse().ok()).unwrap_or(0.0);
    Duration::from_secs_f64(hours * 3600.0 + mins * 60.0 + secs)
}

/// One lane's counters as `vox status --json` shows them. A round is a round whichever way it
/// ended (ADR-038 FX-15): completed, partial (its requested entries unreceived) or failed;
/// `opened` and `admitted` grow for neither a hinted nor a periodic round and only tell
/// stillness, as `running` (sessions on the lane now) does.
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
struct LaneRounds {
    opened: u64,
    admitted: u64,
    completed: u64,
    empty: u64,
    fetched_completed: u64,
    fetched_empty: u64,
    served_completed: u64,
    served_empty: u64,
    history_fetched: u64,
    history_served: u64,
    history_declined: u64,
    history_offered: u64,
    history_rearmed: u64,
    partial: u64,
    failed: u64,
    running: u64,
}

impl LaneRounds {
    fn rounds(self) -> u64 {
        self.completed + self.partial + self.failed
    }

    /// The rounds since `before`, by how they ended.
    fn since(self, before: Self) -> Self {
        Self {
            completed: self.completed.saturating_sub(before.completed),
            empty: self.empty.saturating_sub(before.empty),
            fetched_completed: self
                .fetched_completed
                .saturating_sub(before.fetched_completed),
            fetched_empty: self.fetched_empty.saturating_sub(before.fetched_empty),
            served_completed: self
                .served_completed
                .saturating_sub(before.served_completed),
            served_empty: self.served_empty.saturating_sub(before.served_empty),
            history_fetched: self.history_fetched.saturating_sub(before.history_fetched),
            history_served: self.history_served.saturating_sub(before.history_served),
            history_declined: self
                .history_declined
                .saturating_sub(before.history_declined),
            history_offered: self.history_offered.saturating_sub(before.history_offered),
            history_rearmed: self.history_rearmed.saturating_sub(before.history_rearmed),
            partial: self.partial.saturating_sub(before.partial),
            failed: self.failed.saturating_sub(before.failed),
            ..Self::default()
        }
    }
}

/// What `vox status --json` shows of one node: its lanes (a room with a peer) and their
/// counters, its rooms and their members, whether every room and every other member carry a
/// last completed sync, and the raw status for a red.
struct Synced {
    lanes: BTreeMap<(String, String), LaneRounds>,
    rooms: BTreeMap<String, Vec<String>>,
    recorded: bool,
    status: String,
}

fn synced(dir: &Path, node: Option<&str>) -> Synced {
    let (ok, out, err) = vox(dir, &as_node(&["status", "--json"], node), None);
    assert!(ok, "PRODUCT: `vox status --json` failed: {err}");
    let v: serde_json::Value = serde_json::from_str(&out)
        .unwrap_or_else(|e| panic!("PRODUCT: `vox status --json` is not JSON: {e}: {out}"));
    let mut lanes: BTreeMap<(String, String), LaneRounds> = BTreeMap::new();
    for lane in v["sync"].as_array().into_iter().flatten() {
        let name = |k: &str| {
            lane[k]
                .as_str()
                .unwrap_or_else(|| {
                    panic!("PRODUCT: a lane of `vox status --json` names no {k}: {lane}")
                })
                .to_owned()
        };
        let n = |k: &str| {
            lane[k].as_u64().unwrap_or_else(|| {
                panic!("PRODUCT: a lane of `vox status --json` counts no {k}: {lane}")
            })
        };
        let room = name("room");
        let peer = name("peer");
        let l = lanes.entry((room.clone(), peer.clone())).or_default();
        l.opened += n("opened");
        l.admitted += n("admitted");
        l.completed += n("completed");
        l.empty += n("empty");
        l.fetched_completed += n("fetched_completed");
        l.fetched_empty += n("fetched_empty");
        l.served_completed += n("served_completed");
        l.served_empty += n("served_empty");
        l.history_fetched += n("history_fetched");
        l.history_served += n("history_served");
        l.history_declined += n("history_declined");
        l.history_offered += n("history_offered");
        l.history_rearmed += n("history_rearmed");
        l.partial += n("partial");
        l.failed += n("failed");
        l.running += lane["running"].as_array().map_or(0, Vec::len) as u64;
    }
    let rooms: BTreeMap<String, Vec<String>> = v["rooms"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|r| {
            let id = r["id"]
                .as_str()
                .unwrap_or_else(|| panic!("PRODUCT: a room of `vox status --json` has no id: {r}"))
                .to_owned();
            let members = r["members"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|m| m["id"].as_str().map(str::to_owned))
                .collect();
            (id, members)
        })
        .collect();
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
    Synced {
        lanes,
        rooms,
        recorded,
        status: out,
    }
}

fn lane_rounds(synced: &Synced, room: &str, peer: &str) -> Option<LaneRounds> {
    synced
        .lanes
        .iter()
        .find(|((seen_room, seen_peer), _)| seen_room.starts_with(room) && seen_peer == peer)
        .map(|(_, rounds)| *rounds)
}

/// The directory of `node` under a data root. A root with one unnamed node resolves to its only
/// node directory, matching the shipped CLI's default-node selection.
fn node_dir_of(dir: &Path, node: Option<&str>) -> std::path::PathBuf {
    let nodes = dir.join("nodes");
    match node {
        Some(name) => nodes.join(name),
        None => {
            let mut dirs: Vec<_> = std::fs::read_dir(&nodes)
                .unwrap_or_else(|e| panic!("APPARATUS: could not list {}: {e}", nodes.display()))
                .flatten()
                .map(|entry| entry.path())
                .filter(|path| path.is_dir())
                .collect();
            assert_eq!(
                dirs.len(),
                1,
                "APPARATUS: {} does not hold exactly one default node: {dirs:?}",
                nodes.display()
            );
            dirs.remove(0)
        }
    }
}

/// What a person can observe of one node's store file at a quiet-window edge. Comparing the
/// complete bytes proves the artifact did not change without depending on a private redb field;
/// mtime independently names a write that happened to reproduce the same bytes.
struct StoreSnapshot {
    path: std::path::PathBuf,
    bytes: Vec<u8>,
    modified: SystemTime,
}

fn store_snapshots(
    everyone: &[(std::path::PathBuf, Option<&str>, &str, String)],
) -> BTreeMap<String, StoreSnapshot> {
    everyone
        .iter()
        .map(|(dir, node, name, _)| {
            let path = node_dir_of(dir, *node).join("store.redb");
            let bytes = std::fs::read(&path).unwrap_or_else(|error| {
                panic!(
                    "APPARATUS: could not snapshot {name}'s store {}: {error}",
                    path.display()
                )
            });
            let modified = std::fs::metadata(&path)
                .and_then(|metadata| metadata.modified())
                .unwrap_or_else(|error| {
                    panic!(
                        "APPARATUS: could not read {name}'s store mtime {}: {error}",
                        path.display()
                    )
                });
            (
                (*name).to_owned(),
                StoreSnapshot {
                    path,
                    bytes,
                    modified,
                },
            )
        })
        .collect()
}

/// `args` as `node` runs it: `--node <node>` appended; a root with one node names none.
fn as_node<'a>(args: &[&'a str], node: Option<&'a str>) -> Vec<&'a str> {
    let mut v = args.to_vec();
    if let Some(n) = node {
        v.extend(["--node", n]);
    }
    v
}

/// `vox node unlock <node>` in the daemon holding `dir`, as a person makes a second node Ready
/// beside the first. The passphrase comes from a private file the proof writes
/// (`attach::persistent_args`: stdin's `-` is read on a Mac only).
fn unlock(dir: &Path, node: &str) {
    let args = attach::persistent_args(
        dir,
        &["node", "unlock", node, "--passphrase-file", "-"],
        IDENTITY,
    );
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let (ok, out, err) = vox_plain(dir, &args, None);
    assert!(
        ok,
        "APPARATUS: staging `vox node unlock {node}` failed: {out}{err}"
    );
}

/// Bytes in and bytes out.
type Bytes = (u64, u64);
/// A socket as `nettop` names it, and its place among rows of the same name.
type SocketKey = (String, usize);

/// A daemon's network bytes over a stretch of time, in and out, as Activity Monitor counts
/// them: `nettop`'s per-socket cumulative counters (unprivileged on a Mac), sampled through the
/// stretch. Each socket counts from its first sample (zero for one that appears later) to its
/// last, so a socket that closes keeps what it carried up to its last sample, and one that
/// replaces a closed one under the same label counts from zero. Why that is sound: `nettop`
/// lists open sockets only, and a closed one vanishes with its bytes (its per-process row is
/// that aggregate, so a snapshot before and after would drop a closed socket wholesale); sampled
/// every [`ASK_EVERY`], at most the last interval of a closing socket is missed, and the
/// daemon's sockets (a QUIC endpoint per node, the LAN group, the proxy listener) live as long
/// as it does. Off a Mac there is no `nettop`, and [`NetMeter::moved`] says so.
#[derive(Default)]
struct NetMeter {
    /// Per socket (its `nettop` label and its place among same-labelled rows): bytes in and out
    /// at its first sample, and at its last.
    sockets: BTreeMap<SocketKey, (Bytes, Bytes)>,
    /// Bytes in and out of sockets that closed and were replaced under their label.
    retired: Bytes,
    samples: usize,
    /// Why a sample could not be read, if one could not.
    fault: Option<String>,
}

impl NetMeter {
    fn sample(&mut self, pid: u32) {
        let rows = match net_sockets(pid) {
            Ok(rows) => rows,
            Err(e) => {
                self.fault.get_or_insert(e);
                return;
            }
        };
        let mut seen: BTreeMap<String, usize> = BTreeMap::new();
        for (label, now) in rows {
            let nth = seen.entry(label.clone()).or_insert(0);
            let key = (label, *nth);
            *nth += 1;
            match self.sockets.get_mut(&key) {
                Some((first, last)) if now.0 >= last.0 && now.1 >= last.1 => *last = now,
                Some((first, last)) => {
                    // A new socket under this label: the old one closed, and what it carried
                    // up to its last sample is kept.
                    self.retired.0 += last.0 - first.0;
                    self.retired.1 += last.1 - first.1;
                    *first = (0, 0);
                    *last = now;
                }
                None => {
                    let first = if self.samples == 0 { now } else { (0, 0) };
                    self.sockets.insert(key, (first, now));
                }
            }
        }
        self.samples += 1;
    }

    /// Bytes in and out over the samples so far, or why they are not known.
    fn moved(&self) -> Result<Bytes, String> {
        if let Some(why) = &self.fault {
            return Err(why.clone());
        }
        if self.samples < 2 {
            return Err(format!("{} nettop sample(s), not two", self.samples));
        }
        let (i, o) = self
            .sockets
            .values()
            .fold(self.retired, |(i, o), (first, last)| {
                (i + (last.0 - first.0), o + (last.1 - first.1))
            });
        Ok((i, o))
    }
}

/// A process's open sockets as `nettop` lists them, each with its bytes in and out so far: the
/// label (`udp4 127.0.0.1:57671<->*:*`) and the two counters, in `nettop`'s order. `Err` says
/// why they could not be read (there is no `nettop` off a Mac).
fn net_sockets(pid: u32) -> Result<Vec<(String, Bytes)>, String> {
    if !cfg!(target_os = "macos") {
        return Err("no nettop on this platform".to_owned());
    }
    let out = Command::new("nettop")
        .args(["-x", "-n", "-J", "bytes_in,bytes_out", "-p"])
        .arg(pid.to_string())
        .args(["-L", "1"])
        .output()
        .map_err(|e| format!("nettop: {e}"))?;
    let text = String::from_utf8_lossy(&out.stdout);
    // `time,,bytes_in,bytes_out,`, the process row `17:09:08.5,vox.83287,0,0,`, then a row per
    // socket `17:09:08.5,udp4 127.0.0.1:57671<->*:*,0,0,` (a listener's counters are blank).
    let process = format!(".{pid}");
    let mut rows = Vec::new();
    let mut seen_process = false;
    for line in text.lines().skip(1) {
        let cols: Vec<&str> = line.split(',').collect();
        let Some(label) = cols.get(1).filter(|l| !l.is_empty()) else {
            continue;
        };
        if label.ends_with(&process) {
            seen_process = true;
            continue;
        }
        let n = |i: usize| -> Result<u64, String> {
            match cols.get(i).copied().unwrap_or("") {
                "" => Ok(0),
                c => c
                    .parse::<u64>()
                    .map_err(|e| format!("nettop row {line:?}: column {i} is not a count: {e}")),
            }
        };
        rows.push(((*label).to_owned(), (n(2)?, n(3)?)));
    }
    if !seen_process {
        return Err(format!("nettop printed no row for pid {pid}: {text}"));
    }
    Ok(rows)
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


