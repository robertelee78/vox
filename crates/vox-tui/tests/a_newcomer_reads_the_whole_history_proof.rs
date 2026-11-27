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
//!    [`BOUND`] of his join. Two sizes: [`BACKLOG`] (257: 129 below the window) **blocks**; 1,500
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
//! 3. **A join through a member that has just restarted gets in** (ledger 75). Alice's daemon is
//!    stopped and started again, and bob and dave join through her at once while her room's
//!    governance is still refreshing: the test-only `VOX_TEST_HOLD_JOIN_REFRESH_FILE` makes her
//!    admission answer "refreshing", as a restarted member's does until its fold has caught up
//!    (seen in the busy-room journey and reproduced on plain main by timing alone, 1 attempt in
//!    18), until the proof sees both admissions meet it; then it is released and carol posts, the
//!    room publication that a finished fold turn would be. Each `vox room join` must succeed —
//!    each was refused with "a member accepted the passphrase but could not admit this identity;
//!    remote admission may have occurred" — each newcomer is a member once, and from their return
//!    each reads alice and carol and both read each within [`READY_WITHIN`]:
//!    [`a_join_through_a_member_that_just_restarted_gets_in`]. The same through the seat's door,
//!    alice's room already refreshing when bob's seat is reserved (`<file>.seat`):
//!    [`a_join_through_a_member_refreshing_when_its_seat_is_reserved_gets_in`]. And the run-out,
//!    the hold never released: alice asks bob's admission once, stops at her admission patience
//!    (20 s), bob is told before his own 30 s wait for her answer ends, neither side counts him a
//!    member, and once released his second join and dave's get in:
//!    [`a_join_whose_admission_stays_refreshing_is_refused_in_time_and_leaves_nothing`]. And the
//!    other "busy": alice's Computer publication lease held from bob's admission request
//!    (`<file>.lease`, as a policy transition holds it): one attempt while it stands, and bob gets
//!    in once it is released: [`a_join_whose_admission_meets_the_computer_lease_gets_in_once_it_is_released`].
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
//! - the admitting member answering a join at once while its governance refreshes
//!   (`VOX_MUTANT_JOIN_REFRESH=no-wait`, read by alice's daemon): claim 3 red, bob's join refused,
//!   at the admission and at the seat;
//! - a refused admission's own completion taken for the room having moved on
//!   (`VOX_MUTANT_JOIN_REFRESH=self-wake`): the run-out red, alice asking bob's admission again
//!   and again while nothing changed;
//! - a busy admission's own completion taken for the Computer lease's release
//!   (`VOX_MUTANT_JOIN_REFRESH=busy-own-wake`): the lease arm red, alice asking bob's admission
//!   again and again while the lease stood.

// Two blocking-or-optional arms (decider, 2026-10-01: "Valid proofs block; rest optional"). The
// 257-post history BLOCKS: a newcomer reads every post exactly once and in order, the part below
// the live window on demand. The timing claim (one wait, fresh or behind) and the 1,500-post
// history are optional: CI only compiles them, and without `--features optional-proofs` a stand-in
// says each was not run (`support/optional_proof.rs`).
#![cfg_attr(not(feature = "optional-proofs"), allow(dead_code))]
// The existing room and relay apparatus each includes its own attachment/layout support.
#![cfg_attr(feature = "optional-proofs", allow(clippy::duplicate_mod))]
#![cfg(unix)]

#[path = "support/optional_proof.rs"]
mod optional_proof;
optional_proof::not_run!(
    a_newcomer_trusted_before_every_post_reads_all_of_them,
    a_newcomer_talks_both_ways_at_one_wait_fresh_or_behind_a_backlog,
    hosted_nodes_read_each_other,
    interrupted_history_and_private_packages_recover,
    retained_rows_render_once_their_key_and_consent_arrive,
    a_busy_room_newcomer_reads_every_member_with_a_paused_member,
    a_busy_room_newcomer_reads_every_member_with_a_delayed_path,
    the_busy_room_reader_finds_the_first_of_five_thousand_rows,
    a_returning_reader_eight_thousand_entries_behind_reads_and_pages_back,
);

#[path = "support/test_knobs.rs"]
mod test_knobs;
#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/attach.rs"]
mod attach;

#[path = "support/typed.rs"]
mod typed;

#[path = "support/ports.rs"]
mod ports;

use std::collections::BTreeSet;
use std::io::Write;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const VOX: &str = env!("CARGO_BIN_EXE_vox");
const IDENTITY: &str = "an identity passphrase";
const ROOMPASS: &str = "the room passphrase";
/// External deadman for the optional whole-journey timing measurement. The blocking catch-up
/// claim does not use this to decide whether a page is wedged.
const BOUND: Duration = Duration::from_secs(300);
/// **The one wait** (ADR-037 R1): from bob's `vox room join` returning, alice reads his first
/// post and he reads hers, in a fresh room and behind a backlog alike. The bound a member back in
/// its room already meets both ways (`a_member_that_restarts_finds_its_room_proof`, 10 s); a
/// fresh room measured well under it, and the backlog room must meet the same figure.
const READY_WITHIN: Duration = Duration::from_secs(10);
/// Existing optional private-history responsiveness claim; the blocking connected catch-up arm
/// uses structural owner/progress observations instead of this elapsed bound.
const PAGE_WITHIN: Duration = Duration::from_secs(60);
/// The reproduced connected catch-up backlog: past `MAX_PAGE_ENTRIES` (128), so 129 rows sit
/// below the live window and are read only on demand. The former 160-row arm did not cover the
/// 257-row daemon wedge observed on the release base.
const BACKLOG: usize = 257;
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
    /// Stop it as a person does (SIGTERM, ADR-012: a clean stop), waiting for it to exit.
    fn stop(mut self) {
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

/// The same, with more shipped daemon arguments (`--no-node`, for a multi-node host; a `--listen`
/// of its own replaces the loopback default).
fn daemon_with(dir: &Path, tag: &str, args: &[&str], env: &[(&str, &str)]) -> Daemon {
    let file = |kind: &str| {
        let at = dir.join(format!("daemon-{tag}.{kind}"));
        std::fs::File::create(&at)
            .unwrap_or_else(|e| panic!("APPARATUS: could not create {}: {e}", at.display()))
    };
    let mut cmd = Command::new(VOX);
    cmd.arg("daemon");
    if !args.contains(&"--listen") {
        cmd.args(["--listen", "127.0.0.1:0"]);
    }
    cmd.args(args)
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

/// The same shipped readiness observation for one named node on a multi-node daemon.
fn attached_as(dir: &Path, _tag: &str, node: Option<&str>) -> String {
    const APPARATUS_ATTACH_RETRY_PACE: Duration = Duration::from_millis(200);
    loop {
        let (ok, out, err) = vox(dir, &as_node(&["room", "list"], node), None);
        if ok {
            return out;
        }
        let _ = err;
        std::thread::sleep(APPARATUS_ATTACH_RETRY_PACE);
    }
}

/// `args` as one named node on a multi-node daemon runs it.
fn as_node<'a>(args: &[&'a str], node: Option<&'a str>) -> Vec<&'a str> {
    let mut args = args.to_vec();
    if let Some(node) = node {
        args.extend(["--node", node]);
    }
    args
}

/// Make one named node Ready beside the others hosted by `vox daemon --no-node`.
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

/// Wait for the shipped room list to say `room` is open. The proof's operator-selected watchdog
/// owns any apparatus timebox; this causal wait has no elapsed product verdict of its own.
fn wait_room_open(dir: &Path, room: &str, who: &str) {
    loop {
        let (ok, out, err) = vox(dir, &["room", "list"], None);
        assert!(
            ok,
            "PRODUCT (staging): {who}'s shipped `vox room list` failed while waiting for its \
             restarted room: {err}"
        );
        if out
            .lines()
            .any(|line| line.trim_start().starts_with(room) && !line.contains("[preparing"))
        {
            return;
        }
        // This is apparatus pacing, not a product deadline. Avoid turning an unavailable room
        // into a hot loop; the operator-selected whole-proof watchdog owns wedge detection.
        std::thread::sleep(Duration::from_millis(100));
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

/// Every row a person reads, oldest first, in one exact paged JSON observation. Follow the
/// product's explicit refresh instruction by discarding the partial observation, not its rows.
fn room_rows(dir: &Path, room: &str) -> Vec<serde_json::Value> {
    let limit = PAGE.to_string();
    let mut before: Option<String> = None;
    let mut pages_newest_first = Vec::new();
    loop {
        let mut args = vec!["room", "read", room, "--json", "--limit", &limit];
        if let Some(cursor) = before.as_deref() {
            args.extend(["--before", cursor]);
        }
        let (ok, out, err) = vox(dir, &args, None);
        if !ok
            && err.lines().any(|line| {
                line.trim()
                    .ends_with("the room changed while reading; refresh and retry")
            })
        {
            before = None;
            pages_newest_first.clear();
            continue;
        }
        assert!(
            ok,
            "PRODUCT: paged `vox room read --json` refused before {before:?}: {out}{err}"
        );
        let rows: Vec<serde_json::Value> = out
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| {
                serde_json::from_str(line).unwrap_or_else(|error| {
                    panic!(
                        "PRODUCT: `vox room read --json` printed a row that is not JSON \
                         ({error}): {line}"
                    )
                })
            })
            .collect();
        if rows.is_empty() {
            break;
        }
        let short = rows.len() < PAGE;
        let next = rows[0]["entry_hash"]
            .as_str()
            .unwrap_or_else(|| {
                panic!(
                    "PRODUCT: a `vox room read --json` row carries no entry_hash: {}",
                    rows[0]
                )
            })
            .to_owned();
        assert_ne!(
            before.as_deref(),
            Some(next.as_str()),
            "PRODUCT: paged `vox room read --json` repeated cursor {next}"
        );
        before = Some(next);
        pages_newest_first.push(rows);
        if short {
            break;
        }
    }
    pages_newest_first.into_iter().rev().flatten().collect()
}

/// The hash view exposes retained ciphertext; the timeline must not expose its SAY body while
/// a required key or consent fact is absent. Stage exact source hashes, not a row-count proxy.
fn wait_for_held_rows(dir: &Path, room: &str, expected_hashes: &[String], hold: &str) {
    loop {
        let hashes = room_hashes(dir, "reader", room);
        let held: Vec<&String> = hashes
            .iter()
            .filter(|hash| expected_hashes.contains(hash))
            .collect();
        let rows = room_rows(dir, room);
        let staged: Vec<&serde_json::Value> = rows
            .iter()
            .filter(|row| {
                row["entry_hash"]
                    .as_str()
                    .is_some_and(|hash| expected_hashes.iter().any(|expected| expected == hash))
            })
            .collect();
        assert!(
            staged
                .iter()
                .all(|row| row["envelope"]["body"].as_str().is_none()),
            "PRODUCT: an exact retained row was readable while its required {hold} fact was \
             absent in room {room}; staged rows: {staged:?}"
        );
        if held.len() < expected_hashes.len() {
            std::thread::yield_now();
            continue;
        }
        assert_eq!(
            held,
            expected_hashes.iter().collect::<Vec<_>>(),
            "APPARATUS: the exact late rows were not retained once each in source order while \
             the {hold} hold was engaged in room {room}; hashes: {hashes:?}"
        );
        return;
    }
}

/// Shipped reads follow a multi-turn render continuation, then one exact observation
/// proves that these retained objects—not merely equal text from a refetch or duplicate post—
/// became readable once each in source order.
fn assert_exact_read_rows(
    dir: &Path,
    reader: &str,
    room: &str,
    expected_hashes: &[String],
    expected_texts: &[String],
    ordering: &str,
) {
    let expected: Vec<(String, Option<String>)> = expected_hashes
        .iter()
        .cloned()
        .zip(expected_texts.iter().cloned().map(Some))
        .collect();
    let mut work_seen = false;
    loop {
        let rows = room_rows(dir, room);
        let actual: Vec<(String, Option<String>)> = rows
            .iter()
            .filter_map(|row| {
                let hash = row["entry_hash"].as_str()?;
                expected_hashes
                    .iter()
                    .any(|expected| expected == hash)
                    .then(|| {
                        (
                            hash.to_owned(),
                            row["envelope"]["body"].as_str().map(str::to_owned),
                        )
                    })
            })
            .collect();
        if actual == expected {
            return;
        }
        let status = room_status(dir, reader, room);
        work_seen |=
            status.render_backfill_pending || actual.iter().any(|(_, text)| text.is_some());
        if work_seen && !status.render_backfill_pending {
            // The first paged walk may have straddled the last render turn. Once shipped status
            // says no continuation remains, take a fresh, stable observation before judging the
            // product; otherwise a healthy completion between pages could look incomplete.
            let final_rows = room_rows(dir, room);
            let final_actual: Vec<(String, Option<String>)> = final_rows
                .iter()
                .filter_map(|row| {
                    let hash = row["entry_hash"].as_str()?;
                    expected_hashes
                        .iter()
                        .any(|expected| expected == hash)
                        .then(|| {
                            (
                                hash.to_owned(),
                                row["envelope"]["body"].as_str().map(str::to_owned),
                            )
                        })
                })
                .collect();
            if final_actual == expected {
                return;
            }
            let settled = room_status(dir, reader, room);
            if settled.render_backfill_pending {
                work_seen = true;
                continue;
            }
            panic!(
                "PRODUCT: after {ordering}, Bob's causally engaged render continuation finished \
                 without showing each exact retained object once, readable, and in source order \
                 in room {room}; expected: {expected:?}; first observation: {actual:?}; stable \
                 observation: {final_actual:?}; all stable rows: {final_rows:?}; final status: \
                 {settled:?}"
            );
        }
        std::thread::yield_now();
    }
}

#[derive(Clone, Debug)]
struct RoomStatus {
    log_entries: u64,
    members: Vec<String>,
    received_key_generations: u64,
    render_backfill_pending: bool,
    key_delivery_pending: Vec<String>,
}

/// What the shipped status command says about one room. Refused or malformed output is a product
/// red even while the proof is arranging its deliberate holds: it is still the shipped command's
/// user-visible answer.
fn room_status(dir: &Path, reader: &str, room: &str) -> RoomStatus {
    loop {
        let (ok, out, err) = vox(dir, &["status", "--json"], None);
        assert!(
            ok,
            "PRODUCT: {reader}'s `vox status --json` was unavailable while staging room {room}: \
         {out}{err}"
        );
        let value: serde_json::Value = serde_json::from_str(&out).unwrap_or_else(|error| {
            panic!(
                "PRODUCT: {reader}'s `vox status --json` was malformed while staging room {room} \
             ({error}): {out}"
            )
        });
        let Some(row) = value["rooms"].as_array().and_then(|rooms| {
            rooms
                .iter()
                .find(|row| row["id"].as_str().is_some_and(|id| id.starts_with(room)))
        }) else {
            if value["preparing"].as_array().is_some_and(|rooms| {
                rooms
                    .iter()
                    .any(|row| row["id"].as_str().is_some_and(|id| id.starts_with(room)))
            }) {
                // Ready is node readiness, not publication of every restored room.
                // Wait for this exact staged room, without inventing its status.
                std::thread::yield_now();
                continue;
            }
            panic!(
                "PRODUCT: {reader}'s `vox status --json` did not contain staged room {room}: \
             {out}"
            );
        };
        return RoomStatus {
            log_entries: row["log_entries"].as_u64().unwrap_or_else(|| {
                panic!("PRODUCT: {reader}'s room status has no numeric `log_entries`: {row}")
            }),
            members: row["members"]
                .as_array()
                .unwrap_or_else(|| panic!("PRODUCT: {reader}'s room status has no members: {row}"))
                .iter()
                .map(|member| {
                    member["id"]
                        .as_str()
                        .unwrap_or_else(|| panic!("PRODUCT: room member has no id: {member}"))
                        .to_owned()
                })
                .collect(),
            received_key_generations: row["received_key_generations"].as_u64().unwrap_or_else(
                || {
                    panic!(
                "PRODUCT: {reader}'s room status has no numeric `received_key_generations`: {row}"
            )
                },
            ),
            render_backfill_pending: row["render_backfill_pending"].as_bool().unwrap_or_else(
                || {
                    panic!(
                "PRODUCT: {reader}'s room status has no boolean `render_backfill_pending`: {row}"
            )
                },
            ),
            key_delivery_pending: row["members"]
                .as_array()
                .unwrap_or_else(|| panic!("PRODUCT: {reader}'s room status has no members: {row}"))
                .iter()
                .filter_map(|member| {
                    let pending = member["key_delivery_pending"].as_bool().unwrap_or_else(|| {
                        panic!(
                            "PRODUCT: {reader}'s room member has no boolean \
                         `key_delivery_pending`: {member}"
                        )
                    });
                    pending.then(|| {
                        member["id"]
                            .as_str()
                            .unwrap_or_else(|| {
                                panic!(
                                    "PRODUCT: {reader}'s pending key-delivery member has no id: \
                                 {member}"
                                )
                            })
                            .to_owned()
                    })
                })
                .collect(),
        };
    }
}

fn room_id(dir: &Path, reader: &str, room: &str) -> vox_core::hash::Digest32 {
    room_id_as(dir, None, reader, room)
}

fn room_id_as(
    dir: &Path,
    node: Option<&str>,
    reader: &str,
    room: &str,
) -> vox_core::hash::Digest32 {
    let (ok, out, err) = vox(dir, &as_node(&["status", "--json"], node), None);
    if !ok
        && (out.contains("this data root holds several nodes")
            || err.contains("this data root holds several nodes"))
    {
        panic!(
            "APPARATUS: {reader}'s room-id observation did not select a stored node \
             (asked {node:?}) for {room}: {out}{err}"
        );
    }
    assert!(
        ok,
        "PRODUCT: {reader}'s `vox status --json` was unavailable for room {room}: {out}{err}"
    );
    let value: serde_json::Value = serde_json::from_str(&out).unwrap_or_else(|error| {
        panic!("PRODUCT: {reader}'s status was malformed ({error}): {out}")
    });
    let id = value["rooms"]
        .as_array()
        .and_then(|rooms| {
            rooms.iter().find(|row| {
                row["id"].as_str().is_some_and(|id| id.starts_with(room)) || row["name"] == room
            })
        })
        .and_then(|row| row["id"].as_str())
        .unwrap_or_else(|| panic!("PRODUCT: {reader}'s status omitted room {room}: {out}"));
    vox_core::node::link::b32_decode(id, "status room id").unwrap_or_else(|error| {
        panic!("PRODUCT: {reader}'s status named a malformed room id: {error}")
    })
}

/// Exact authenticated room-order hashes exposed by the shipped diagnostic command.
fn room_hashes(dir: &Path, reader: &str, room: &str) -> Vec<String> {
    let (ok, out, err) = loop {
        let result = vox(dir, &["room", "read", room, "--hashes"], None);
        if !result.0
            && matches!(
                result.2.trim(),
                "vox: the room changed while reading; refresh and retry"
                    | "vox: node: the room changed while reading; refresh and retry"
            )
        {
            continue;
        }
        break result;
    };
    assert!(
        ok,
        "PRODUCT: {reader}'s `vox room read --hashes` failed for {room}: {out}{err}"
    );
    out.lines()
        .map(|line| {
            let mut fields = line.split_whitespace();
            let hash = fields.next().unwrap_or_else(|| {
                panic!("PRODUCT: {reader}'s room order contained an empty row: {out}")
            });
            let clock = fields.next().and_then(|clock| clock.parse::<u64>().ok());
            assert!(
                fields.next().is_none() && clock.is_some(),
                "PRODUCT: {reader}'s room order row was malformed: {line:?}"
            );
            hash.to_owned()
        })
        .collect()
}

fn grant_full_history(dir: &Path, fingerprint: &str, name: &str) -> (bool, String, String) {
    loop {
        let result = vox(
            dir,
            &[
                "trust",
                "add",
                fingerprint,
                "--name",
                name,
                "--history",
                "full",
            ],
            None,
        );
        if result.0
            || !result.2.lines().any(|line| {
                line.trim() == "vox: a previous change to this room is still being applied; this request made no change"
            })
        {
            return result;
        }
        // Follow only the explicit no-change wait instruction, as the rename journey does.
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Rename through the shipped command and return the exact authenticated row it says it appended.
fn rename_hash(dir: &Path, reader: &str, room: &str, name: &str) -> String {
    let (ok, out, err) = loop {
        let result = vox(dir, &["room", "rename", room, name], None);
        if !result.0
            && result.2.starts_with(
                "vox: cannot rename the room: a previous change to this room is still being applied; this request made no change",
            )
        {
            // The command explicitly made no change. Follow its wait instruction before
            // asking again; all other refusals remain product failures.
            std::thread::sleep(Duration::from_millis(100));
            continue;
        }
        break result;
    };
    assert!(
        ok,
        "PRODUCT: {reader}'s `vox room rename {room} {name}` was refused: {out}{err}"
    );
    let hashes: Vec<_> = out
        .lines()
        .filter_map(|line| line.trim().strip_prefix("entry "))
        .collect();
    assert_eq!(
        hashes.len(),
        1,
        "PRODUCT: {reader}'s successful room rename did not name exactly one appended entry: \
         {out}{err}"
    );
    vox_core::node::link::b32_decode(hashes[0], "rename entry hash").unwrap_or_else(|error| {
        panic!(
            "PRODUCT: {reader}'s room rename named a malformed entry hash ({error}): {}",
            hashes[0]
        )
    });
    hashes[0].to_owned()
}

/// Wait for a shipped authority-dependent page to answer. Refreshing is the product's explicit
/// retry result while the causal fold is in progress; any other refusal is a product red. An
/// external operator deadman may stop a structurally stalled run as NO RESULT; elapsed time is
/// not a product or apparatus verdict here.
fn wait_governance_current(dir: &Path, reader: &str, room: &str, _claim: &str) {
    loop {
        let (ok, out, err) = vox(
            dir,
            &["room", "read", room, "--json", "--notices", "--limit", "1"],
            None,
        );
        if ok {
            return;
        }
        assert!(
            err.contains("governance") && err.contains("refreshing"),
            "PRODUCT: {reader}'s authority-dependent room page failed for {room}: {out}{err}"
        );
        std::thread::yield_now();
    }
}

/// Wait for a causal product observation. A key arriving while its marker hold exists means the
/// staging itself was not achieved; elapsed time says nothing about product correctness.
fn wait_room_status(
    dir: &Path,
    reader: &str,
    room: &str,
    key_must_stay_held: bool,
    claim: &str,
    ready: impl Fn(&RoomStatus) -> bool,
) -> RoomStatus {
    loop {
        let status = room_status(dir, reader, room);
        assert!(
            !key_must_stay_held || status.received_key_generations == 0,
            "APPARATUS: {reader} accepted a sender key in room {room} while the package hold \
             marker still existed during `{claim}`: {status:?}"
        );
        if ready(&status) {
            return status;
        }
        std::thread::yield_now();
    }
}

/// The product's trust sentence for a room member. Doctor may exit non-zero because another
/// check warns; its JSON is still the user-visible observation this staging needs.
fn trust_detail(dir: &Path, reader: &str, room: &str, member: &str) -> String {
    let (_, out, err) = vox(dir, &["agent", "doctor", "--room", room, "--json"], None);
    let report: serde_json::Value = serde_json::from_str(&out).unwrap_or_else(|error| {
        panic!(
            "PRODUCT: {reader}'s `vox agent doctor --json` was malformed while staging room \
             {room} ({error}): {out}{err}"
        )
    });
    // A join can return before its room is published. Doctor explicitly reports that state
    // instead of inventing a trust answer; waiters must observe it until preparation completes.
    if report["room"].is_null() {
        if let Some(detail) = report["checks"].as_array().and_then(|checks| {
            checks
                .iter()
                .find(|check| check["check"] == "room")
                .and_then(|check| check["detail"].as_str())
                .filter(|detail| detail.starts_with("that room is preparing its saved history;"))
        }) {
            return detail.to_owned();
        }
    }
    let trust_check = format!("trust {member}");
    report["checks"]
        .as_array()
        .and_then(|checks| {
            checks
                .iter()
                .find(|check| check["check"].as_str().is_some_and(|id| id == trust_check))
        })
        .and_then(|check| check["detail"].as_str())
        .unwrap_or_else(|| {
            panic!(
                "PRODUCT: {reader}'s doctor reported no `trust {member}` detail for staged \
                 room {room}: {report}"
            )
        })
        .to_owned()
}

fn wait_trust_detail(dir: &Path, reader: &str, room: &str, member: &str, expected: &str) {
    loop {
        let actual = trust_detail(dir, reader, room, member);
        if actual == expected {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// A newly joined room can briefly lack the reader's own published consent even after its
/// node-wide trust command succeeded. Wait for that exact room fact; mutual trust would mean
/// the missing-consent staging failed.
#[track_caller]
fn wait_reader_one_way_trust(dir: &Path, reader: &str, room: &str, member: &str) {
    loop {
        let actual = trust_detail(dir, reader, room, member);
        match actual.as_str() {
            "you trust it; your node has not received its trust for you, so cannot tell whether it trusts you" => return,
            "you have not trusted it: it cannot read you, and you do not read it" => {
                std::thread::sleep(Duration::from_millis(100));
            }
            detail if detail.starts_with("that room is preparing its saved history") => {
                std::thread::sleep(Duration::from_millis(100));
            }
            _ => panic!("APPARATUS: required missing-consent boundary was not staged for {reader}/{member} in {room}: {actual}"),
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

/// Reads an act repeated because `vox room read` refused "the room changed while reading;
/// refresh and retry": a person told to refresh reads again. Counted and said, never a verdict.
static READ_AGAIN: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Whether a refused read told the person to read again because the room changed meanwhile.
fn room_changed_while_reading(err: &str) -> bool {
    let refused = err.lines().any(|line| {
        line.trim()
            .ends_with("the room changed while reading; refresh and retry")
    });
    if refused {
        let n = READ_AGAIN.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
        eprintln!("[ACT read-again] `vox room read` said the room changed while reading; read again (n={n})");
    }
    refused
}

/// Whether `vox room read` on `dir` shows `text` now. A read that fails is a red, never silence;
/// a read the room asks to refresh is read again, as a person would.
fn reads(dir: &Path, room: &str, text: &str) -> bool {
    loop {
        let (ok, out, err) = vox(dir, &["room", "read", room], None);
        if !ok && room_changed_while_reading(&err) {
            continue;
        }
        assert!(ok, "PRODUCT: `vox room read` refused: {out}{err}");
        return out.contains(text);
    }
}

/// The exact first read which consumes Alice's sparse Content after Bob's join. Only this causal
/// operation may pronounce the sparse-Content mutant verdict; later reads retain their own claim.
fn reads_first_sparse_content(dir: &Path, room: &str, text: &str) -> bool {
    let (ok, out, err) = vox(dir, &["room", "read", room], None);
    assert!(
        ok,
        "PRODUCT [FX29 sparse-content-publication]: Bob's first `vox room read` refused after Alice's exact post was accepted: {out}{err}"
    );
    out.contains(text)
}

/// The exact entry hash a person sees for `text`, walking the shipped JSON read pages.
fn read_hash(dir: &Path, room: &str, text: &str) -> Option<String> {
    let mut before: Option<String> = None;
    loop {
        let limit = PAGE.to_string();
        let mut args = vec!["room", "read", room, "--json", "--limit", &limit];
        if let Some(oldest) = before.as_deref() {
            args.extend(["--before", oldest]);
        }
        let (ok, out, err) = vox(dir, &args, None);
        assert!(
            ok,
            "PRODUCT: `vox room read --json` refused while locating {text:?}: {out}{err}"
        );
        let rows: Vec<serde_json::Value> = out
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| {
                serde_json::from_str(line).unwrap_or_else(|error| {
                    panic!("PRODUCT: `vox room read --json` printed invalid JSON ({error}): {line}")
                })
            })
            .collect();
        if let Some(hash) = rows.iter().find_map(|row| {
            (row["text"].as_str() == Some(text))
                .then(|| row["entry_hash"].as_str().map(str::to_owned))
                .flatten()
        }) {
            return Some(hash);
        }
        if rows.len() < PAGE {
            return None;
        }
        before = rows
            .first()
            .and_then(|row| row["entry_hash"].as_str())
            .map(str::to_owned);
        assert!(
            before.is_some(),
            "PRODUCT: a `vox room read --json` row carries no entry_hash while locating {text:?}"
        );
    }
}

struct HistoryObservation {
    phase: String,
    remaining: u64,
    request: Option<String>,
}

fn history_observation(dir: &Path, room: &str) -> HistoryObservation {
    let (ok, out, err) = vox(
        dir,
        &["room", "read", room, "--json", "--history", "status"],
        None,
    );
    assert!(
        ok,
        "PRODUCT: `vox room read --history status --json` was refused: {out}{err}"
    );
    let value: serde_json::Value = serde_json::from_str(&out).unwrap_or_else(|error| {
        panic!("PRODUCT: `vox room read --history status --json` printed invalid JSON ({error}): {out}")
    });
    let status = &value["status"];
    let phase = status["phase"]
        .as_str()
        .unwrap_or_else(|| panic!("PRODUCT: history status named no phase: {value}"))
        .to_owned();
    let remaining = status["remaining"]
        .as_u64()
        .unwrap_or_else(|| panic!("PRODUCT: history status named no remaining count: {value}"));
    // The CLI renders the binary request id as a copyable hexadecimal string at the envelope;
    // the nested status keeps its wire-shaped byte array.
    let request = match &value["request"] {
        serde_json::Value::String(request) => Some(request.to_owned()),
        serde_json::Value::Null => None,
        _ => panic!("PRODUCT: history status printed a non-string request id: {value}"),
    };
    HistoryObservation {
        phase,
        remaining,
        request,
    }
}

fn history_status(dir: &Path, room: &str) -> (String, u64) {
    let observed = history_observation(dir, room);
    (observed.phase, observed.remaining)
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

/// The first two-way convergence after Bob's sparse join, with Bob's Content read carrying the
/// exact publication verdict. Elapsed time remains the surrounding product claim, not this one.
fn first_sparse_arrivals(
    since: Instant,
    alice: &Path,
    bob: &Path,
    room: &str,
    outcome: &Path,
    alice_hash: &str,
    limit: Duration,
) -> (Option<Duration>, Option<Duration>) {
    let recorded = loop {
        match std::fs::read_to_string(outcome) {
            Ok(recorded) => break recorded,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error) => panic!(
                "APPARATUS: could not read Bob's exact sparse-Content outcome marker {}: {error}",
                outcome.display()
            ),
        }
    };
    let accepted = format!("accepted:{alice_hash}");
    let refused = format!("refused:{alice_hash}");
    assert!(
        recorded == accepted || recorded == refused,
        "APPARATUS: Bob's first sparse-Content outcome marker did not bind Alice's exact accepted entry {alice_hash}: {recorded:?}"
    );
    eprintln!(
        "[proof] FX-29 sparse Content publication apparatus staged: Bob processed Alice's exact accepted entry {alice_hash} with outcome {recorded}"
    );
    let to_bob = reads_first_sparse_content(bob, room, "post 1").then(|| since.elapsed());
    let mut to_alice = None;
    while to_alice.is_none() && since.elapsed() < limit {
        if to_alice.is_none() && reads(alice, room, "bob is here") {
            to_alice = Some(since.elapsed());
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    (to_alice, to_bob)
}

/// The blocking arm: a backlog past the live window, read over several pages, the part below the
/// window on demand.
#[test]
#[ignore = "real vox daemons and production Argon2id; CI runs it in release"]
fn a_newcomer_reads_a_short_history_once_each_in_order() {
    watchdog::arm();
    let mut tmp = tempfile::tempdir().unwrap_or_else(|e| panic!("APPARATUS: no temp dir: {e}"));
    if std::env::var_os("VOX_PROOF_KEEP_DIRS").is_some() {
        tmp.disable_cleanup(true);
        println!("[proof] daemon dirs kept under {}", tmp.path().display());
    }
    newcomer_reads_the_whole_history(tmp.path(), BACKLOG, PAGE);
}

/// The members who keep posting while alice reads, each a post, a second's pause, a post.
const BUSY_AUTHORS: [&str; 3] = ["bob", "carol", "dave"];
/// Alice's own history: past one page of a plain read (200 rows) and many `--hashes` pages (64).
const BUSY_BACKLOG: usize = 300;
/// Reads of each kind while the others post. A read takes tens of milliseconds in release, so
/// twenty of each lasted about as long as three posts of each member; fifty span many more.
const BUSY_READS: usize = 50;

/// **A read is not refused because someone else posted** (ledger 95). Alice holds a history of
/// several pages; three members keep posting, each a post, a second's pause, a post; once each
/// has had posts accepted and alice shows them, alice reads it the three ways
/// that take more than one request: `vox room read --unread`, `vox room read --hashes`, and a
/// reply by a prefix of an old message (`vox room post --re PREFIX`, which scans every page).
/// A message that arrives changes no row already read, so none of them may be refused, and
/// each must give what a person expects: the unread messages, the whole order, the reply
/// posted to the message named. On main 4e16a0da7 (five members) 124, 174 and 8 of 200 such
/// reads were refused "the room changed while reading". Mutant
/// `VOX_MUTANT_READ_REFUSES_ARRIVALS` (the daemon compares what an arrival moves again): refused.
#[test]
#[ignore = "four real vox daemons, three members posting while one reads; CI runs it in release"]
fn a_reader_is_not_refused_while_others_keep_posting() {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Arc;
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap_or_else(|e| panic!("APPARATUS: no temp dir: {e}"));
    let alice = tmp.path().join("alice");
    let authors: Vec<std::path::PathBuf> = BUSY_AUTHORS
        .iter()
        .map(|name| tmp.path().join(name))
        .collect();
    for d in std::iter::once(&alice).chain(&authors) {
        std::fs::create_dir_all(d.join("cfg"))
            .unwrap_or_else(|e| panic!("APPARATUS: could not create {}: {e}", d.display()));
    }
    let fingerprint = |dir: &Path| {
        let (ok, out, err) = vox(dir, &["id"], None);
        assert!(ok, "PRODUCT (staging): `vox id` failed: {err}");
        out.trim().to_owned()
    };
    let alice_fp = fingerprint(&alice);
    for (dir, name) in authors.iter().zip(BUSY_AUTHORS) {
        let fp = fingerprint(dir);
        for (who, whom, called) in [(&alice, &fp, name), (dir, &alice_fp, "alice")] {
            let (ok, _, err) = vox(who, &["trust", "add", whom, "--name", called], None);
            assert!(
                ok,
                "PRODUCT (staging): `vox trust add` of {called} failed: {err}"
            );
        }
    }

    let _alice_daemon = daemon(&alice, "alice");
    attached(&alice, "alice");
    let (ok, _, err) = vox(
        &alice,
        &["room", "create", "--passphrase-file", "-", "--name", "busy"],
        Some(&format!("{ROOMPASS}\n")),
    );
    assert!(ok, "PRODUCT (staging): `vox room create` failed: {err}");
    let listed = attached(&alice, "alice");
    let room = listed
        .split_whitespace()
        .find(|w| w.len() >= 8 && w.chars().all(|c| c.is_ascii_alphanumeric()))
        .unwrap_or_else(|| panic!("PRODUCT (staging): `vox room list` shows no room id: {listed}"))
        .to_owned();
    for i in 1..=BUSY_BACKLOG {
        let (ok, _, err) = vox(&alice, &["room", "post", &room, &format!("busy {i}")], None);
        assert!(ok, "PRODUCT (staging): alice's post {i} was refused: {err}");
    }
    // The reply's target: alice's first post, below the newest page; a prefix only it has.
    let rows = room_rows(&alice, &room);
    let target = rows
        .iter()
        .find(|row| row["text"].as_str() == Some("busy 1"))
        .and_then(|row| row["entry_hash"].as_str())
        .unwrap_or_else(|| panic!("PRODUCT (staging): alice's paged read lacks her first post"))
        .to_owned();
    let prefix = target[..20].to_owned();
    assert!(
        rows.iter()
            .filter(|row| row["entry_hash"]
                .as_str()
                .is_some_and(|h| h.starts_with(&prefix)))
            .count()
            == 1,
        "APPARATUS: the reply prefix {prefix} is not unique among alice's rows"
    );

    let (ok, link, err) = vox(&alice, &["room", "link", &room], None);
    assert!(ok, "PRODUCT (staging): `vox room link` failed: {err}");
    let link = link
        .lines()
        .find(|line| line.starts_with("vox://"))
        .unwrap_or(link.trim())
        .to_owned();
    let mut daemons = Vec::new();
    for (dir, name) in authors.iter().zip(BUSY_AUTHORS) {
        daemons.push(daemon(dir, name));
        attached(dir, name);
        let (ok, out, err) = vox(
            dir,
            &["room", "join", "--passphrase-file", "-", &link],
            Some(&format!("{ROOMPASS}\n")),
        );
        assert!(
            ok,
            "PRODUCT (staging): {name}'s join was refused: {out}{err}"
        );
    }

    // Each member keeps posting until alice has read: a post, a second's pause, a post.
    let stop = Arc::new(AtomicBool::new(false));
    let posted = Arc::new(AtomicUsize::new(0));
    let posters: Vec<_> = authors
        .iter()
        .zip(BUSY_AUTHORS)
        .map(|(dir, name)| {
            let (dir, room, stop, posted) = (
                dir.clone(),
                room.clone(),
                Arc::clone(&stop),
                Arc::clone(&posted),
            );
            std::thread::spawn(move || {
                // (attempts, time spent posting, first refusal): diagnostics only.
                let mut n = 0usize;
                let mut spent = Duration::ZERO;
                let mut refusal = None;
                while !stop.load(Ordering::Relaxed) {
                    n += 1;
                    let asked = Instant::now();
                    let (ok, out, err) = vox(
                        &dir,
                        &["room", "post", &room, &format!("{name} says {n}")],
                        None,
                    );
                    spent += asked.elapsed();
                    if ok {
                        posted.fetch_add(1, Ordering::Relaxed);
                    } else if refusal.is_none() {
                        refusal = Some(format!("{name}: {}{}", out.trim(), err.trim()));
                    }
                    std::thread::sleep(Duration::from_secs(1));
                }
                (n, spent, refusal)
            })
        })
        .collect();
    // Staging: the members' first posts are behind them (three accepted for each, on average) and
    // alice shows every member's posts before she reads.
    loop {
        let (ok, out, _) = vox(&alice, &["room", "read", &room], None);
        if ok
            && posted.load(Ordering::Relaxed) >= 3 * BUSY_AUTHORS.len()
            && BUSY_AUTHORS
                .iter()
                .all(|name| out.contains(&format!("{name} says")))
        {
            break;
        }
        std::thread::sleep(Duration::from_millis(500));
    }

    let hashes_line = |line: &str| {
        let mut fields = line.split_whitespace();
        fields.next().is_some_and(|h| h.len() == 52)
            && fields
                .next()
                .is_some_and(|c| c.chars().all(|c| c.is_ascii_digit()))
            && fields.next().is_none()
    };
    let mut refused = Vec::new();
    let mut held_before = None;
    let mut held_after = 0;
    let posted_before = posted.load(Ordering::Relaxed);
    for i in 1..=BUSY_READS {
        let (ok, out, err) = vox(&alice, &["room", "read", &room, "--unread"], None);
        if ok {
            assert!(
                BUSY_AUTHORS
                    .iter()
                    .all(|name| out.contains(&format!("{name} says"))),
                "PRODUCT: alice's `vox room read --unread` did not show the members' unread \
                 messages: {out}{err}"
            );
        } else {
            refused.push(format!("--unread #{i}: {}", err.trim()));
        }
        let (ok, out, err) = vox(&alice, &["room", "read", &room, "--hashes"], None);
        if ok {
            let lines: Vec<&str> = out.lines().collect();
            assert!(
                lines.len() > BUSY_BACKLOG && lines.iter().all(|line| hashes_line(line)),
                "PRODUCT: alice's `vox room read --hashes` is not the room's whole order \
                 ({} lines): {out}{err}",
                lines.len()
            );
            held_before.get_or_insert(lines.len());
            held_after = lines.len();
        } else {
            refused.push(format!("--hashes #{i}: {}", err.trim()));
        }
        let text = format!("busy reply {i}");
        let (ok, out, err) = vox(
            &alice,
            &["room", "post", &room, "--re", &prefix, &text],
            None,
        );
        if !ok {
            refused.push(format!("--re #{i}: {}{}", out.trim(), err.trim()));
        }
    }
    let posted_during = posted.load(Ordering::Relaxed) - posted_before;
    stop.store(true, Ordering::Relaxed);
    for poster in posters {
        let (attempts, spent, refusal) = poster
            .join()
            .unwrap_or_else(|_| panic!("APPARATUS: a posting thread panicked"));
        println!(
            "[proof] a member tried {attempts} posts, {:?} each on average; first refused: \
             {refusal:?}",
            spent / u32::try_from(attempts.max(1)).unwrap_or(u32::MAX)
        );
    }
    println!(
        "[proof] while alice read {BUSY_READS} times each way, the members posted \
         {posted_during}; her --hashes went from {held_before:?} to {held_after} entries; \
         refused: {}",
        refused.len()
    );
    for line in said(&alice, "alice")
        .lines()
        .filter(|line| line.contains(" engaged"))
    {
        println!("[proof] alice's daemon said: {line}");
    }
    assert!(
        posted_during >= BUSY_AUTHORS.len() && held_before.is_none_or(|b| held_after > b),
        "APPARATUS NO RESULT: nothing arrived while alice read (posted {posted_during}, \
         --hashes {held_before:?} to {held_after})"
    );
    assert!(
        refused.is_empty(),
        "PRODUCT: in a room where {} members keep posting, alice's reads that take more than one \
         request were refused although no row she had read changed: {refused:#?}",
        BUSY_AUTHORS.len()
    );
    let replies = room_rows(&alice, &room)
        .iter()
        .filter(|row| row.to_string().contains("busy reply ") && row["envelope"]["re"] == target)
        .count();
    assert!(
        replies == BUSY_READS,
        "PRODUCT: {replies} of alice's {BUSY_READS} replies by the prefix {prefix} answer {target}"
    );
    drop(daemons);
}

/// The optional arm: half again past one sender-key generation (1,000 messages), from one author.
#[cfg(feature = "optional-proofs")]
#[test]
#[ignore = "real vox daemons, 1,500 CLI posts and production Argon2id; optional, run it in release"]
fn a_newcomer_trusted_before_every_post_reads_all_of_them() {
    watchdog::arm();
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
    watchdog::arm();
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

/// The test-only hold alice's restarted daemon reads (ledger 75): while its file exists her join
/// admissions are answered "room governance is refreshing", and while `<file>.seat` exists so are
/// her joins' seats. Each admission answered so, held or not, appends its joiner's fingerprint to
/// `<file>.met`, each seat to `<file>.seat.met`: one line per answer. While `<file>.lease` exists
/// her daemon's Computer publication lease is held from the next admission request on, as a
/// policy transition holds it, and each admission requested while it is held appends its joiner
/// to `<file>.lease.met`.
const JOIN_REFRESH_HOLD: &str = "VOX_TEST_HOLD_JOIN_REFRESH_FILE";
/// The mutant switch alice's daemon reads: `self-wake` takes a refused admission's own completion
/// for the room having moved on (the first version of the fix); `busy-own-wake` takes a busy
/// admission's own completion for the Computer lease's release (the second); any other value
/// answers a join at once while the room's governance refreshes, as before ledger 75.
const JOIN_REFRESH_MUTANT: &str = "VOX_MUTANT_JOIN_REFRESH";
/// How long the lease arm keeps alice's Computer publication lease held once bob's admission has
/// met it: staging, well inside her 20 s admission patience; no verdict reads it.
const LEASE_HELD_FOR: Duration = Duration::from_secs(3);

/// Alice's room just after her restart (ledger 75): alice and carol in it, carol reading alice;
/// alice's daemon stopped while carol posted, then started again on its own address reading the
/// hold's switch (and the mutant's, when the proof runs under it) with the named holds in place;
/// the newcomers' daemons running. Every identity consents to every other.
struct JustRestarted {
    tmp: tempfile::TempDir,
    alice: std::path::PathBuf,
    carol: std::path::PathBuf,
    /// Each newcomer's name, profile and fingerprint.
    newcomers: Vec<(&'static str, std::path::PathBuf, String)>,
    room: String,
    link: String,
    hold: std::path::PathBuf,
    _daemons: Vec<Daemon>,
}

impl JustRestarted {
    /// The hold's file with `suffix`: "" the admission hold, ".seat" the seat hold, ".met" and
    /// ".seat.met" the doors' records.
    fn marker(&self, suffix: &str) -> std::path::PathBuf {
        let mut path = self.hold.clone().into_os_string();
        path.push(suffix);
        std::path::PathBuf::from(path)
    }

    /// Release a hold.
    fn release(&self, suffix: &str) {
        std::fs::remove_file(self.marker(suffix))
            .unwrap_or_else(|e| panic!("APPARATUS: releasing the hold{suffix}: {e}"));
    }

    /// The joiners a door answered "refreshing", once per answer, as alice's daemon wrote them.
    fn met(&self, record: &str) -> Vec<String> {
        std::fs::read_to_string(self.marker(record))
            .unwrap_or_default()
            .lines()
            .map(str::to_owned)
            .collect()
    }

    /// Start `vox room join` through alice as a person runs it; what it says is kept in
    /// `<who>-join<attempt>.{out,err}`.
    fn join(&self, who: &str, dir: &Path, attempt: usize) -> Child {
        let file = |kind: &str| {
            let at = self.tmp.path().join(format!("{who}-join{attempt}.{kind}"));
            std::fs::File::create(&at)
                .unwrap_or_else(|e| panic!("APPARATUS: could not create {}: {e}", at.display()))
        };
        let mut join = Command::new(VOX)
            .args(["room", "join", "--passphrase-file", "-", &self.link])
            .env("VOX_DATA_DIR", dir)
            .env("VOX_CONFIG_DIR", dir.join("cfg"))
            .env("VOX_IDENTITY_PASSPHRASE", IDENTITY)
            .env_remove("VOX_ROOM")
            .env_remove("VOX_SESSION")
            .stdin(Stdio::piped())
            .stdout(Stdio::from(file("out")))
            .stderr(Stdio::from(file("err")))
            .spawn()
            .unwrap_or_else(|e| panic!("APPARATUS: could not run {who}'s `vox room join`: {e}"));
        if let Err(e) = join
            .stdin
            .take()
            .expect("APPARATUS: a piped stdin")
            .write_all(format!("{ROOMPASS}\n").as_bytes())
        {
            eprintln!("[harness] {who}'s join did not take its passphrase: {e}");
        }
        join
    }

    /// What a `vox room join` started by [`Self::join`] said on stderr.
    fn join_said(&self, who: &str, attempt: usize) -> String {
        std::fs::read_to_string(self.tmp.path().join(format!("{who}-join{attempt}.err")))
            .unwrap_or_default()
    }

    /// What alice's restarted daemon said about joins that did not complete.
    fn alice_refused(&self) -> Vec<String> {
        said(&self.alice, "alice-restarted")
            .lines()
            .filter(|line| line.contains("join did not complete"))
            .map(str::to_owned)
            .collect()
    }

    /// The fingerprints alice lists among the room's members (`vox status --json`).
    fn members(&self) -> Vec<String> {
        let (ok, status, err) = vox(&self.alice, &["status", "--json"], None);
        assert!(ok, "PRODUCT: alice's `vox status --json` failed: {err}");
        let status: serde_json::Value = serde_json::from_str(&status)
            .unwrap_or_else(|e| panic!("PRODUCT: alice's `vox status --json` is not JSON: {e}"));
        status["rooms"]
            .as_array()
            .and_then(|rooms| {
                rooms.iter().find(|row| {
                    row["id"]
                        .as_str()
                        .is_some_and(|id| id.starts_with(&self.room))
                })
            })
            .and_then(|row| row["members"].as_array())
            .map(|rows| {
                rows.iter()
                    .filter_map(|row| row["id"].as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Carol posts `text`: a room publication at alice, as a finished fold turn is.
    fn carol_posts(&self, text: &str) {
        let (ok, out, err) = vox(&self.carol, &["room", "post", &self.room, text], None);
        assert!(
            ok,
            "PRODUCT (staging): carol's post was refused: {out}{err}"
        );
    }
}

/// Stage [`JustRestarted`] for `newcomers`, with the holds named by `held` ("" admission, ".seat"
/// seat) in place before alice's daemon starts again.
fn just_restarted(newcomers: &[&'static str], held: &[&str]) -> JustRestarted {
    let mutant = std::env::var(JOIN_REFRESH_MUTANT).ok();
    let mut knobs = vec![JOIN_REFRESH_HOLD];
    if mutant.is_some() {
        knobs.push(JOIN_REFRESH_MUTANT);
    }
    test_knobs::require(&knobs);
    let tmp = tempfile::tempdir().unwrap_or_else(|e| panic!("APPARATUS: no temp dir: {e}"));
    let root = tmp.path();
    let names: Vec<&'static str> = ["alice", "carol"]
        .into_iter()
        .chain(newcomers.iter().copied())
        .collect();
    let dirs: Vec<std::path::PathBuf> = names.iter().map(|name| root.join(name)).collect();
    for d in &dirs {
        std::fs::create_dir_all(d.join("cfg"))
            .unwrap_or_else(|e| panic!("APPARATUS: could not create {}: {e}", d.display()));
    }
    let (alice, carol) = (dirs[0].clone(), dirs[1].clone());

    // ---- every identity, each consenting to the others before any daemon runs ---------------
    let mut fps = Vec::new();
    for dir in &dirs {
        let (ok, out, err) = vox(dir, &["id"], None);
        assert!(ok, "PRODUCT (staging): `vox id` failed: {err}");
        fps.push(out.trim().to_owned());
    }
    for (i, dir) in dirs.iter().enumerate() {
        for (j, name) in names.iter().enumerate() {
            if i != j {
                let (ok, _, err) = vox(dir, &["trust", "add", &fps[j], "--name", name], None);
                assert!(
                    ok,
                    "PRODUCT (staging): `vox trust add` of {name} failed: {err}"
                );
            }
        }
    }

    // ---- alice's room, carol in it, each reading the other -----------------------------------
    let alice_first = daemon(&alice, "alice");
    attached(&alice, "alice");
    let (ok, _, err) = vox(
        &alice,
        &[
            "room",
            "create",
            "--passphrase-file",
            "-",
            "--name",
            "restart",
        ],
        Some(&format!("{ROOMPASS}\n")),
    );
    assert!(ok, "PRODUCT (staging): `vox room create` failed: {err}");
    let listed = attached(&alice, "alice");
    let room = listed
        .split_whitespace()
        .find(|w| w.len() >= 8 && w.chars().all(|c| c.is_ascii_alphanumeric()))
        .unwrap_or_else(|| panic!("PRODUCT (staging): `vox room list` shows no room id: {listed}"))
        .to_owned();
    let (ok, link, err) = vox(&alice, &["room", "link", &room], None);
    assert!(ok, "PRODUCT (staging): `vox room link` failed: {err}");
    let link = link.trim().to_owned();
    let (ok, status, err) = vox(&alice, &["status", "--json"], None);
    assert!(
        ok,
        "PRODUCT (staging): alice's `vox status --json` failed: {err}"
    );
    let listen = ports::loopback_listen(&status).unwrap_or_else(|| {
        panic!("PRODUCT (staging): alice's `vox status --json` names no loopback address: {status}")
    });
    let mut daemons = vec![daemon(&carol, "carol")];
    attached(&carol, "carol");
    let (ok, out, err) = vox(
        &carol,
        &["room", "join", "--passphrase-file", "-", &link],
        Some(&format!("{ROOMPASS}\n")),
    );
    assert!(
        ok,
        "PRODUCT (staging): carol's `vox room join` failed: {out}{err}"
    );
    let before = "alice before her restart";
    let (ok, out, err) = vox(&alice, &["room", "post", &room, before], None);
    assert!(
        ok,
        "PRODUCT (staging): alice's post was refused: {out}{err}"
    );
    let posted = Instant::now();
    while !reads(&carol, &room, before) {
        assert!(
            posted.elapsed() < READY_WITHIN,
            "PRODUCT (staging): carol, a member, did not read alice's post within {READY_WITHIN:?}"
        );
        std::thread::sleep(Duration::from_millis(200));
    }

    // ---- alice stops; carol posts; alice starts again on her own address, the holds armed ----
    alice_first.stop();
    let (ok, out, err) = vox(
        &carol,
        &["room", "post", &room, "carol while alice was down"],
        None,
    );
    assert!(
        ok,
        "PRODUCT (staging): carol's post while alice was down was refused: {out}{err}"
    );
    let hold = root.join("join-refresh-hold");
    for suffix in held {
        let mut at = hold.clone().into_os_string();
        at.push(suffix);
        std::fs::write(&at, "hold").unwrap_or_else(|e| panic!("APPARATUS: writing the hold: {e}"));
    }
    let hold_path = hold.to_str().expect("APPARATUS: a UTF-8 temp path");
    let mut env = vec![(JOIN_REFRESH_HOLD, hold_path)];
    if let Some(mutant) = &mutant {
        env.push((JOIN_REFRESH_MUTANT, mutant.as_str()));
    }
    let listen = listen.to_string();
    let mut alice_back = daemon_with(&alice, "alice-restarted", &["--listen", &listen], &env);
    loop {
        if let Ok(Some(exit)) = alice_back.0.try_wait() {
            let said = said(&alice, "alice-restarted");
            assert!(
                !ports::bind_refused(&said),
                "{}: {said}",
                ports::APPARATUS_BIND
            );
            panic!("PRODUCT (staging): alice's restarted daemon exited {exit}: {said}");
        }
        if vox(&alice, &["room", "list"], None).0 {
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    daemons.push(alice_back);
    let newcomers: Vec<(&'static str, std::path::PathBuf, String)> = names
        .iter()
        .zip(dirs.iter().zip(fps))
        .skip(2)
        .map(|(name, (dir, fp))| (*name, dir.clone(), fp))
        .collect();
    for (name, dir, _) in &newcomers {
        daemons.push(daemon(dir, name));
        attached(dir, name);
    }
    JustRestarted {
        tmp,
        alice,
        carol,
        newcomers,
        room,
        link,
        hold,
        _daemons: daemons,
    }
}

/// **A join through a member that has just restarted gets in** (claim 3, ledger 75). Alice and
/// carol share a room; alice's daemon stops, carol posts, alice's daemon starts again on the same
/// address, and bob and dave join through her at once while her admissions answer that the room's
/// governance is refreshing. Each join must succeed, each newcomer is a member once, and from
/// their return each reads alice and carol and both read each within [`READY_WITHIN`].
#[test]
#[ignore = "real vox daemons, a restart and a test-only hold; run with test-knobs in release"]
fn a_join_through_a_member_that_just_restarted_gets_in() {
    watchdog::arm();
    let at = just_restarted(&["bob", "dave"], &[""]);
    let mut joins: Vec<(&str, Child, Option<std::process::ExitStatus>)> = at
        .newcomers
        .iter()
        .map(|(who, dir, _)| (*who, at.join(who, dir, 1), None))
        .collect();
    // The newcomers whose admission met alice's refresh, as her daemon names them.
    let met = || at.met(".met").into_iter().collect::<BTreeSet<String>>();
    // Released once both admissions have met the refresh (or a join has already returned):
    // carol's next post is a room publication at alice, as a finished fold turn is.
    let mut released = false;
    while joins.iter().any(|(_, _, exit)| exit.is_none()) {
        for (_, join, exit) in &mut joins {
            if exit.is_none() {
                *exit = join.try_wait().ok().flatten();
            }
        }
        if !released && (met().len() >= 2 || joins.iter().any(|(_, _, exit)| exit.is_some())) {
            at.release("");
            at.carol_posts("carol wakes alice");
            released = true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let joined = Instant::now();
    let alice_said = at.alice_refused();
    let refused: Vec<String> = joins
        .iter()
        .filter(|(_, _, exit)| !exit.is_some_and(|exit| exit.success()))
        .map(|(who, _, exit)| format!("{who} ({exit:?}):\n{}", at.join_said(who, 1)))
        .collect();
    let met = met();
    assert!(
        !met.is_empty(),
        "APPARATUS: no join admission met alice's governance refresh, so this run did not stage \
         the window; joins refused: {refused:?}"
    );
    assert!(
        refused.is_empty(),
        "PRODUCT: a `vox room join` through alice, just restarted, was refused while her \
         admissions answered that the room's governance is refreshing:\n{}\nalice's daemon said: {alice_said:?}",
        refused.join("\n")
    );
    let unmet: Vec<&str> = at
        .newcomers
        .iter()
        .filter(|(_, _, fp)| !met.contains(fp.as_str()))
        .map(|(who, _, _)| *who)
        .collect();
    assert!(
        unmet.is_empty(),
        "APPARATUS: the admission of {unmet:?} never met alice's governance refresh, so this run \
         did not stage both joins in it"
    );

    // ---- each newcomer a member once, on the member that admitted them ---------------------
    let members = at.members();
    for (who, _, fp) in &at.newcomers {
        let times = members.iter().filter(|id| *id == fp).count();
        assert!(
            times == 1,
            "PRODUCT: alice lists {who} {times} time(s) among the room's members: {members:?}"
        );
    }

    // ---- from the joins' return: each newcomer reads alice and carol, and both read each ---
    let (bob, dave) = (&at.newcomers[0].1, &at.newcomers[1].1);
    let (alice_after, carol_after) = ("alice after the joins", "carol after the joins");
    for (dir, who, text) in [
        (&at.alice, "alice", alice_after),
        (&at.carol, "carol", carol_after),
        (bob, "bob", "bob is here"),
        (dave, "dave", "dave is here"),
    ] {
        let (ok, out, err) = vox(dir, &["room", "post", &at.room, text], None);
        assert!(
            ok,
            "PRODUCT: {who}'s post after the joins was refused: {out}{err}"
        );
    }
    let reader = |who: &str| match who {
        "alice" => &at.alice,
        "carol" => &at.carol,
        "bob" => bob,
        _ => dave,
    };
    let mut missing: Vec<(&str, &str)> = vec![
        ("bob", alice_after),
        ("bob", carol_after),
        ("dave", alice_after),
        ("dave", carol_after),
        ("alice", "bob is here"),
        ("carol", "bob is here"),
        ("alice", "dave is here"),
        ("carol", "dave is here"),
    ];
    while !missing.is_empty() && joined.elapsed() < READY_WITHIN {
        missing.retain(|(who, text)| !reads(reader(who), &at.room, text));
        std::thread::sleep(Duration::from_millis(200));
    }
    assert!(
        missing.is_empty(),
        "PRODUCT: within {READY_WITHIN:?} of the joins returning, these were not read (reader, \
         post): {missing:?}\nalice's daemon said: {}",
        said(&at.alice, "alice-restarted")
    );
    println!(
        "[proof] bob and dave joined through alice just back from a restart, both admissions \
         having met her governance refresh; every way read {:?} after the joins returned",
        joined.elapsed()
    );
}

/// **A join whose seat meets the refresh gets in too** (claim 3, the seat's door). As above, but
/// alice's room is already refreshing when bob's seat is reserved: her seat reservation answers
/// "refreshing" until the proof sees bob's seat meet it, then it is released and carol posts. Bob's
/// join must succeed and alice must list him once.
#[test]
#[ignore = "real vox daemons, a restart and a test-only hold; run with test-knobs in release"]
fn a_join_through_a_member_refreshing_when_its_seat_is_reserved_gets_in() {
    watchdog::arm();
    let at = just_restarted(&["bob"], &[".seat"]);
    let (_, bob, bob_fp) = &at.newcomers[0];
    let mut join = at.join("bob", bob, 1);
    // Released once bob's seat has met the refresh: carol's next post is a room publication at
    // alice, as a finished fold turn is.
    let mut released = false;
    while join.try_wait().ok().flatten().is_none() {
        if !released && at.met(".seat.met").contains(bob_fp) {
            at.release(".seat");
            at.carol_posts("carol wakes alice");
            released = true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let exit = join
        .wait()
        .unwrap_or_else(|e| panic!("APPARATUS: waiting for bob's join: {e}"));
    let bob_said = at.join_said("bob", 1);
    assert!(
        at.met(".seat.met").contains(bob_fp),
        "APPARATUS: bob's seat never met alice's governance refresh, so this run did not stage \
         the seat's door; bob said: {bob_said}"
    );
    assert!(
        exit.success(),
        "PRODUCT: a `vox room join` through alice, just restarted, was refused when her room's \
         governance was refreshing as his seat was reserved ({exit}):\n{bob_said}\nalice's daemon \
         said: {:?}",
        at.alice_refused()
    );
    let members = at.members();
    let times = members.iter().filter(|id| *id == bob_fp).count();
    assert!(
        times == 1,
        "PRODUCT: alice lists bob {times} time(s) among the room's members: {members:?}"
    );
    println!(
        "[proof] bob joined through alice, just restarted, his seat having met her governance \
         refresh; listed once"
    );
}

/// **A join whose admission meets the Computer's publication lease held gets in once it is
/// released** (claim 3, the second source of "room publication is busy"). From bob's admission
/// request alice's daemon holds its Computer publication lease, as a policy transition holds it,
/// so his admission is answered "busy". While it stands nothing releases it, so alice must ask
/// bob's admission once; the proof keeps it for [`LEASE_HELD_FOR`], then releases it, and bob's
/// join must succeed and alice list him once.
#[test]
#[ignore = "real vox daemons, a restart and a test-only hold; run with test-knobs in release"]
fn a_join_whose_admission_meets_the_computer_lease_gets_in_once_it_is_released() {
    watchdog::arm();
    let at = just_restarted(&["bob"], &[".lease"]);
    let (_, bob, bob_fp) = &at.newcomers[0];
    let mut join = at.join("bob", bob, 1);
    let mut met = None;
    let mut released = false;
    while join.try_wait().ok().flatten().is_none() {
        if met.is_none() && at.met(".lease.met").contains(bob_fp) {
            met = Some(Instant::now());
        }
        if !released && met.is_some_and(|met| met.elapsed() >= LEASE_HELD_FOR) {
            at.release(".lease");
            released = true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let exit = join
        .wait()
        .unwrap_or_else(|e| panic!("APPARATUS: waiting for bob's join: {e}"));
    let bob_said = at.join_said("bob", 1);
    // Recorded only while the hold's file exists: the attempts made while the lease stood.
    let attempts = at
        .met(".lease.met")
        .iter()
        .filter(|fp| *fp == bob_fp)
        .count();
    assert!(
        attempts >= 1,
        "APPARATUS: bob's admission never met alice's held Computer publication lease, so this run \
         did not stage it ({exit}); bob said: {bob_said}"
    );
    assert!(
        attempts == 1,
        "PRODUCT: alice asked bob's admission {attempts} times while her Computer publication \
         lease stood and nothing released it: a busy refusal taken for the lease's release \
         ({exit})\nbob said: {bob_said}\nalice's daemon said: {:?}",
        at.alice_refused()
    );
    assert!(
        released && exit.success(),
        "PRODUCT: bob's `vox room join` through alice was refused although her Computer \
         publication lease was released inside her admission patience (released: {released}, \
         {exit}):\n{bob_said}\nalice's daemon said: {:?}",
        at.alice_refused()
    );
    let members = at.members();
    let times = members.iter().filter(|id| *id == bob_fp).count();
    assert!(
        times == 1,
        "PRODUCT: alice lists bob {times} time(s) among the room's members: {members:?}"
    );
    println!(
        "[proof] bob's admission met alice's held Computer publication lease once; released after \
         {LEASE_HELD_FOR:?}, he joined and is listed once"
    );
}

/// **A join whose admission stays refreshing is refused once, in time, and leaves nothing**
/// (claim 3, run-out). Alice's admissions answer "refreshing" and the hold is not released: alice
/// asks bob's admission once (nothing in this run can make her room ready, so asking again would
/// be asking with nothing changed), stops at her admission patience, and bob is told so before
/// his own wait for her answer runs out. Neither side counts bob a member. Once the hold is
/// released, bob's second join gets in at once and so does dave's.
#[test]
#[ignore = "real vox daemons, a restart and a test-only hold; run with test-knobs in release"]
fn a_join_whose_admission_stays_refreshing_is_refused_in_time_and_leaves_nothing() {
    watchdog::arm();
    let at = just_restarted(&["bob", "dave"], &[""]);
    let (_, bob, bob_fp) = &at.newcomers[0];
    let (_, dave, dave_fp) = &at.newcomers[1];
    let started = Instant::now();
    let exit = at
        .join("bob", bob, 1)
        .wait()
        .unwrap_or_else(|e| panic!("APPARATUS: waiting for bob's join: {e}"));
    let took = started.elapsed();
    let bob_said = at.join_said("bob", 1);
    let attempts = at.met(".met").iter().filter(|fp| *fp == bob_fp).count();
    assert!(
        attempts >= 1,
        "APPARATUS: bob's admission never met alice's held refresh, so this run did not stage the \
         run-out ({exit}); bob said: {bob_said}"
    );
    assert!(
        attempts == 1,
        "PRODUCT: alice asked bob's admission {attempts} times while her governance stayed \
         refreshing and nothing could make it ready: a refusal taken for progress ({exit}, after \
         {took:?})\nbob said: {bob_said}\nalice's daemon said: {:?}",
        at.alice_refused()
    );
    assert!(
        !exit.success(),
        "PRODUCT: bob's `vox room join` succeeded while every admission alice made answered \
         'refreshing': {bob_said}"
    );
    assert!(
        bob_said.contains("could not admit this identity")
            && !bob_said.contains("no complete frame in time"),
        "PRODUCT: bob was not told alice's refusal before his own wait for her answer ran out \
         ({exit}, after {took:?}): {bob_said}"
    );
    // Alice's join task, the slot's holder, says it ended once it has.
    let short = &bob_fp[..12];
    let ended = loop {
        let refused = at.alice_refused();
        if let Some(line) = refused.into_iter().find(|line| line.contains(short)) {
            break line;
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    assert!(
        ended.contains("room governance is refreshing"),
        "PRODUCT: alice ended bob's join for another reason than her refreshing governance: {ended}"
    );

    // ---- nothing admitted on either side -----------------------------------------------------
    let members = at.members();
    assert!(
        !members.contains(bob_fp),
        "PRODUCT: alice lists bob among the room's members after refusing him: {members:?}"
    );
    let bob_rooms = attached(bob, "bob");
    assert!(
        !bob_rooms.contains(&at.room),
        "PRODUCT: bob lists the room he was refused: {bob_rooms}"
    );

    // ---- released: bob's second join and dave's get in ----------------------------------------
    at.release("");
    for (who, dir, fp, attempt) in [("bob", bob, bob_fp, 2), ("dave", dave, dave_fp, 1)] {
        let exit = at
            .join(who, dir, attempt)
            .wait()
            .unwrap_or_else(|e| panic!("APPARATUS: waiting for {who}'s join: {e}"));
        assert!(
            exit.success(),
            "PRODUCT: {who}'s `vox room join` after the hold was released was refused ({exit}): {}",
            at.join_said(who, attempt)
        );
        let members = at.members();
        let times = members.iter().filter(|id| *id == fp).count();
        assert!(
            times == 1,
            "PRODUCT: alice lists {who} {times} time(s) among the room's members: {members:?}"
        );
    }
    println!(
        "[proof] bob's admission met alice's held refresh once and he was refused after {took:?}: \
         alice said {ended:?}; bob said {:?}; released, bob's second join and dave's got in",
        bob_said.lines().next().unwrap_or_default()
    );
}

/// `vox room post` started as its own process, not waited for, so a slow daemon delays only that
/// author's answer and never the next post's offer (the busy-room journey's poster).
#[cfg(feature = "optional-proofs")]
fn offer_post(dir: &Path, room: &str, text: &str) -> Child {
    Command::new(VOX)
        .args(["room", "post", room, text])
        .env("VOX_DATA_DIR", dir)
        .env("VOX_CONFIG_DIR", dir.join("cfg"))
        .env("VOX_IDENTITY_PASSPHRASE", IDENTITY)
        .env_remove("VOX_ROOM")
        .env_remove("VOX_SESSION")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("APPARATUS: could not run {VOX} room post: {e}"))
}

/// How many posts z makes after y becomes slow: twice the journey's 100, so the rule is applied
/// past the point where flows kept for y would fill the node's retained positions.
#[cfg(feature = "optional-proofs")]
const SLOW_MEMBER_POSTS: usize = 200;

/// **A slow member delays only itself** (ADR-052 RG-6, "a slow peer delays only itself"; the
/// busy-room journey's HELD group, reduced to three daemons).
///
/// Staging: y, z and n trust each other before any daemon runs. y creates the room, z joins from
/// y's link and n from z's, and each shows the other two's first post. Then y is made slow for n,
/// in the shape the busy-room journey traced: y's daemon reads each history request n sends it
/// and answers nothing while the connection stays up (`VOX_TEST_HOLD_HISTORY_SERVE_FILE`).
/// z serves the evidence it actually holds, without a forced refusal. From then y and z each
/// offer a post once a second.
///
/// GREEN: until z has [`SLOW_MEMBER_POSTS`] posts acknowledged after y became slow, n's `vox room
/// read` always shows one of z's latest 100 (the busy-room journey's own rule, counted in posts,
/// applied all the way through), and no post is refused. RED PRODUCT: z acknowledged 100 posts
/// in a row and n shows none of them, or a post was refused. APPARATUS: y never held a request
/// of n's (y's stderr `holding a history request from <n>`, the staging switch's own line).
/// `VOX_PROOF_SLOW_OFF=1` runs without y's hold (a control, never a verdict).
///
/// Mutant (ADR-054 M2), passed to n's daemon, its engaged line required on n's stderr:
/// `VOX_MUTANT_ONE_ASK_PER_NODE` (one history request in flight per node: n's request held by y
/// keeps n's loop toward z from asking).
#[cfg(feature = "optional-proofs")]
#[test]
#[ignore = "three real daemons, one made slow by a test-only hold; optional, run it QUIET in release"]
fn a_slow_member_delays_only_itself() {
    slow_member_scene();
}

#[cfg(feature = "optional-proofs")]
fn slow_member_scene() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    watchdog::arm();
    test_knobs::require(&["VOX_TEST_HOLD_HISTORY_SERVE_FILE"]);
    let mutant = "VOX_MUTANT_ONE_ASK_PER_NODE";
    let mutant_value = std::env::var(mutant).ok();
    if mutant_value.is_some() {
        test_knobs::require(&[mutant]);
    }
    let mut tmp = tempfile::tempdir().unwrap_or_else(|e| panic!("APPARATUS: no temp dir: {e}"));
    if std::env::var_os("VOX_PROOF_KEEP_DIRS").is_some() {
        tmp.disable_cleanup(true);
    }
    let slow_on = std::env::var("VOX_PROOF_SLOW_OFF").as_deref() != Ok("1");
    println!(
        "[slow-member] scratch={} y_slow={slow_on} {mutant}={mutant_value:?}",
        tmp.path().display()
    );
    let root = tmp.path();
    let names = ["y", "z", "n"];
    let [y, z, n] = names.map(|name| {
        let dir = root.join(name);
        std::fs::create_dir_all(dir.join("cfg"))
            .unwrap_or_else(|e| panic!("APPARATUS: could not create {}: {e}", dir.display()));
        dir
    });
    let mut fps = Vec::new();
    for dir in [&y, &z, &n] {
        let (ok, out, err) = vox(dir, &["id"], None);
        assert!(ok, "PRODUCT: `vox id` failed: {err}");
        fps.push(out.trim().to_owned());
    }
    for (i, dir) in [&y, &z, &n].into_iter().enumerate() {
        for (j, fp) in fps.iter().enumerate() {
            if i != j {
                let (ok, _, err) = vox(dir, &["trust", "add", fp, "--name", names[j]], None);
                assert!(
                    ok,
                    "PRODUCT: {}'s `vox trust add` of {} failed: {err}",
                    names[i], names[j]
                );
            }
        }
    }
    let holds = root.join("y-holds");
    let y_daemon = daemon_env(
        &y,
        "y",
        &[("VOX_TEST_HOLD_HISTORY_SERVE_FILE", holds.to_str().unwrap())],
    );
    attached(&y, "y");
    let (ok, _, err) = vox(
        &y,
        &["room", "create", "--passphrase-file", "-", "--name", "slow"],
        Some(&format!("{ROOMPASS}\n")),
    );
    assert!(ok, "PRODUCT: y's `vox room create` failed: {err}");
    let listed = attached(&y, "y");
    let room = listed
        .split_whitespace()
        .find(|w| w.len() >= 8 && w.chars().all(|c| c.is_ascii_alphanumeric()))
        .unwrap_or_else(|| panic!("PRODUCT: `vox room list` shows no room id: {listed}"))
        .to_owned();
    let z_daemon = daemon(&z, "z");
    // The mutant is handed to n's daemon by name; the act never relies on inherited environment.
    let n_env: Vec<(&str, &str)> = mutant_value
        .as_deref()
        .map(|value| (mutant, value))
        .into_iter()
        .collect();
    let n_daemon = daemon_env(&n, "n", &n_env);
    for (dir, who, from) in [(&z, "z", &y), (&n, "n", &z)] {
        attached(dir, who);
        let (ok, link, err) = vox(from, &["room", "link", &room], None);
        assert!(ok, "PRODUCT: `vox room link` failed: {err}");
        let (ok, _, err) = vox(
            dir,
            &["room", "join", "--passphrase-file", "-", link.trim()],
            Some(&format!("{ROOMPASS}\n")),
        );
        assert!(ok, "PRODUCT: {who}'s `vox room join` was refused: {err}");
    }
    // Everyone shows everyone before y becomes slow: n holds what it needs of y's feed so far.
    for (dir, who) in [(&y, "y"), (&z, "z"), (&n, "n")] {
        let (ok, _, err) = vox(dir, &["room", "post", &room, &format!("{who} seed")], None);
        assert!(ok, "PRODUCT: {who}'s first post was refused: {err}");
    }
    for (dir, who) in [(&y, "y"), (&z, "z"), (&n, "n")] {
        for other in names.iter().filter(|other| *other != &who) {
            while !reads(dir, &room, &format!("{other} seed")) {
                std::thread::sleep(Duration::from_millis(200));
            }
        }
    }
    println!("[slow-member] y, z and n each show the other two's first post");

    if slow_on {
        std::fs::write(&holds, format!("{}\n", fps[2]))
            .unwrap_or_else(|e| panic!("APPARATUS: could not write {}: {e}", holds.display()));
    }
    let slow = Instant::now();

    // Each author offers a post once a second; the answers are collected as they come.
    let stop = Arc::new(AtomicBool::new(false));
    let acked: [Arc<Mutex<Vec<String>>>; 2] = [Arc::default(), Arc::default()];
    let refused = Arc::new(Mutex::new(Vec::<String>::new()));
    let posters: Vec<_> = [(&y, "y", 0), (&z, "z", 1)]
        .into_iter()
        .map(|(dir, who, slot)| {
            let (dir, room, stop) = (dir.clone(), room.clone(), Arc::clone(&stop));
            let (acked, refused) = (Arc::clone(&acked[slot]), Arc::clone(&refused));
            std::thread::spawn(move || {
                let mut waiting = Vec::new();
                let start = Instant::now();
                let mut k = 0u64;
                while !stop.load(Ordering::SeqCst) {
                    if let Some(wait) =
                        (start + Duration::from_secs(k)).checked_duration_since(Instant::now())
                    {
                        std::thread::sleep(wait);
                    }
                    k += 1;
                    // The `#` ends the number: "z live 1#" is not a prefix of "z live 10#".
                    let text = format!("{who} live {k}#");
                    let child = offer_post(&dir, &room, &text);
                    let (acked, refused) = (Arc::clone(&acked), Arc::clone(&refused));
                    waiting.push(std::thread::spawn(move || match child.wait_with_output() {
                        Ok(out) if out.status.success() => acked.lock().unwrap().push(text),
                        Ok(out) => refused.lock().unwrap().push(format!(
                            "{text}: {}{}",
                            String::from_utf8_lossy(&out.stdout),
                            String::from_utf8_lossy(&out.stderr)
                        )),
                        Err(e) => refused.lock().unwrap().push(format!("{text}: {e}")),
                    }));
                }
                for w in waiting {
                    let _ = w.join();
                }
            })
        })
        .collect();

    let shown_z = loop {
        let z_acked = acked[1].lock().unwrap().clone();
        let read = loop {
            let (ok, read, err) = vox(&n, &["room", "read", &room], None);
            if !ok && room_changed_while_reading(&err) {
                continue;
            }
            assert!(ok, "PRODUCT: n's `vox room read` refused: {read}{err}");
            break read;
        };
        let newest = z_acked
            .iter()
            .filter(|t| read.contains(t.as_str()))
            .filter_map(|t| {
                t.strip_prefix("z live ")?
                    .strip_suffix('#')?
                    .parse::<usize>()
                    .ok()
            })
            .max()
            .unwrap_or(0);
        println!(
            "[slow-member] t={}ms z_acked={} y_acked={} n shows z live {newest}#",
            slow.elapsed().as_millis(),
            z_acked.len(),
            acked[0].lock().unwrap().len(),
        );
        if z_acked.len() >= newest + 100 {
            break Err((z_acked.len(), newest));
        }
        if z_acked.len() >= SLOW_MEMBER_POSTS {
            break Ok(newest);
        }
        std::thread::sleep(Duration::from_millis(1000));
    };
    stop.store(true, Ordering::SeqCst);
    for p in posters {
        let _ = p.join();
    }
    let z_acked = acked[1].lock().unwrap().len();
    let (y_said, n_said) = (said(&y, "y"), said(&n, "n"));
    let held = y_said
        .lines()
        .filter(|l| l.contains(&format!("holding a history request from {}", fps[2])))
        .count();
    println!("[slow-member] y held {held} of n's requests");
    if let Some(value) = &mutant_value {
        let line = n_said
            .lines()
            .find(|l| l.contains(&format!("{mutant} engaged")));
        println!("[slow-member] {mutant}={value:?}; n's daemon: {line:?}");
        assert!(
            line.is_some(),
            "APPARATUS: {mutant} was passed to n's daemon but it never said it engaged"
        );
    }
    assert!(
        held > 0 || !slow_on,
        "APPARATUS: staging not reached: y held none of n's history requests"
    );
    let refused = refused.lock().unwrap().clone();
    assert!(
        refused.is_empty(),
        "RED PRODUCT: posts were refused while y was slow: {refused:?}"
    );
    match shown_z {
        Ok(newest) => println!(
            "GREEN PRODUCT: y_slow={slow_on}; with z at {z_acked} acknowledged posts after y \
             became slow, n always showed one of z's latest 100 (now \"z live {newest}#\"), after \
             {:?}",
            slow.elapsed()
        ),
        Err((acked, newest)) => panic!(
            "RED PRODUCT: y_slow={slow_on}; z acknowledged {acked} posts after y became slow for \
             n and n's `vox room read` shows none of z's latest 100 (newest shown: {newest}, 0 is \
             none)\nn's daemon said: {n_said}"
        ),
    }
    drop(n_daemon);
    drop(z_daemon);
    drop(y_daemon);
}

const FX35_HOSTED: [&str; 15] = [
    "robert", "claude", "codex", "opencode", "kimi", "glm", "fable", "one", "two", "three", "four",
    "five", "six", "seven", "eight",
];
/// The rooms every node is in; the first hosted node makes them.
const QUIET_ROOMS: [&str; 2] = ["quiet-1", "quiet-2"];
/// Hosted nodes and a peer in two rooms.
struct Staged {
    // The daemons first: they are killed before their directories go.
    _host_daemon: Daemon,
    _peer_daemon: Daemon,
    everyone: Vec<(
        std::path::PathBuf,
        Option<&'static str>,
        &'static str,
        String,
    )>,
    rooms: Vec<String>,
    _tmp: tempfile::TempDir,
}

/// Retry only the shipped room's explicit transient "still being applied" refusal. Every other
/// refusal is the exact staging fault; only the proof's external APPARATUS deadman can stop a
/// still-progressing retry sequence.
fn stage_post(dir: &Path, node: Option<&str>, name: &str, room: &str, text: &str) -> Duration {
    let asked = Instant::now();
    loop {
        let (ok, out, err) = stage_post_once(dir, node, room, text);
        if ok {
            return asked.elapsed();
        }
        let busy = err.contains("still being applied") || out.contains("still being applied");
        assert!(
            busy,
            "APPARATUS: {name}'s staging post in {room} was refused before the measured moment: \
             {out}{err}"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// Run one setup post through the shipped binary. This helper owns no product timeout; the proof's
/// external deadman is the only wall-clock apparatus bound.
fn stage_post_once(
    dir: &Path,
    node: Option<&str>,
    room: &str,
    text: &str,
) -> (bool, String, String) {
    let mut args = vec!["room", "post", room, text];
    if let Some(node) = node {
        args.extend(["--node", node]);
    }
    vox(dir, &args, None)
}

/// Stage hosted nodes on one daemon and a peer on another, then post in both rooms.
fn stage_hosted_nodes(hosted: &'static [&'static str]) -> Staged {
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

    // One daemon for the host's nodes, as the decider's Mac runs it: `vox daemon --no-node`, each
    // node made Ready in it with `vox node unlock`. The passphrases it remembers go to the proof's
    // own Keychain file, never the login Keychain.
    let keychain = attach::keychain(&host).to_string_lossy().into_owned();
    let host_daemon = daemon_with(
        &host,
        "host",
        &["--no-node"],
        &[("VOX_TEST_KEYCHAIN", keychain.as_str())],
    );
    while !attach::Root::at(&host, IDENTITY).daemon_running() {
        std::thread::sleep(Duration::from_millis(200));
    }
    for name in hosted {
        unlock(&host, name);
        attached_as(&host, "host", Some(name));
    }
    let peer_daemon = daemon(&peer, "peer");
    attached_as(&peer, "peer", None);

    // Trust in every direction before anyone posts.
    for (dir, node, name, _) in &everyone {
        for (_, _, other, fp) in &everyone {
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
    let mut rooms = Vec::with_capacity(QUIET_ROOMS.len());
    for name in QUIET_ROOMS {
        let maker_name = hosted[0];
        let maker = Some(maker_name);
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
        let room_selector = listed
            .lines()
            .find(|l| l.contains(name))
            .and_then(|l| l.split_whitespace().next())
            .unwrap_or_else(|| panic!("APPARATUS: staged room {name} is not listed: {listed}"))
            .to_owned();
        let room =
            vox_core::node::link::b32_encode(&room_id_as(&host, maker, maker_name, &room_selector));
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
            if !ok {
                let verdict = if err.contains("your passphrase was accepted")
                    && (err.contains("did not answer") || err.contains("sent no frame in time"))
                {
                    "PRODUCT"
                } else {
                    "APPARATUS"
                };
                panic!("{verdict}: {who}'s staging join of {name} was refused: {err}");
            }
        }
        rooms.push(room);
    }
    // One post each in each room. Retry only the explicit no-change refusal while the room
    // applies its last change; callers assess delivery separately from setup.
    for room in &rooms {
        for (dir, node, name, _) in &everyone {
            let text = format!("{name} is here");
            stage_post(dir, *node, name, room, &text);
        }
    }
    eprintln!(
        "[delivery] all {} posts accepted across {} identities and {} rooms; actual member reads follow",
        everyone.len() * rooms.len(),
        everyone.len(),
        rooms.len()
    );
    Staged {
        _host_daemon: host_daemon,
        _peer_daemon: peer_daemon,
        everyone,
        rooms,
        _tmp: tmp,
    }
}

/// Every member reads every other's post.
fn converged(staged: &Staged) {
    let Staged {
        everyone, rooms, ..
    } = staged;
    let mut unread: Vec<String> = Vec::new();
    let mut previous_unread = None;
    loop {
        unread.clear();
        for room in rooms {
            for (dir, node, reader, _) in everyone {
                let (ok, out, err) = vox(dir, &as_node(&["room", "read", room], *node), None);
                if !ok
                    && err.lines().any(|line| {
                        line.trim()
                            .ends_with("the room changed while reading; refresh and retry")
                    })
                {
                    // Follow the same explicit refresh instruction as room_rows; a refused
                    // observation supplies no delivery evidence and cannot complete this journey.
                    unread.push(format!("{reader} must refresh its read of {room}"));
                    continue;
                }
                assert!(
                    ok,
                    "PRODUCT: {reader}'s `vox room read` refused: {out}{err}"
                );
                for (_, _, author, _) in everyone {
                    if author != reader && !out.contains(&format!("{author} is here")) {
                        unread.push(format!("{reader} has not read {author} in {room}"));
                    }
                }
            }
        }
        if previous_unread.as_ref() != Some(&unread) {
            eprintln!(
                "[delivery] ordinary reads still missing {} reader/author/room observations; examples: {:?}",
                unread.len(),
                &unread[..unread.len().min(8)]
            );
            previous_unread = Some(unread.clone());
        }
        if unread.is_empty() {
            break;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}

/// More than eight nodes hosted by one daemon can read one another's posts.
#[cfg(feature = "optional-proofs")]
#[test]
#[ignore = "two real vox daemons, one hosting more than eight nodes; optional, run it in release"]
fn hosted_nodes_read_each_other() {
    watchdog::arm();
    let staged = stage_hosted_nodes(&FX35_HOSTED);
    converged(&staged);
}

/// Members recover readable history and exchange posts after an interrupted history request.
/// Status also names the last room sync, and a late member sees a pruned body as unavailable.
#[cfg(feature = "optional-proofs")]
#[test]
#[ignore = "real vox daemons and private-package staging; optional, run it in release"]
fn interrupted_history_and_private_packages_recover() {
    test_knobs::require(&[
        "VOX_TEST_HOLD_PACKAGES_FILE",
        "VOX_TEST_SERVE_NONRECIPIENT_HISTORY_BODY_FILE",
        "VOX_TEST_FX29_MUTANT",
        "VOX_TEST_FX29_CONTENT_OUTCOME_FILE",
        "VOX_TEST_FX29_CONTENT_REFILL_OUTCOME_FILE",
        "VOX_TEST_FX29_CONTENT_REFILL_HASH",
        "VOX_TEST_HOLD_RETENTION_SWEEP_FILE",
    ]);
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap_or_else(|e| panic!("APPARATUS: no temp dir: {e}"));
    let root = tmp.path();
    let alice = root.join("alice");
    let bob = root.join("bob");
    let carol = root.join("carol");
    let late = root.join("late");
    for d in [&alice, &bob, &carol, &late] {
        std::fs::create_dir_all(d.join("cfg"))
            .unwrap_or_else(|e| panic!("APPARATUS: could not create {}: {e}", d.display()));
    }
    let mut fps = Vec::new();
    for dir in [&alice, &bob, &carol, &late] {
        let (ok, out, err) = vox(dir, &["id"], None);
        assert!(ok, "PRODUCT: `vox id` failed: {err}");
        fps.push(out.trim().to_owned());
    }
    for (dir, fp, name) in [
        (&alice, &fps[1], "bob"),
        (&bob, &fps[0], "alice"),
        (&carol, &fps[0], "alice"),
        (&carol, &fps[1], "bob"),
        (&alice, &fps[3], "late"),
        (&bob, &fps[3], "late"),
        (&carol, &fps[3], "late"),
        (&late, &fps[0], "alice"),
        (&late, &fps[1], "bob"),
        (&late, &fps[2], "carol"),
    ] {
        let (ok, _, err) = vox(dir, &["trust", "add", fp, "--name", name], None);
        assert!(ok, "PRODUCT: `vox trust add` of {name} failed: {err}");
    }
    let hostile = root.join("serve-private-body-once");
    let hostile_path = hostile
        .to_str()
        .expect("APPARATUS: a UTF-8 hostile-body marker path")
        .to_owned();
    let alice_knob = [(
        "VOX_TEST_SERVE_NONRECIPIENT_HISTORY_BODY_FILE",
        hostile_path.as_str(),
    )];
    let sparse_content_outcome = root.join("fx29-sparse-content-outcome");
    let sparse_content_outcome_path = sparse_content_outcome
        .to_str()
        .expect("APPARATUS: a UTF-8 sparse-Content outcome marker path")
        .to_owned();
    let alice_daemon = daemon_env(&alice, "alice", &alice_knob);
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
    let bob_knob = [(
        "VOX_TEST_FX29_CONTENT_OUTCOME_FILE",
        sparse_content_outcome_path.as_str(),
    )];
    let bob_daemon = daemon_env(&bob, "bob", &bob_knob);
    attached(&bob, "bob");
    let (ok, _, err) = vox(
        &bob,
        &["room", "join", "--passphrase-file", "-", &link],
        Some(&format!("{ROOMPASS}\n")),
    );
    assert!(ok, "PRODUCT: bob's `vox room join` was refused: {err}");
    let joined = Instant::now();
    let (ok, out, err) = vox(&bob, &["room", "post", &room, "bob is here"], None);
    assert!(ok, "PRODUCT: bob's first post was refused: {out}{err}");
    eprintln!(
        "[proof] FX-29 sparse control publication apparatus staged: Bob joined room {room} before Alice's next shipped post"
    );
    let (ok, out, err) = vox(&alice, &["room", "post", &room, "--json", "post 1"], None);
    assert!(
        ok,
        "PRODUCT [FX29 sparse-control-publication]: Alice's post after Bob joined was refused: {out}{err}"
    );
    let posted: serde_json::Value = serde_json::from_str(out.trim()).unwrap_or_else(|error| {
        panic!("PRODUCT: Alice's `vox room post --json` response was not JSON: {error}: {out}")
    });
    let alice_post_hash = posted["entry_hash"]
        .as_str()
        .unwrap_or_else(|| {
            panic!("PRODUCT: Alice's `vox room post --json` named no exact entry hash: {out}")
        })
        .to_owned();
    let (to_alice, to_bob) = first_sparse_arrivals(
        joined,
        &alice,
        &bob,
        &room,
        &sparse_content_outcome,
        &alice_post_hash,
        BOUND,
    );
    assert!(
        to_alice.is_some() && to_bob.is_some(),
        "PRODUCT: within {BOUND:?} of the join, alice read bob: {to_alice:?}; bob read alice: \
         {to_bob:?} (None = never)\nbob's daemon said: {}\nalice's daemon said: {}",
        said(&bob, "bob"),
        said(&alice, "alice")
    );
    // Bob is now a real returning member, but is offline while two authors build suffixes.  That
    // makes his next Page settle newer positions before the older private-package header closes
    // Alice's gap, and gives the durable continuation scheduler two authors to rotate.
    bob_daemon.stop();

    // ---- a private package Carol is owed is a header-only, role-complete row on Bob --------
    let hold = root.join("hold-carol-packages");
    let hold_path = hold
        .to_str()
        .expect("APPARATUS: a UTF-8 package-hold path")
        .to_owned();
    let knob = [("VOX_TEST_HOLD_PACKAGES_FILE", hold_path.as_str())];
    let carol_daemon = daemon_env(&carol, "carol", &knob);
    attached(&carol, "carol");
    let (ok, _, err) = vox(
        &carol,
        &["room", "join", "--passphrase-file", "-", &link],
        Some(&format!("{ROOMPASS}\n")),
    );
    assert!(ok, "PRODUCT: carol's `vox room join` was refused: {err}");

    // Carol must be an admitted member in Alice's shipped status before going offline; otherwise
    // Alice cannot address a package to her. Her join completing alone is not that observation on
    // Alice's node. This is causal staging: the operator-selected watchdog owns any apparatus
    // timebox rather than a second elapsed guess here.
    wait_room_open(&carol, &room, "carol-after-join");
    while member_connected(&alice, &room, &fps[2]).is_none() {
        std::thread::yield_now();
    }

    // Alice cannot release her sender key to Carol before Alice trusts her. Therefore Carol
    // cannot possibly acknowledge an Alice row before this trust decision, even though Carol
    // already trusts Alice: demanding that state made the old proof wait for an impossible
    // boundary. Stop Carol first and observe the member disconnected in shipped status.
    carol_daemon.stop();
    while member_connected(&alice, &room, &fps[2]) != Some(false) {
        std::thread::yield_now();
    }
    let before_package_text = "alice row before carol's package";
    let (ok, out, err) = vox(&alice, &["room", "post", &room, before_package_text], None);
    assert!(
        ok,
        "PRODUCT: alice's row before the private package was refused: {out}{err}"
    );
    let before_package_hash = read_hash(&alice, &room, before_package_text).unwrap_or_else(|| {
        panic!(
            "PRODUCT: alice's shipped JSON read omitted the accepted row before the private package"
        )
    });
    let before_package_log = status_log_entries(&alice, &room).unwrap_or_else(|| {
        panic!(
            "PRODUCT: alice's `vox status --json` did not report her contiguous log before the \
             private package was staged"
        )
    });
    let before_package_through = room_own_feed_through(&alice, &room).unwrap_or_else(|| {
        panic!(
            "PRODUCT: alice's `vox status --json` did not name her authenticated feed before the \
             private package was staged"
        )
    });
    let (ok, _, err) = vox(&alice, &["trust", "add", &fps[2], "--name", "carol"], None);
    assert!(
        ok,
        "PRODUCT: alice's `vox trust add` of carol failed: {err}"
    );
    let after_package_log = status_log_entries(&alice, &room).unwrap_or_else(|| {
        panic!(
            "PRODUCT: after Carol's exact failed-direct event, Alice's shipped status omitted \
             the room's contiguous log"
        )
    });
    assert_eq!(
        after_package_log,
        before_package_log.saturating_add(2),
        "PRODUCT: after Carol's exact failed-direct event, Alice's contiguous log advanced from \
         {before_package_log} to {after_package_log}, not by exactly the owed package and consent"
    );
    let package_feed_through = room_own_feed_through(&alice, &room).unwrap_or_else(|| {
        panic!(
            "PRODUCT: after Carol's exact failed-direct event, Alice's shipped status omitted \
             her authenticated feed"
        )
    });
    assert_eq!(
        package_feed_through,
        before_package_through.saturating_add(2),
        "PRODUCT: after Carol's exact failed-direct event, Alice's authenticated feed advanced \
         from {before_package_through} to {package_feed_through}, not by exactly the owed package \
         and consent"
    );
    // `members[].key_waits` is deliberately not evidence here. A cached signed-prekey bundle
    // lets this fallback proceed without ever entering that wait, so observing `null` would not
    // establish either a prior wait or its clearance.

    // Restart Carol with the installer held only after the package exists. Her exact local
    // role-complete cursor must reach Alice's package-bearing feed position: that shipped cursor,
    // not a generic queue bit or an aggregate count, proves she fetched the segment. The pending
    // bit supplements it only by confirming that generic package maintenance remains held.
    std::fs::write(&hold, b"")
        .unwrap_or_else(|e| panic!("APPARATUS: could not create {}: {e}", hold.display()));
    let carol_daemon = daemon_env(&carol, "carol-package-held", &knob);
    attached(&carol, "carol-package-held");
    while member_holds_through(&carol, &room, &fps[0])
        .is_none_or(|through| through < package_feed_through)
        || key_packages_pending(&carol, &room) != Some(true)
    {
        std::thread::yield_now();
    }

    let carol_successors = vox_core::log::history::MAX_PAGE_ENTRIES + 1;
    for n in 0..carol_successors {
        let text = format!("carol settled successor {n}");
        let (ok, out, err) = vox(&carol, &["room", "post", &room, &text], None);
        assert!(ok, "PRODUCT: carol's successor {n} was refused: {out}{err}");
    }
    let carol_tail_through = room_own_feed_through(&carol, &room).unwrap_or_else(|| {
        panic!(
            "PRODUCT: carol's `vox status --json` did not name her authenticated feed after \
             {carol_successors} accepted successors"
        )
    });
    let carol_replicated_deadline = Instant::now() + READY_WITHIN;
    while member_held_through(&carol, &room, &fps[0]) != Some(carol_tail_through) {
        assert!(
            Instant::now() < carol_replicated_deadline,
            "APPARATUS: Alice did not acknowledge Carol's exact feed position \
             {carol_tail_through} within {READY_WITHIN:?}; the offline two-author continuation \
             was not staged\ncarol said: {}\nalice said: {}",
            said(&carol, "carol"),
            said(&alice, "alice")
        );
        std::thread::sleep(Duration::from_millis(200));
    }
    carol_daemon.stop();
    let before_private_suffix = room_own_feed_through(&alice, &room).unwrap_or_else(|| {
        panic!(
            "PRODUCT: alice's `vox status --json` did not name her feed before the private \
             package suffix"
        )
    });
    let alice_successors = vox_core::log::history::MAX_PAGE_ENTRIES + 1;
    for n in 0..alice_successors {
        let text = format!("alice settled successor {n}");
        let (ok, out, err) = vox(&alice, &["room", "post", &room, &text], None);
        assert!(ok, "PRODUCT: alice's successor {n} was refused: {out}{err}");
    }
    let package_marker = format!("alice settled successor {}", alice_successors - 1);
    let marker_through = room_own_feed_through(&alice, &room).unwrap_or_else(|| {
        panic!(
            "PRODUCT: alice's `vox status --json` did not name her authenticated room-feed \
             position after the package marker"
        )
    });
    assert!(
        marker_through.saturating_sub(before_private_suffix)
            > vox_core::log::history::MAX_PAGE_ENTRIES as u64,
        "APPARATUS: Alice's authenticated feed advanced only from {before_private_suffix} to \
         {marker_through}; the private-package suffix did not exceed the production page bound {}",
        vox_core::log::history::MAX_PAGE_ENTRIES
    );

    std::fs::write(&hostile, b"")
        .unwrap_or_else(|e| panic!("APPARATUS: could not create {}: {e}", hostile.display()));
    let bob_after_gap = daemon(&bob, "bob-after-gap");
    attached(&bob, "bob-after-gap");
    wait_room_open(&bob, &room, "bob-after-gap");
    let marker_deadline = Instant::now() + READY_WITHIN;
    while !reads(&bob, &room, &package_marker) {
        assert!(
            Instant::now() < marker_deadline,
            "PRODUCT: Bob did not read Alice's newest marker within {READY_WITHIN:?}; the shipped \
             archive request could not be staged\nbob said: {}",
            said(&bob, "bob-after-gap")
        );
        std::thread::sleep(Duration::from_millis(200));
    }
    let oldest_alice_live = format!(
        "alice settled successor {}",
        alice_successors - vox_core::log::history::MAX_PAGE_ENTRIES
    );
    let oldest = read_hash(&bob, &room, &oldest_alice_live).unwrap_or_else(|| {
        panic!(
            "PRODUCT: Bob's shipped JSON read omitted Alice's expected oldest live-window row \
             {oldest_alice_live:?} before archive paging"
        )
    });
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
        "PRODUCT: Bob's `vox room read --history older --before {oldest}` was refused: {out}{err}"
    );
    bob_after_gap.stop();
    let bob_after_interruption = daemon(&bob, "bob-after-interruption");
    attached(&bob, "bob-after-interruption");
    let (ok, out, err) = vox(&bob, &["room", "read", &room, "--history", "resume"], None);
    assert!(
        ok,
        "PRODUCT: Bob's shipped `vox room read --history resume` was refused after interruption: \
         {out}{err}"
    );
    // Reading a fresh later row is not proof of crossing a sparse gap: it can arrive and render
    // independently. Alice must instead report Bob's authenticated receipt through the exact
    // feed position after the package. That role-contiguous cursor cannot jump over Carol's
    // package header, even though Bob must never receive its private body.
    while member_held_through(&alice, &room, &fps[1]) != Some(marker_through) {
        let current = history_observation(&bob, &room);
        assert!(
            current.phase != "complete" && current.remaining != 0,
            "PRODUCT: Bob's exact archive request reached terminal status {}/{}, but Alice did \
             not report his authenticated receipt through {marker_through}; Carol's header-only \
             package did not settle contiguously for Bob's role\n\
             bob's daemon said: {}",
            current.phase,
            current.remaining,
            said(&bob, "bob-after-interruption")
        );
        std::thread::sleep(Duration::from_millis(200));
    }
    assert!(
        read_hash(&bob, &room, before_package_text).as_deref()
            == Some(before_package_hash.as_str()),
        "PRODUCT: Bob's shipped archive read settled Alice's exact cursor through \
         {marker_through}, but did not continue past Carol's header to the exact older row \
         {before_package_hash}\nbob's daemon said: {}",
        said(&bob, "bob-after-interruption")
    );
    let archive_status = history_status(&bob, &room);
    assert_eq!(
        archive_status,
        ("complete".to_owned(), 0),
        "PRODUCT: after the shipped archive read crossed Carol's role-complete header and \
         returned the exact older row, its status was not exactly complete with zero remaining"
    );
    for dir in [&alice, &bob] {
        let (ok, out, err) = vox(dir, &["status", "--json"], None);
        assert!(ok, "PRODUCT: `vox status --json` failed: {err}");
        let status: serde_json::Value = serde_json::from_str(&out)
            .unwrap_or_else(|e| panic!("PRODUCT: `vox status --json` is not JSON: {e}: {out}"));
        assert!(
            status["rooms"]
                .as_array()
                .is_some_and(|rooms| !rooms.is_empty()
                    && rooms.iter().all(|room| !room["last_sync_ms"].is_null())),
            "PRODUCT: status does not say when the room last synced: {out}"
        );
    }

    // Restart Bob before the next receipt probe. Alice observing a newer completed sync and the
    // same exact held-through position proves Bob reconstructed the durable cursor; it is not an
    // in-memory acknowledgement left over from the first daemon.
    bob_after_interruption.stop();
    let bob_after_restart = daemon(&bob, "bob-after-restart");
    attached(&bob, "bob-after-restart");
    wait_room_open(&bob, &room, "bob-after-restart");
    assert!(
        member_holds_through(&bob, &room, &fps[0]) == Some(marker_through)
            && member_holds_through(&bob, &room, &fps[2]) == Some(carol_tail_through),
        "PRODUCT: after restarted Bob's shipped room reached its Open terminal state, \
         `vox status --json` did not restore the exact durable contiguous feed heads for Alice \
         through {marker_through} and Carol through {carol_tail_through}\nbob said: {}",
        said(&bob, "bob-after-restart")
    );

    // Alice now goes offline. Release Carol's package hold only after Carol and Bob are running,
    // then wait for a completed Carol↔Bob sync (not elapsed silence). If Bob persisted the hostile
    // ciphertext, he can serve it and Carol will show Alice's tail. The correct product completed
    // that sync but has only the authenticated package header, so her shipped read remains absent.
    alice_daemon.stop();
    let carol_from_bob_daemon = daemon_env(&carol, "carol-from-bob", &knob);
    attached(&carol, "carol-from-bob");
    wait_room_open(&carol, &room, "carol-from-bob");
    assert!(
        !reads(&carol, &room, &package_marker),
        "PRODUCT: Carol read Alice's marker while the confirmed package-installer hold remained \
         armed; the product installed or served the held key-package past its causal hold"
    );
    std::fs::remove_file(&hold)
        .unwrap_or_else(|e| panic!("APPARATUS: could not release {}: {e}", hold.display()));
    // A successful trust update causally releases retained key-package replay and advances its
    // first bounded turn before the shipped command returns. Keep Alice offline, then wait on the
    // shipped pending bit until every continuation is done: the privacy verdict is not a race
    // with the separately scheduled package-maintenance turn.
    let (ok, out, err) = vox(&carol, &["trust", "add", &fps[0], "--name", "alice"], None);
    assert!(
        ok,
        "PRODUCT: Carol's idempotent shipped trust update could not start retained-package \
         processing while Alice was offline: {out}{err}"
    );
    let packages_deadline = Instant::now() + READY_WITHIN;
    while key_packages_pending(&carol, &room) != Some(false) {
        assert!(
            Instant::now() < packages_deadline,
            "PRODUCT: Carol's shipped status did not report retained key-package processing \
             complete within {READY_WITHIN:?} while Alice was offline\ncarol said: {}",
            said(&carol, "carol-from-bob")
        );
        std::thread::yield_now();
    }

    // A completed inventory round is not evidence that Bob had to answer for Alice's history.
    // Re-arm Carol's package hold before the shipped reader asks for the exact page below Alice's
    // oldest live-window row. The hold keeps the shipped pending bit observable until the proof
    // releases it. The product has only the role-complete header: persisting the hostile private
    // body already turns the earlier exact refusal assertion red.
    std::fs::write(&hold, b"").unwrap_or_else(|e| {
        panic!(
            "APPARATUS: could not re-arm Carol's package hold at {} before the explicit history \
             request: {e}",
            hold.display()
        )
    });

    // The bounded interval contains the package. Alice is offline and Bob is the only source, so
    // the retained request bound to that exact authenticated Alice cursor and ending its quantum
    // has given Bob the exact opportunity to serve every byte he holds in that interval.
    let (ok, out, err) = vox(
        &carol,
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
        "PRODUCT: while Alice was offline, Carol's shipped history read through Bob was refused: \
         {out}{err}"
    );
    let history_deadline = Instant::now() + PAGE_WITHIN;
    let bob_only_history = loop {
        let observed = history_observation(&carol, &room);
        if observed.request.is_some() && matches!(observed.phase.as_str(), "more" | "complete") {
            break observed;
        }
        assert!(
            Instant::now() < history_deadline,
            "PRODUCT: Carol's shipped history status did not finish the exact Alice page through \
             reachable Bob within {PAGE_WITHIN:?} while Alice was offline; phase={}, request={:?}, \
             remaining={}\ncarol said: {}\nbob said: {}",
            observed.phase,
            observed.request,
            observed.remaining,
            said(&carol, "carol-from-bob"),
            said(&bob, "bob-after-restart")
        );
        std::thread::yield_now();
    };

    std::fs::remove_file(&hold).unwrap_or_else(|e| {
        panic!(
            "APPARATUS: could not release Carol's post-history package hold at {}: {e}",
            hold.display()
        )
    });
    let post_history_packages_deadline = Instant::now() + READY_WITHIN;
    while key_packages_pending(&carol, &room) != Some(false) {
        assert!(
            Instant::now() < post_history_packages_deadline,
            "PRODUCT: Carol's shipped status did not report post-history key-package processing \
             complete within {READY_WITHIN:?} while Alice was offline\ncarol said: {}",
            said(&carol, "carol-from-bob")
        );
        std::thread::yield_now();
    }
    assert!(
        !reads(&carol, &room, &package_marker),
        "PRODUCT: after Bob exhausted Carol's explicit Alice-history quantum (phase={}, \
         remaining={}) and retained-package replay completed while Alice was offline, Carol read \
         Alice's private-package tail {package_marker:?}; Bob persisted and re-served ciphertext \
         addressed only to Carol\ncarol said: {}\nbob said: {}",
        bob_only_history.phase,
        bob_only_history.remaining,
        said(&carol, "carol-from-bob"),
        said(&bob, "bob-after-restart")
    );

    // Bringing the actual source back is the one causal change that makes Carol's package
    // available. Her exact tail appears, then all three shipped daemons still exchange content.
    let _alice_after_privacy = daemon_env(&alice, "alice-after-privacy", &alice_knob);
    attached(&alice, "alice-after-privacy");
    let released_deadline = Instant::now() + READY_WITHIN;
    while !reads(&carol, &room, &package_marker) {
        assert!(
            Instant::now() < released_deadline,
            "PRODUCT: Carol did not read Alice's exact tail within {READY_WITHIN:?} after the \
             actual package source returned\ncarol said: {}\nalice said: {}",
            said(&carol, "carol-from-bob"),
            said(&alice, "alice-after-privacy")
        );
        std::thread::sleep(Duration::from_millis(200));
    }
    let (ok, out, err) = vox(&bob, &["trust", "add", &fps[2], "--name", "carol"], None);
    assert!(
        ok,
        "PRODUCT: Bob could not trust Carol immediately before their final healthy post: \
         {out}{err}"
    );
    let carol_reply = "carol sees the room";
    let (ok, out, err) = vox(&carol, &["room", "post", &room, carol_reply], None);
    assert!(ok, "PRODUCT: carol's post was refused: {out}{err}");
    let converged_deadline = Instant::now() + READY_WITHIN;
    while !(reads(&alice, &room, carol_reply) && reads(&bob, &room, carol_reply)) {
        assert!(
            Instant::now() < converged_deadline,
            "PRODUCT: alice and bob did not both read carol's post within {READY_WITHIN:?} after \
             her package landed\nalice's daemon said: {}\nbob's daemon said: {}",
            said(&alice, "alice-after-privacy"),
            said(&bob, "bob-after-restart")
        );
        std::thread::sleep(Duration::from_millis(200));
    }
    prove_a_pruned_body_stays_unshown(
        &alice,
        &bob,
        &carol,
        &late,
        &room,
        &link,
        carol_from_bob_daemon,
    );
    drop(bob_after_restart);
}

/// Continue the quiet-room journey with a member trusted before the posts. `late` was mutually
/// trusted with every author before any room post. Alice and Bob visibly prune one Bob body while
/// its only retaining source (Carol) is offline, so late settles its authenticated header and
/// shows the post as not received yet. A later local post visibly aging out proves that header's
/// sealed retention origin is already expired. Carol then returns with the body while a
/// proof-only sweep hold preserves the exact post-refill observation: the old body must not become
/// visible merely because its bytes arrived later. No forged frame or database inspection stands
/// in for the shipped product.
#[cfg(feature = "optional-proofs")]
fn prove_a_pruned_body_stays_unshown(
    alice: &Path,
    bob: &Path,
    carol: &Path,
    late: &Path,
    room: &str,
    link: &str,
    carol_daemon: Daemon,
) {
    const LOCAL_RETENTION: &str = "default 1\n";
    let pruned = "bob body retained only until the late member joins";
    for (name, dir) in [("alice", alice), ("bob", bob)] {
        std::fs::write(dir.join("cfg/retention"), LOCAL_RETENTION).unwrap_or_else(|error| {
            panic!(
                "APPARATUS: could not stage {name}'s local retention file for the refusal: {error}"
            )
        });
        let (ok, out, err) = vox(dir, &["room", "retention", room, "--steps", "7d"], None);
        assert!(
            ok,
            "PRODUCT: {name}'s shipped retention reload was refused while staging the late-member \
             lifecycle: {out}{err}"
        );
    }
    std::fs::write(carol.join("cfg/retention"), "default forever\n").unwrap_or_else(|error| {
        panic!("APPARATUS: could not preserve Carol as the delayed body source: {error}")
    });
    let (ok, out, err) = vox(carol, &["room", "retention", room, "--steps", "7d"], None);
    assert!(
        ok,
        "PRODUCT: Carol's shipped retention reload was refused while staging the delayed body: \
         {out}{err}"
    );
    std::fs::write(late.join("cfg/retention"), LOCAL_RETENTION).unwrap_or_else(|error| {
        panic!("APPARATUS: could not stage late's local retention file: {error}")
    });
    let (ok, out, err) = vox(bob, &["room", "post", room, "--json", pruned], None);
    assert!(
        ok,
        "PRODUCT: Bob's authorized refusal-lifecycle post was refused: {out}{err}"
    );
    let posted: serde_json::Value = serde_json::from_str(out.trim()).unwrap_or_else(|error| {
        panic!("PRODUCT: Bob's delayed-refill post response was not JSON: {error}: {out}")
    });
    let pruned_hash = posted["entry_hash"]
        .as_str()
        .unwrap_or_else(|| panic!("PRODUCT: Bob's delayed-refill post named no entry hash: {out}"))
        .to_owned();
    while !reads(carol, room, pruned) || !reads(alice, room, pruned) {
        std::thread::yield_now();
    }
    carol_daemon.stop();
    while reads(alice, room, pruned) || reads(bob, room, pruned) {
        std::thread::yield_now();
    }

    let refill_outcome = late.join("fx29-content-refill-outcome");
    let refill_hold = late.join("hold-retention-after-content-refill");
    let refill_outcome_text = refill_outcome.to_string_lossy().into_owned();
    let refill_hold_text = refill_hold.to_string_lossy().into_owned();
    let late_daemon = daemon_env(
        late,
        "late-refusal",
        &[
            (
                "VOX_TEST_FX29_CONTENT_REFILL_OUTCOME_FILE",
                refill_outcome_text.as_str(),
            ),
            ("VOX_TEST_FX29_CONTENT_REFILL_HASH", pruned_hash.as_str()),
            (
                "VOX_TEST_HOLD_RETENTION_SWEEP_FILE",
                refill_hold_text.as_str(),
            ),
        ],
    );
    attached(late, "late-refusal");
    let (ok, out, err) = vox(
        late,
        &["room", "join", "--passphrase-file", "-", link],
        Some(&format!("{ROOMPASS}\n")),
    );
    assert!(
        ok,
        "PRODUCT: the member trusted before the pruned post could not join through the shipped \
         command: {out}{err}"
    );
    wait_room_open(late, room, "late-refusal");
    let (ok, out, err) = vox(late, &["room", "retention", room, "--steps", "7d"], None);
    assert!(
        ok,
        "PRODUCT: late's shipped retention reload was refused after join: {out}{err}"
    );
    // Staging fence, read as a person reads: late's room shows Bob's post in its place as not
    // received yet (#1396). Until then its missing-body decision is not made.
    while !shows_not_received_yet(late, room, &pruned_hash) {
        std::thread::sleep(Duration::from_millis(200));
    }
    eprintln!("[proof] late shows Bob's pruned post {pruned_hash} as not received yet");
    assert!(
        !reads(late, room, pruned),
        "PRODUCT: the late member read Bob's body after every shipped holder had pruned it"
    );

    // The witness is younger than the already-settled Bob header. Its disappearance from the
    // shipped read is therefore a causal proof that the header's original retention age has
    // expired; no elapsed threshold decides this verdict. Freeze only later retention sweeps,
    // return the sole body source, and wait for the exact committed refill marker. One shipped
    // read while the sweep is held distinguishes preserved age from the mutant's reset age.
    let witness = "late retention witness after Bob header settlement";
    let (ok, out, err) = vox(late, &["room", "post", room, witness], None);
    assert!(
        ok,
        "PRODUCT: late's retention witness post was refused: {out}{err}"
    );
    assert!(
        reads(late, room, witness),
        "PRODUCT: late's accepted retention witness was never visible in its shipped room read"
    );
    while reads(late, room, witness) {
        std::thread::yield_now();
    }
    std::fs::write(&refill_hold, b"").unwrap_or_else(|error| {
        panic!("APPARATUS: could not hold retention after the exact refill: {error}")
    });
    let _carol_after_refill = daemon(carol, "carol-delayed-refill-source");
    attached(carol, "carol-delayed-refill-source");
    wait_room_open(carol, room, "carol-delayed-refill-source");
    while !refill_outcome.is_file() {
        std::thread::yield_now();
    }
    let refill = std::fs::read_to_string(&refill_outcome).unwrap_or_else(|error| {
        panic!("APPARATUS: could not read the exact sparse-Content refill marker: {error}")
    });
    assert_eq!(
        refill,
        format!("accepted:{pruned_hash}"),
        "APPARATUS: sparse-Content refill marker named a different entry"
    );
    eprintln!(
        "[proof] FX-29 settled Content delayed-refill apparatus staged: hash={pruned_hash} older witness visibly expired"
    );
    assert!(
        !reads(late, room, pruned),
        "PRODUCT [FX29 settled-content-refill-age]: delayed bytes made expired Bob body \
         {pruned_hash} visible after its younger shipped retention witness had already disappeared"
    );
    std::fs::remove_file(&refill_hold).unwrap_or_else(|error| {
        panic!("APPARATUS: could not release post-refill retention maintenance: {error}")
    });
    std::fs::write(carol.join("cfg/retention"), LOCAL_RETENTION).unwrap_or_else(|error| {
        panic!("APPARATUS: could not shorten Carol's retention after the refill claim: {error}")
    });
    let (ok, out, err) = vox(carol, &["room", "retention", room, "--steps", "7d"], None);
    assert!(
        ok,
        "PRODUCT: Carol's post-refill retention reload was refused: {out}{err}"
    );
    while [alice, bob, carol]
        .iter()
        .any(|holder| reads(holder, room, pruned))
    {
        std::thread::yield_now();
    }
    drop(late_daemon);
}

/// Whether `vox room read` on `dir` shows the message `hash` in its place as not received yet
/// (V030-10, #1396): the row's first column is a prefix of the hash and the row ends in the
/// placeholder a person sees.
#[cfg(feature = "optional-proofs")]
fn shows_not_received_yet(dir: &Path, room: &str, hash: &str) -> bool {
    loop {
        let (ok, out, err) = vox(dir, &["room", "read", room], None);
        if !ok && room_changed_while_reading(&err) {
            continue;
        }
        assert!(ok, "PRODUCT: `vox room read` refused: {out}{err}");
        return out.lines().any(|line| {
            line.ends_with(vox_core::node::api::NOT_RECEIVED_YET)
                && line
                    .split(' ')
                    .next()
                    .is_some_and(|first| !first.is_empty() && hash.starts_with(first))
        });
    }
}

/// Rooms staged together so the bounded backfill has both a long author and independent work.
const WORK_ROOMS: usize = 3;
/// Cross a production render turn without requesting an archive outside the 128-position live
/// suffix. The missing-key/consent journey must not wait for unrequested older history.
const BEFORE_KEY: usize = vox_core::node::channel::RENDER_BACKFILL_ROWS_PER_TURN + 1;
/// **Retained rows wake when their key and consent arrive** (ADR-038 FX-22, #1007).
/// Bob receives the key before Alice's consent, then restarts with both facts retained and Alice
/// unavailable; every exact row must become readable once and in order.
///
/// Mutant: after rendering the first retained row, clearing that author's next sparse backfill
/// cursor makes shipped status say the continuation is finished while exact retained hashes/text
/// are still missing, which turns the stable user-visible completion assertion PRODUCT red.
fn key_before_consent_survives_a_restart(root: &Path) {
    let alice = root.join("alice");
    let bob = root.join("bob");
    for dir in [&alice, &bob] {
        std::fs::create_dir_all(dir.join("cfg"))
            .unwrap_or_else(|error| panic!("APPARATUS: could not create profile: {error}"));
    }
    let alice_fold = root.join("alice-fold");
    let bob_fold = root.join("bob-fold");
    let consent_hold = root.join("incoming-consent-hold");
    let consent_entered = consent_hold.with_extension("entered");
    let render_hold = root.join("render-hold");
    let alice_fold_path = alice_fold
        .to_str()
        .expect("APPARATUS: a UTF-8 Alice fold path");
    let bob_fold_path = bob_fold.to_str().expect("APPARATUS: a UTF-8 Bob fold path");

    let (ok, alice_fp, err) = vox(&alice, &["id"], None);
    assert!(ok, "PRODUCT: Alice's `vox id` failed: {err}");
    let (ok, bob_fp, err) = vox(&bob, &["id"], None);
    assert!(ok, "PRODUCT: Bob's `vox id` failed: {err}");
    let (ok, out, err) = vox(
        &bob,
        &["trust", "add", alice_fp.trim(), "--name", "alice"],
        None,
    );
    assert!(
        ok,
        "PRODUCT: Bob's `vox trust add alice` failed: {out}{err}"
    );
    let alice_daemon = daemon_env(
        &alice,
        "alice-consent-last",
        &[("VOX_TEST_FOLD_HOLD_FILE", alice_fold_path)],
    );
    let bob_daemon = daemon_env(
        &bob,
        "bob-consent-last",
        &[
            ("VOX_TEST_FOLD_HOLD_FILE", bob_fold_path),
            (
                "VOX_TEST_HOLD_INCOMING_CONSENT_FILE",
                consent_hold.to_str().expect("APPARATUS: consent hold path"),
            ),
            (
                "VOX_TEST_HOLD_RENDER_FILE",
                render_hold.to_str().expect("APPARATUS: render hold path"),
            ),
        ],
    );
    attached(&alice, "alice-consent-last");
    attached(&bob, "bob-consent-last");
    let (ok, out, err) = vox(
        &alice,
        &[
            "room",
            "create",
            "--passphrase-file",
            "-",
            "--name",
            "consent-last",
        ],
        Some(&format!("{ROOMPASS}\n")),
    );
    assert!(
        ok,
        "PRODUCT: Alice could not create consent-last: {out}{err}"
    );
    let listed = attached(&alice, "alice-consent-last");
    let room = listed
        .lines()
        .find(|line| line.contains("consent-last"))
        .and_then(|line| line.split_whitespace().next())
        .unwrap_or_else(|| panic!("PRODUCT: `vox room list` omitted consent-last: {listed}"))
        .to_owned();
    let (ok, link, err) = vox(&alice, &["room", "link", &room], None);
    assert!(ok, "PRODUCT: `vox room link` failed: {err}");
    let mut hashes = Vec::with_capacity(BEFORE_KEY);
    let mut expected = Vec::with_capacity(BEFORE_KEY);
    for row in 0..BEFORE_KEY {
        let text = format!("key before consent row {row}");
        let (ok, out, err) = vox(&alice, &["room", "post", &room, "--json", "-"], Some(&text));
        assert!(ok, "PRODUCT: Alice's retained post failed: {out}{err}");
        let posted: serde_json::Value = serde_json::from_str(&out).unwrap_or_else(|error| {
            panic!("PRODUCT: `vox room post --json` was malformed ({error}): {out}")
        });
        hashes.push(
            posted["entry_hash"]
                .as_str()
                .unwrap_or_else(|| panic!("PRODUCT: post named no entry_hash: {posted}"))
                .to_owned(),
        );
        expected.push(text);
    }

    std::fs::write(&alice_fold, b"")
        .unwrap_or_else(|error| panic!("APPARATUS: could not engage Alice's fold: {error}"));
    let (ok, out, err) = vox(
        &bob,
        &["room", "join", "--passphrase-file", "-", link.trim()],
        Some(&format!("{ROOMPASS}\n")),
    );
    assert!(ok, "PRODUCT: Bob could not join consent-last: {out}{err}");
    wait_reader_one_way_trust(&bob, "bob", &room, "alice");
    wait_for_held_rows(&bob, &room, &hashes, "author-governance");
    wait_room_status(
        &alice,
        "alice",
        &room,
        false,
        "Alice never listed Bob as a room member",
        |status| status.members.iter().any(|member| member == bob_fp.trim()),
    );

    std::fs::write(&bob_fold, b"")
        .unwrap_or_else(|error| panic!("APPARATUS: could not engage Bob's fold: {error}"));
    let full_room = vox_core::node::link::b32_encode(&room_id(&alice, "alice", &room));
    let consent_scope = format!("{} {} {}", full_room, alice_fp.trim(), bob_fp.trim());
    std::fs::write(&consent_hold, &consent_scope)
        .unwrap_or_else(|error| panic!("APPARATUS: cannot hold incoming consent: {error}"));
    std::fs::remove_file(&alice_fold)
        .unwrap_or_else(|error| panic!("APPARATUS: could not release Alice's fold: {error}"));
    let (ok, out, err) = grant_full_history(&alice, bob_fp.trim(), "bob");
    assert!(
        ok,
        "PRODUCT: Alice could not grant Bob full history: {out}{err}"
    );
    let with_key = wait_room_status(
        &bob,
        "bob",
        &room,
        false,
        "Bob never accepted the retained sender key before consent",
        |status| status.received_key_generations >= 1,
    );
    wait_reader_one_way_trust(&bob, "bob", &room, "alice");
    wait_for_held_rows(&bob, &room, &hashes, "consent-fold");
    assert!(
        with_key.received_key_generations >= 1,
        "APPARATUS: key-before-consent was not staged: {with_key:?}"
    );

    while !consent_entered.exists() {
        std::thread::yield_now();
    }
    let entered = std::fs::read_to_string(&consent_entered)
        .unwrap_or_else(|error| panic!("APPARATUS: cannot read held consent: {error}"));
    let (scope, hash) = entered
        .rsplit_once(' ')
        .unwrap_or_else(|| panic!("APPARATUS: malformed held consent: {entered}"));
    assert_eq!(
        scope, consent_scope,
        "APPARATUS: held consent belongs to another room or peer"
    );
    assert!(
        room_hashes(&alice, "alice", &room)
            .iter()
            .any(|held| held == hash),
        "APPARATUS: held consent is not an actual Alice publication: {entered}"
    );
    wait_for_held_rows(&bob, &room, &hashes, "key-before-consent");
    std::fs::write(&render_hold, b"")
        .unwrap_or_else(|error| panic!("APPARATUS: cannot hold rendering: {error}"));
    std::fs::remove_file(&consent_hold)
        .unwrap_or_else(|error| panic!("APPARATUS: cannot release consent: {error}"));
    std::fs::remove_file(&bob_fold)
        .unwrap_or_else(|error| panic!("APPARATUS: cannot release Bob's fold: {error}"));
    wait_trust_detail(&bob, "bob", &room, "alice", "you trust each other");
    wait_for_held_rows(&bob, &room, &hashes, "post-consent restart boundary");
    // Both facts are durable, but the retained rows have not rendered. Only Bob returns.
    alice_daemon.stop();
    bob_daemon.stop();
    let bob_held = daemon_env(
        &bob,
        "bob-consent-last-held-restart",
        &[(
            "VOX_TEST_HOLD_RENDER_FILE",
            render_hold.to_str().expect("APPARATUS: render hold path"),
        )],
    );
    attached(&bob, "bob-consent-last-held-restart");
    wait_trust_detail(&bob, "bob", &room, "alice", "you trust each other");
    wait_for_held_rows(&bob, &room, &hashes, "held Bob-only restart");
    bob_held.stop();
    std::fs::remove_file(&render_hold)
        .unwrap_or_else(|error| panic!("APPARATUS: cannot release rendering: {error}"));
    let _bob_restarted = daemon(&bob, "bob-consent-last-restarted");
    attached(&bob, "bob-consent-last-restarted");
    wait_trust_detail(&bob, "bob", &room, "alice", "you trust each other");
    assert_exact_read_rows(
        &bob,
        "bob",
        &room,
        &hashes,
        &expected,
        "row→key→consent with Alice unavailable and Bob restarted",
    );
}

#[cfg(feature = "optional-proofs")]
#[test]
#[ignore = "real vox daemons and deterministic missing-fact holds; optional, run it in release"]
fn retained_rows_render_once_their_key_and_consent_arrive() {
    test_knobs::require(&[
        "VOX_TEST_FOLD_HOLD_FILE",
        "VOX_TEST_HOLD_INCOMING_CONSENT_FILE",
        "VOX_TEST_HOLD_PACKAGES_FILE",
        "VOX_TEST_HOLD_RENDER_FILE",
    ]);
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap_or_else(|e| panic!("APPARATUS: no temp dir: {e}"));
    key_before_consent_survives_a_restart(&tmp.path().join("key-before-consent"));
    let row_before_key = tmp.path().join("row-before-key");
    let root = row_before_key.as_path();
    let mut alice = root.join("alice");
    let bob = root.join("bob");
    let mut carol = root.join("carol");
    for d in [&alice, &bob, &carol] {
        std::fs::create_dir_all(d.join("cfg"))
            .unwrap_or_else(|e| panic!("APPARATUS: could not create {}: {e}", d.display()));
    }
    let mut fps = Vec::new();
    for dir in [&alice, &bob, &carol] {
        let (ok, out, err) = vox(dir, &["id"], None);
        assert!(ok, "PRODUCT: `vox id` failed: {err}");
        fps.push(out.trim().to_owned());
    }
    let alice_id = vox_core::node::link::b32_decode(&fps[0], "Alice fingerprint")
        .unwrap_or_else(|error| panic!("APPARATUS: Alice's fingerprint was malformed: {error}"));
    let carol_id = vox_core::node::link::b32_decode(&fps[2], "Carol fingerprint")
        .unwrap_or_else(|error| panic!("APPARATUS: Carol's fingerprint was malformed: {error}"));
    if alice_id > carol_id {
        // The durable queue orders by author fingerprint. Give the lower fingerprint the long
        // backlog so the competing row genuinely observes a round-robin step rather than the
        // tree's ordinary successor after a short author.
        std::mem::swap(&mut alice, &mut carol);
        fps.swap(0, 2);
    }
    for (dir, fp, name) in [
        (&alice, &fps[2], "carol"),
        (&bob, &fps[0], "alice"),
        (&bob, &fps[2], "carol"),
        (&carol, &fps[0], "alice"),
    ] {
        let (ok, _, err) = vox(
            dir,
            &["trust", "add", fp, "--name", name, "--history", "now"],
            None,
        );
        assert!(ok, "PRODUCT: `vox trust add` of {name} failed: {err}");
    }
    let fold_hold = root.join("fx22-fold-hold");
    let carol_fold_hold = root.join("fx22-carol-fold-hold");
    let package_hold = root.join("fx22-package-hold");
    let package_hold_engaged = root.join("fx22-package-hold.engaged");
    let render_hold = root.join("fx22-render-hold");
    let render_hold_ready = root.join("fx22-render-hold.ready");
    let render_hold_engaged = root.join("fx22-render-hold.engaged");
    let render_hold_replacement = root.join("fx22-render-hold-replacement");
    let fold_hold_path = fold_hold
        .to_str()
        .expect("APPARATUS: a UTF-8 fold-hold path")
        .to_owned();
    let carol_fold_hold_path = carol_fold_hold
        .to_str()
        .expect("APPARATUS: a UTF-8 Carol fold-hold path")
        .to_owned();
    let package_hold_path = package_hold
        .to_str()
        .expect("APPARATUS: a UTF-8 package-hold path")
        .to_owned();
    let render_hold_path = render_hold
        .to_str()
        .expect("APPARATUS: a UTF-8 render-hold path")
        .to_owned();
    let fold_knob = [("VOX_TEST_FOLD_HOLD_FILE", fold_hold_path.as_str())];
    let carol_fold_knob = [("VOX_TEST_FOLD_HOLD_FILE", carol_fold_hold_path.as_str())];
    let package_knob = [
        ("VOX_TEST_HOLD_PACKAGES_FILE", package_hold_path.as_str()),
        ("VOX_TEST_HOLD_RENDER_FILE", render_hold_path.as_str()),
    ];
    let alice_daemon = daemon_env(&alice, "alice", &fold_knob);
    let carol_daemon = daemon_env(&carol, "carol", &carol_fold_knob);
    attached(&alice, "alice");
    attached(&carol, "carol");
    let mut rooms = Vec::with_capacity(WORK_ROOMS);
    let mut links = Vec::with_capacity(WORK_ROOMS);
    let mut late_hashes = Vec::with_capacity(WORK_ROOMS);
    let mut competing_hashes = Vec::with_capacity(WORK_ROOMS);
    let mut competing_texts = Vec::with_capacity(WORK_ROOMS);
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
        let mut room_late_hashes = Vec::with_capacity(BEFORE_KEY);
        for row in 0..BEFORE_KEY {
            let text = format!("alice before key room {i} row {row}");
            let (ok, out, err) = vox(&alice, &["room", "post", &room, "--json", "-"], Some(&text));
            assert!(ok, "PRODUCT: Alice's pre-key post was refused: {out}{err}");
            let posted: serde_json::Value = serde_json::from_str(&out).unwrap_or_else(|error| {
                panic!(
                    "PRODUCT: Alice's `vox room post --json` answer was malformed ({error}): \
                     {out}{err}"
                )
            });
            room_late_hashes.push(
                posted["entry_hash"]
                    .as_str()
                    .unwrap_or_else(|| {
                        panic!(
                            "PRODUCT: Alice's `vox room post --json` answer named no entry_hash: \
                             {posted}"
                        )
                    })
                    .to_owned(),
            );
        }
        rooms.push(room);
        links.push(link.trim().to_owned());
        late_hashes.push(room_late_hashes);
    }

    // Carol is an independently keyed source in every room. Her one retained row sits behind
    // Alice's continuation of more than two production pages, so eventual exact visibility from
    // both authors proves the per-author queue does not let that continuation starve a peer.
    for (index, (room, link)) in rooms.iter().zip(&links).enumerate() {
        let (ok, out, err) = vox(
            &carol,
            &["room", "join", "--passphrase-file", "-", link],
            Some(&format!("{ROOMPASS}\n")),
        );
        assert!(
            ok,
            "PRODUCT: Carol could not join work-{}: {out}{err}",
            index + 1
        );
        wait_trust_detail(&carol, "carol", room, "alice", "you trust each other");
        wait_room_status(
            &carol,
            "carol",
            room,
            false,
            "Carol never accepted Alice's sender key",
            |status| status.received_key_generations >= 1,
        );
        let text = format!("carol competing row room {}", index + 1);
        let (ok, out, err) = vox(&carol, &["room", "post", room, "--json", "-"], Some(&text));
        assert!(ok, "PRODUCT: Carol's competing post failed: {out}{err}");
        let posted: serde_json::Value = serde_json::from_str(&out).unwrap_or_else(|error| {
            panic!("PRODUCT: Carol's post answer was malformed ({error}): {out}")
        });
        competing_hashes.push(vec![posted["entry_hash"]
            .as_str()
            .unwrap_or_else(|| panic!("PRODUCT: Carol's post named no entry_hash: {posted}"))
            .to_owned()]);
        competing_texts.push(vec![text]);
    }

    // Set the later same-name input before holding the fold: rename itself requires that fold
    // to finish. Prove the command appended one exact authenticated object rather than accepting
    // command success from a mutant that skipped the append.
    for room in &rooms {
        let before = room_hashes(&alice, "alice", room);
        let appended = rename_hash(&alice, "alice", room, room);
        assert!(
            !before.contains(&appended) && room_hashes(&alice, "alice", room).contains(&appended),
            "PRODUCT: Alice's successful same-name rename named entry {appended}, but that exact \
             authenticated row was not newly present in room {room}"
        );
    }

    // Neither author trusts Bob yet. He can retain their existing LogDb prefixes without
    // consent or sender keys. The product itself must show those exact retained hashes while
    // their content remains unreadable: the APPARATUS preconditions for the late-render verdict.
    std::fs::write(&fold_hold, b"")
        .unwrap_or_else(|error| panic!("APPARATUS: could not engage the fold hold: {error}"));
    std::fs::write(&carol_fold_hold, b"")
        .unwrap_or_else(|error| panic!("APPARATUS: could not engage Carol's fold hold: {error}"));
    std::fs::write(&package_hold, b"")
        .unwrap_or_else(|error| panic!("APPARATUS: could not engage the package hold: {error}"));
    let bob_before_key = daemon_env(&bob, "bob", &package_knob);
    attached(&bob, "bob");
    for (i, (room, link)) in rooms.iter().zip(&links).enumerate() {
        let (ok, out, err) = vox(
            &bob,
            &["room", "join", "--passphrase-file", "-", link],
            Some(&format!("{ROOMPASS}\n")),
        );
        assert!(
            ok,
            "PRODUCT: bob's `vox room join work-{}` was refused: {out}{err}",
            i + 1
        );
        wait_room_status(
            &bob,
            "bob",
            room,
            true,
            "Bob never retained Alice's pre-key room prefix",
            |status| status.log_entries > 0,
        );
        wait_reader_one_way_trust(&bob, "bob", room, "alice");
        wait_for_held_rows(&bob, room, &late_hashes[i], "governance-fold");
        wait_reader_one_way_trust(&bob, "bob", room, "carol");
        wait_for_held_rows(&bob, room, &competing_hashes[i], "Carol-governance-fold");
        // Membership, not counts over two different retained collections, is the precondition
        // for Alice to issue Bob's consent after the fold is released.
        wait_room_status(
            &alice,
            "alice",
            room,
            false,
            "Alice never listed Bob as a room member",
            |status| status.members.iter().any(|member| member == &fps[1]),
        );
    }

    // The exact held rows and missing product facts above are the staging evidence. CPU and
    // elapsed time are not verdicts for this claim: the causal consent/key events below must
    // either make those same hashes readable or leave structural render work unfinished.
    bob_before_key.stop();
    if package_hold_engaged.exists() {
        std::fs::remove_file(&package_hold_engaged).unwrap_or_else(|error| {
            panic!("APPARATUS: could not clear the first daemon's package-hold evidence: {error}")
        });
    }

    // With Bob offline, release each source through a real user action. Their later mutual
    // trust answers establish the grants; a whole-room hash delta cannot identify one grant.
    std::fs::remove_file(&fold_hold)
        .unwrap_or_else(|error| panic!("APPARATUS: could not release the fold hold: {error}"));
    // The real trust decision is the missing fact and wakes Alice's released fold.
    let (ok, out, err) = grant_full_history(&alice, &fps[1], "bob");
    assert!(
        ok,
        "PRODUCT: Alice could not grant Bob her retained history: {out}{err}"
    );

    std::fs::remove_file(&carol_fold_hold)
        .unwrap_or_else(|error| panic!("APPARATUS: could not release Carol's fold hold: {error}"));
    // Carol must not have consented before the missing-fact boundary. Her earlier room join
    // can already publish off-roster consent when Bob is in her keyring.
    let (ok, out, err) = grant_full_history(&carol, &fps[1], "bob");
    assert!(
        ok,
        "PRODUCT: Carol could not grant Bob her retained history: {out}{err}"
    );

    // A successful grant can still owe an asynchronous dial and logged fallback. Keep Bob
    // offline until each source finishes that delivery; otherwise his held live route can win
    // the race without ever publishing the recipient package this restart claim requires.
    for (dir, reader) in [(&alice, "alice"), (&carol, "carol")] {
        for room in &rooms {
            // No delivery debt exists before this room's grant is published. First observe
            // the source's actual outbound consent, then take a fresh delivery-status read.
            loop {
                let consent = trust_detail(dir, reader, room, "bob");
                if matches!(
                    consent.as_str(),
                    "you trust each other"
                        | "you trust it; your node has not received its trust for you, so cannot tell whether it trusts you"
                ) {
                    break;
                }
                std::thread::yield_now();
            }
            wait_room_status(
                dir,
                reader,
                room,
                false,
                "source offline key-package publication",
                |status| !status.key_delivery_pending.contains(&fps[1]),
            );
        }
    }

    // Bob now receives Alice's consent and the sealed package row, but the package marker keeps
    // the shipped daemon from opening it. Doctor says consent is mutual while status still says
    // zero received generations: the second hold is visibly engaged.
    let mut bob_daemon = daemon_env(&bob, "bob", &package_knob);
    attached(&bob, "bob");
    while !package_hold_engaged.exists() {
        for room in &rooms {
            let status = room_status(&bob, "bob", room);
            assert_eq!(
                status.received_key_generations, 0,
                "APPARATUS: Bob accepted a sender key before a real package/delivery attempt \
                 causally engaged the package hold in room {room}: {status:?}"
            );
        }
        std::thread::yield_now();
    }
    for (i, room) in rooms.iter().enumerate() {
        wait_trust_detail(&bob, "bob", room, "alice", "you trust each other");
        wait_trust_detail(&bob, "bob", room, "carol", "you trust each other");
        // Reciprocal consent may still be on Bob. Check it only after his daemon restarts;
        // neither source can obtain a missing Bob-authored fact while he is stopped.
        wait_trust_detail(&alice, "alice", room, "bob", "you trust each other");
        wait_trust_detail(&carol, "carol", room, "bob", "you trust each other");
        let held = wait_room_status(
            &bob,
            "bob",
            room,
            true,
            "Bob never reported the room while its key package was held",
            |_| true,
        );
        wait_for_held_rows(&bob, room, &late_hashes[i], "logged-key-package");
        wait_for_held_rows(&bob, room, &competing_hashes[i], "Carol-logged-key-package");
        assert_eq!(
            held.received_key_generations, 0,
            "APPARATUS: Bob accepted Alice's sender key while its package hold was engaged in \
             room {room}: {held:?}"
        );
    }

    // An intercepted live delivery is not a saved package. Wait for both exact authors'
    // recipient bodies in every local room before taking either source offline.
    let key_authors = [
        vox_core::node::link::b32_decode(&fps[0], "Alice's package author")
            .unwrap_or_else(|error| panic!("APPARATUS: malformed Alice fingerprint: {error}")),
        vox_core::node::link::b32_decode(&fps[2], "Carol's package author")
            .unwrap_or_else(|error| panic!("APPARATUS: malformed Carol fingerprint: {error}")),
    ];
    let expected_packages: Vec<_> = rooms
        .iter()
        .flat_map(|name| {
            let room = room_id(&bob, "bob", name);
            key_authors.map(move |author| (room, author))
        })
        .collect();
    loop {
        let receipt = match std::fs::read(&package_hold_engaged) {
            Ok(receipt) => receipt,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(error) => panic!("APPARATUS: could not read retained-package receipt: {error}"),
        };
        assert!(
            receipt.len().is_multiple_of(64),
            "APPARATUS: retained-package receipt has a partial room/author record"
        );
        if expected_packages.iter().all(|(room, author)| {
            receipt
                .chunks_exact(64)
                .any(|record| record[..32] == room[..] && record[32..] == author[..])
        }) {
            break;
        }
        for room in &rooms {
            let status = room_status(&bob, "bob", room);
            assert_eq!(
                status.received_key_generations, 0,
                "APPARATUS: Bob accepted a sender key before all exact package bodies were \
                 retained in room {room}: {status:?}"
            );
        }
        std::thread::yield_now();
    }
    // Both sources stop only after the local bodies are committed, so the subsequent key
    // installation and exact retained-row reads cannot be satisfied by a fresh delivery.
    alice_daemon.stop();
    carol_daemon.stop();
    let fairness_room = room_id(&bob, "bob", &rooms[0]);
    let long_author = vox_core::node::link::b32_decode(&fps[0], "long author fingerprint")
        .unwrap_or_else(|error| panic!("APPARATUS: Alice's fingerprint was malformed: {error}"));
    let competing_author =
        vox_core::node::link::b32_decode(&fps[2], "competing author fingerprint").unwrap_or_else(
            |error| panic!("APPARATUS: Carol's fingerprint was malformed: {error}"),
        );
    let mut key_stage = Vec::with_capacity(96);
    key_stage.extend_from_slice(&fairness_room);
    key_stage.extend_from_slice(&long_author);
    key_stage.extend_from_slice(&competing_author);
    std::fs::write(&render_hold, key_stage).unwrap_or_else(|error| {
        panic!("APPARATUS: could not hold both exact authors' render cursors: {error}")
    });
    std::fs::remove_file(&package_hold)
        .unwrap_or_else(|error| panic!("APPARATUS: could not release the package hold: {error}"));
    std::fs::remove_file(&package_hold_engaged).unwrap_or_else(|error| {
        panic!("APPARATUS: could not clear the package-hold engagement evidence: {error}")
    });
    for (fingerprint, name) in [(&fps[0], "alice"), (&fps[2], "carol")] {
        let (ok, out, err) = vox(&bob, &["trust", "add", fingerprint, "--name", name], None);
        assert!(
            ok,
            "PRODUCT: Bob's idempotent `vox trust add {name}` could not causally replay the held \
             sender-key package after release: {out}{err}"
        );
    }

    // The 96-byte apparatus marker is renamed only after this real daemon holds the sender keys
    // of both exact authors. Rendering stays parked, so neither package arrival can win a race
    // and drain its author before the other author is runnable.
    while !render_hold_ready.exists() {
        std::thread::yield_now();
    }
    let mut fair_turn = Vec::with_capacity(64);
    fair_turn.extend_from_slice(&fairness_room);
    fair_turn.extend_from_slice(&competing_author);
    std::fs::write(&render_hold_replacement, fair_turn).unwrap_or_else(|error| {
        panic!("APPARATUS: could not prepare the competing-author turn marker: {error}")
    });
    std::fs::rename(&render_hold_replacement, &render_hold).unwrap_or_else(|error| {
        panic!("APPARATUS: could not arm the competing-author turn marker: {error}")
    });
    std::fs::remove_file(&render_hold_ready)
        .unwrap_or_else(|error| panic!("APPARATUS: could not release the exact-key hold: {error}"));
    // Bob is a member, not an administrator. His real history-grant upgrade publishes consent
    // and wakes retained work without pretending that he may rename this room.
    let (ok, out, err) = vox(
        &bob,
        &[
            "trust",
            "add",
            &fps[0],
            "--name",
            "alice",
            "--history",
            "full",
        ],
        None,
    );
    assert!(
        ok,
        "PRODUCT: Bob could not grant Alice his full history: {out}{err}"
    );

    // The marker engages only after one real bounded turn commits Carol's exact-author row, then
    // parks later turns. If Alice's exact backlog becomes wholly readable before that boundary,
    // author service was not fair; this cannot depend on catching a transient scheduling window.
    while !render_hold_engaged.exists() {
        let rows = room_rows(&bob, &rooms[0]);
        if render_hold_engaged.exists() {
            break;
        }
        let status = room_status(&bob, "bob", &rooms[0]);
        if !status.render_backfill_pending && !render_hold_engaged.exists() {
            panic!(
                "APPARATUS: Bob's render continuation finished before the exact competing-author \
                 marker engaged in room {}; staging was not achieved: {status:?}; rows: {rows:?}",
                rooms[0]
            );
        }
        std::thread::yield_now();
    }
    let fair_rows = room_rows(&bob, &rooms[0]);
    let competing: Vec<_> = fair_rows
        .iter()
        .filter(|row| row["entry_hash"] == competing_hashes[0][0])
        .collect();
    assert_eq!(
        competing.len(),
        1,
        "PRODUCT: the held fair turn did not show Carol's exact retained row {} once in room {}: \
         {fair_rows:?}",
        competing_hashes[0][0],
        rooms[0]
    );
    assert_eq!(
        competing[0]["envelope"]["body"].as_str(),
        Some(competing_texts[0][0].as_str()),
        "PRODUCT: the held fair turn did not make Carol's exact retained row {} readable in room \
         {}: {}",
        competing_hashes[0][0],
        rooms[0],
        competing[0]
    );
    let fair_readable_long = fair_rows
        .iter()
        .filter(|row| {
            row["entry_hash"].as_str().is_some_and(|hash| {
                late_hashes[0].iter().any(|expected| expected == hash)
                    && row["envelope"]["body"].as_str().is_some()
            })
        })
        .count();
    assert!(
        fair_readable_long < late_hashes[0].len(),
        "PRODUCT: Carol's exact retained row became readable only after all {} rows of Alice's \
         continuation in room {}; the bounded author queue was not fair: {fair_rows:?}",
        late_hashes[0].len(),
        rooms[0]
    );
    let fair_status = room_status(&bob, "bob", &rooms[0]);
    assert!(
        fair_status.render_backfill_pending,
        "PRODUCT: shipped status said no render work remained at the held fair-turn boundary, \
         although only {fair_readable_long} of Alice's {} exact rows were readable in room {}: \
         {fair_status:?}",
        late_hashes[0].len(),
        rooms[0]
    );
    std::fs::remove_file(&render_hold_engaged)
        .unwrap_or_else(|error| panic!("APPARATUS: could not release the fair-turn hold: {error}"));
    let (ok, out, err) = vox(
        &bob,
        &[
            "trust",
            "add",
            &fps[2],
            "--name",
            "carol",
            "--history",
            "full",
        ],
        None,
    );
    assert!(
        ok,
        "PRODUCT: Bob could not grant Carol his full history: {out}{err}"
    );

    for (index, room) in rooms.iter().enumerate() {
        let expected_before: Vec<String> = (0..BEFORE_KEY)
            .map(|row| format!("alice before key room {} row {row}", index + 1))
            .collect();
        assert_exact_read_rows(
            &bob,
            "bob",
            room,
            &late_hashes[index],
            &expected_before,
            "row→consent→key with Alice unavailable after the exact competing author was readable",
        );
        assert_exact_read_rows(
            &bob,
            "bob",
            room,
            &competing_hashes[index],
            &competing_texts[index],
            "competing-author no-starvation after Alice's >64-row continuation with both \
             sources unavailable",
        );
    }

    // Replay the retained package through the shipped trust command while its source is offline.
    // Projection and key-generation counters are not independent consumer verdicts.
    let (ok, out, err) = vox(
        &bob,
        &[
            "trust",
            "add",
            &fps[0],
            "--name",
            "alice",
            "--history",
            "full",
        ],
        None,
    );
    assert!(
        ok,
        "PRODUCT: Bob's idempotent `vox trust add alice` could not replay the retained key \
         package: {out}{err}"
    );
    let mut alice_restarted = daemon_env(&alice, "alice", &fold_knob);
    attached(&alice, "alice");

    // Isolate the repeated-grant sequence to Alice and Bob. A Presence rotation retries consent
    // for every identity Alice still trusts; offline Carol's regrant could share Bob's row
    // interval and prevent identifying his final grant. Remove Carol through the shipped command,
    // then prove the resulting trust and delivery boundary before staging the quiet sequence.
    let (ok, out, err) = vox(&alice, &["trust", "remove", &fps[2]], None);
    assert!(
        ok,
        "PRODUCT: Alice could not remove offline Carol before the isolated repeated-grant \
         sequence: {out}{err}"
    );
    let (ok, trusted, err) = vox(&alice, &["trust", "list"], None);
    assert!(
        ok,
        "PRODUCT: Alice's shipped trust list failed after removing Carol: {err}"
    );
    assert!(
        !trusted
            .lines()
            .any(|line| line.trim_start().starts_with(&fps[2])),
        "PRODUCT: after successful `vox trust remove`, Alice's shipped trust list still named \
         Carol {}: {trusted}",
        fps[2]
    );
    // Reading a new-generation message proves Bob received the post-removal release. Exact
    // revision counts cannot distinguish the reset, revocation and asynchronous regrant.
    let isolation_text = format!("Alice post-removal message in {}", rooms[0]);
    let (ok, out, err) = vox(
        &alice,
        &["room", "post", &rooms[0], "--json", "-"],
        Some(&isolation_text),
    );
    assert!(
        ok,
        "PRODUCT: Alice's post-removal message was refused: {out}{err}"
    );
    let posted: serde_json::Value = serde_json::from_str(&out).unwrap_or_else(|error| {
        panic!("PRODUCT: Alice's post-removal answer was malformed ({error}): {out}{err}")
    });
    let isolation_hash = posted["entry_hash"]
        .as_str()
        .unwrap_or_else(|| {
            panic!("PRODUCT: Alice's post-removal answer named no entry hash: {posted}")
        })
        .to_owned();
    wait_governance_current(
        &alice,
        "alice",
        &rooms[0],
        "Carol's removal and the resulting Bob-only regrant never completed their bounded fold",
    );
    wait_room_status(
        &alice,
        "alice",
        &rooms[0],
        false,
        "Alice did not finish Bob's post-removal key delivery",
        |status| {
            !status
                .key_delivery_pending
                .iter()
                .any(|member| member == &fps[1])
        },
    );
    // This fresh message is a key-arrival canary for the following semantic checks, not an
    // already-retained-input continuation claim. Establish its actual readable baseline.
    wait_trust_detail(&bob, "bob", &rooms[0], "alice", "you trust each other");
    wait_governance_current(
        &bob,
        "bob",
        &rooms[0],
        "Bob's post-removal authority facts never became current",
    );
    loop {
        let rows = room_rows(&bob, &rooms[0]);
        let canary: Vec<_> = rows
            .iter()
            .filter(|row| row["entry_hash"] == isolation_hash)
            .collect();
        if canary
            .iter()
            .any(|row| row["envelope"]["body"].as_str().is_some())
        {
            assert_eq!(
                canary.len(),
                1,
                "PRODUCT: Bob showed the exact post-removal canary more than once: {canary:?}"
            );
            assert_eq!(
                canary[0]["envelope"]["body"].as_str(),
                Some(isolation_text.as_str()),
                "PRODUCT: Bob's exact post-removal canary had the wrong readable body: {canary:?}"
            );
            assert_eq!(
                canary[0]["owed"].as_bool(),
                Some(false),
                "PRODUCT: Bob's readable post-removal canary still said its body was owed: {canary:?}"
            );
            break;
        }
        std::thread::yield_now();
    }

    // A same-value authenticated action remains in the immutable room order. Its exact row and
    // authority-page completion stage the later sequence; revision cardinality is not a verdict.
    let order_before = room_hashes(&alice, "alice", &rooms[0]);
    let semantic_noop = rename_hash(&alice, "alice", &rooms[0], &rooms[0]);
    assert!(
        !order_before.contains(&semantic_noop)
            && room_hashes(&alice, "alice", &rooms[0]).contains(&semantic_noop),
        "PRODUCT: Alice's successful semantic-no-op rename named {semantic_noop}, but that exact \
         authenticated row was not newly present in room {}",
        rooms[0]
    );
    wait_governance_current(
        &alice,
        "alice",
        &rooms[0],
        "the exact same-name rename never completed its bounded governance fold",
    );
    let noop_page = loop {
        let (ok, out, err) = vox(
            &alice,
            &[
                "room",
                "read",
                &rooms[0],
                "--json",
                "--notices",
                "--limit",
                "1",
            ],
            None,
        );
        if ok {
            break out;
        }
        assert!(
            err.contains("governance") && err.contains("refreshing"),
            "PRODUCT: Alice could not read notices after the same-name rename: {out}{err}"
        );
        std::thread::yield_now();
    };
    let noop_rows: Vec<serde_json::Value> = noop_page
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            serde_json::from_str(line).unwrap_or_else(|error| {
                panic!("PRODUCT: Alice's same-name notice page was malformed ({error}): {line}")
            })
        })
        .collect();
    assert!(
        noop_rows.iter().any(|row| {
            row["schema"] == "vox.room.row/1" && row["entry_hash"] == isolation_hash
        }),
        "PRODUCT: Alice's same-name notice page omitted the preceding exact message \
         {isolation_hash}: {noop_page}"
    );
    assert!(
        !noop_rows.iter().any(|row| {
            row["schema"] == "vox.room.notice/1" && row["entry_hash"] == semantic_noop
        }),
        "PRODUCT: Alice displayed another room-change notice for the authenticated same-name \
         rename {semantic_noop}: {noop_page}"
    );

    // Alice's shipped status above is the source-owned terminal observation for the prior re-key:
    // its durable ledger and live delivery machinery both say Bob is owed nothing. Thus no delayed
    // package from Carol's removal can enter the interval below and masquerade as reset or grant2.
    // The original Alice→Bob grant is already user-visible and its sender key is held. Take Bob
    // offline, then drive one source-owned sender-generation bound through the shipped post
    // command. Rotation appends a Presence reset between the original grant and Alice's equal
    // grant to each still-trusted reader. The live and restarted answers must agree with that
    // authenticated sequence; a diagnostic room-order read does not prove network arrival order.
    assert_eq!(
        trust_detail(&bob, "bob", &rooms[0], "alice"),
        "you trust each other",
        "APPARATUS: the first Alice→Bob grant was not visibly effective before staging the \
         repeated-grant sequence"
    );
    let rotation_order_before = room_hashes(&alice, "alice", &rooms[0]);
    bob_daemon.stop();
    let mut last_rotated = None;
    let mut rotation_post_hashes = Vec::new();
    for row in 0..vox_core::group::ROTATE_AFTER_MESSAGES {
        let text = format!("Alice rotation proof row {row}");
        let (ok, out, err) = vox(
            &alice,
            &["room", "post", &rooms[0], "--json", "-"],
            Some(&text),
        );
        assert!(
            ok,
            "PRODUCT: Alice's shipped post {row} of the source-owned sender-generation bound \
             was refused: {out}{err}"
        );
        let posted: serde_json::Value = serde_json::from_str(&out).unwrap_or_else(|error| {
            panic!("PRODUCT: Alice's rotation-bound post answer was malformed ({error}): {out}")
        });
        let posted_hash = posted["entry_hash"]
            .as_str()
            .unwrap_or_else(|| {
                panic!("PRODUCT: Alice's rotation-bound post named no entry_hash: {posted}")
            })
            .to_owned();
        rotation_post_hashes.push(posted_hash.clone());
        if row + 1 == vox_core::group::ROTATE_AFTER_MESSAGES {
            last_rotated = Some((posted_hash, text));
        }
    }
    let (last_rotated_hash, last_rotated_text) = last_rotated
        .unwrap_or_else(|| panic!("APPARATUS: the source-owned rotation bound was empty"));
    wait_governance_current(
        &alice,
        "alice",
        &rooms[0],
        "the source-complete Presence→grant2 sequence never settled its bounded governance \
         work",
    );
    wait_trust_detail(&alice, "alice", &rooms[0], "bob", "you trust each other");
    // A current source fold can still precede the asynchronous regrant. Its affirmative
    // consent above is the witness. Capture the source-observed non-post interval without
    // guessing entry roles or capping legitimate maintenance/package work.
    let transition_rows = loop {
        let order = room_hashes(&alice, "alice", &rooms[0]);
        let rows: Vec<_> = order
            .iter()
            .filter(|hash| {
                !rotation_order_before.contains(hash) && !rotation_post_hashes.contains(hash)
            })
            .cloned()
            .collect();
        if rows.len() >= 2 {
            break rows;
        }
        std::thread::yield_now();
    };

    bob_daemon = daemon_env(&bob, "bob-repeated-grant", &package_knob);
    attached(&bob, "bob-repeated-grant");
    // A responding daemon may still be reopening this room. Stage its shipped open state
    // before observing the authenticated sequence; preparation is not a semantic verdict.
    wait_room_open(&bob, &rooms[0], "bob-repeated-grant");
    loop {
        let held = room_hashes(&bob, "bob", &rooms[0]);
        if transition_rows.iter().all(|hash| held.contains(hash)) {
            let actual: Vec<_> = held
                .iter()
                .filter(|hash| transition_rows.contains(hash))
                .collect();
            assert_eq!(
                actual,
                transition_rows.iter().collect::<Vec<_>>(),
                "PRODUCT: Bob's shipped order changed the authenticated quiet transitions: \
                 expected {transition_rows:?}; held {held:?}"
            );
            break;
        }
        std::thread::yield_now();
    }
    wait_governance_current(
        &bob,
        "bob",
        &rooms[0],
        "the source-generated reset and newer equal grant never completed their governance fold",
    );
    assert_eq!(
        trust_detail(&bob, "bob", &rooms[0], "alice"),
        "you trust each other",
        "PRODUCT: after the source-generated reset and newer equal grant completed, Bob no \
         longer saw Alice's newer grant as effective"
    );
    // The quiet transition set excludes posts: neither its arrival nor current governance
    // establishes receipt of this fresh generation's content. Stage its readable baseline
    // before the source-off restart claim; this is not a retained-continuation verdict.
    loop {
        let rows = room_rows(&bob, &rooms[0]);
        let canary: Vec<_> = rows
            .iter()
            .filter(|row| row["entry_hash"] == last_rotated_hash)
            .collect();
        if canary
            .iter()
            .any(|row| row["envelope"]["body"].as_str().is_some())
        {
            assert_eq!(
                canary.len(),
                1,
                "PRODUCT: Bob showed the exact rotation canary more than once: {canary:?}"
            );
            assert_eq!(
                canary[0]["envelope"]["body"].as_str(),
                Some(last_rotated_text.as_str()),
                "PRODUCT: Bob's exact rotation canary had the wrong readable body: {canary:?}"
            );
            assert_eq!(
                canary[0]["owed"].as_bool(),
                Some(false),
                "PRODUCT: Bob's readable rotation canary still said its body was owed: {canary:?}"
            );
            break;
        }
        std::thread::yield_now();
    }

    // Restart with Alice unavailable. The same exact retained object still reading proves the
    // durable Consent locator names grant₂. The pre-restart observation proves the live answer
    // agrees with the authenticated sequence; no particular network arrival order is claimed.
    alice_restarted.stop();
    bob_daemon.stop();
    bob_daemon = daemon_env(&bob, "bob-repeated-grant-restarted", &package_knob);
    attached(&bob, "bob-repeated-grant-restarted");
    wait_room_open(&bob, &rooms[0], "bob-repeated-grant-restarted");
    wait_governance_current(
        &bob,
        "bob",
        &rooms[0],
        "Bob's durable governance projection never completed after restart",
    );
    assert_eq!(
        trust_detail(&bob, "bob", &rooms[0], "alice"),
        "you trust each other",
        "PRODUCT: after Bob's durable governance projection completed on restart, the older \
         reset revoked Alice's newer equal grant"
    );
    assert_exact_read_rows(
        &bob,
        "bob",
        &rooms[0],
        std::slice::from_ref(&last_rotated_hash),
        std::slice::from_ref(&last_rotated_text),
        "Bob restarted with Alice unavailable after the equal-grant sequence",
    );
    alice_restarted = daemon_env(&alice, "alice-after-repeated-grant", &fold_knob);
    attached(&alice, "alice-after-repeated-grant");
    wait_room_open(&alice, &rooms[0], "alice-after-repeated-grant");
    // Keep both shipped daemons alive for the remaining user journey.
    let _running_after_repeated_grant = (&alice_restarted, &bob_daemon);

    // The exact post after Alice's revocation is a causal boundary: once Bob retains that
    // descendant, his doctor answer can no longer be an observation made before the revocation.
    // Alice's key rotation also keeps the descendant unreadable, so this checks the consent
    // projection itself rather than granting the row through an old key.
    let (ok, out, err) = vox(&alice, &["trust", "remove", &fps[1]], None);
    assert!(
        ok,
        "PRODUCT: Alice's `vox trust remove bob` failed: {out}{err}"
    );
    let revoked_text = "after Alice revoked Bob";
    let (ok, out, err) = vox(
        &alice,
        &["room", "post", &rooms[0], "--json", "-"],
        Some(revoked_text),
    );
    assert!(
        ok,
        "PRODUCT: Alice's post after revocation failed: {out}{err}"
    );
    let posted: serde_json::Value = serde_json::from_str(&out).unwrap_or_else(|error| {
        panic!("PRODUCT: Alice's post-after-revocation answer was malformed ({error}): {out}")
    });
    let revoked_hash = posted["entry_hash"]
        .as_str()
        .unwrap_or_else(|| panic!("PRODUCT: post-after-revocation named no entry_hash: {posted}"))
        .to_owned();
    wait_for_held_rows(
        &bob,
        &rooms[0],
        std::slice::from_ref(&revoked_hash),
        "revocation descendant",
    );
    assert_eq!(
        trust_detail(&bob, "bob", &rooms[0], "alice"),
        "you trust it; your node has not received its trust for you, so cannot tell whether it trusts you",
        "PRODUCT: after Bob retained Alice's exact post-revocation descendant {revoked_hash}, \
         `vox agent doctor` still answered from stale in-memory consent"
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
/// Live posts alice makes while bob fetches, each its own `vox room post`.
const LIVE_POSTS: usize = 40;

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
/// Mutant: the control acceptor made to wait on the actor's turn (a sleep past 500 ms in the
/// hook's greeting path) turns the first assertion red on the hook's own sentence; the
/// contiguous feed's length restored as the room's count (`entry_count()` in `summary_of`)
/// turns the FX-16 claim red on its two numbers.
///
#[cfg(feature = "optional-proofs")]
#[test]
#[ignore = "a timing bound a person feels; two real vox daemons; optional, run it in release"]
fn a_daemon_answers_the_hook_while_syncing() {
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
        for i in 1..=LIVE_POSTS {
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
            bob_status,
            alice_status,
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

/// What `vox status --json` reports under `rooms[].log_entries`: every contiguous authenticated
/// log row, including the control rows a person does not see in `vox room read`.
fn status_log_entries(dir: &Path, room: &str) -> Option<u64> {
    let (ok, out, _) = vox(dir, &["status", "--json"], None);
    if !ok {
        return None;
    }
    serde_json::from_str::<serde_json::Value>(&out).ok()?["rooms"]
        .as_array()?
        .iter()
        .find(|r| r["id"].as_str().is_some_and(|id| id.starts_with(room)))?["log_entries"]
        .as_u64()
}

/// Whether shipped status says the generic package-maintenance queue is pending. Supplemental
/// only: the initial catalog scan also sets this bit, so it never identifies a package by itself.
fn key_packages_pending(dir: &Path, room: &str) -> Option<bool> {
    let (ok, out, _) = vox(dir, &["status", "--json"], None);
    if !ok {
        return None;
    }
    serde_json::from_str::<serde_json::Value>(&out).ok()?["rooms"]
        .as_array()?
        .iter()
        .find(|r| r["id"].as_str().is_some_and(|id| id.starts_with(room)))?["key_packages_pending"]
        .as_bool()
}

/// Whether shipped status says one exact room member has a live connection. `None` means the
/// command, room, member, or field was absent rather than silently meaning disconnected.
fn member_connected(dir: &Path, room: &str, member: &str) -> Option<bool> {
    member_connected_as(dir, None, room, member)
}

fn member_connected_as(dir: &Path, node: Option<&str>, room: &str, member: &str) -> Option<bool> {
    let (ok, out, err) = vox(dir, &as_node(&["status", "--json"], node), None);
    if !ok
        && (out.contains("this data root holds several nodes")
            || err.contains("this data root holds several nodes"))
    {
        panic!(
            "APPARATUS: member-connection observation did not select a stored node \
             (asked {node:?}) for {room}/{member}: {out}{err}"
        );
    }
    if !ok {
        return None;
    }
    let value: serde_json::Value = serde_json::from_str(&out).ok()?;
    value["rooms"]
        .as_array()?
        .iter()
        .find(|row| row["id"].as_str().is_some_and(|id| id.starts_with(room)))?["members"]
        .as_array()?
        .iter()
        .find(|row| row["id"].as_str() == Some(member))?["connected"]
        .as_bool()
}

fn room_own_feed_through(dir: &Path, room: &str) -> Option<u64> {
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

fn member_held_through(dir: &Path, room: &str, member: &str) -> Option<u64> {
    member_held_through_state(dir, room, member).flatten()
}

/// The shipped status observation for one member's receipt of this node's feed. Outer `None`
/// means the command, room, member, or receipt field was absent or malformed; inner `None` is
/// exclusively the valid JSON-null no-receipt state.
fn member_held_through_state(dir: &Path, room: &str, member: &str) -> Option<Option<u64>> {
    let (ok, out, _) = vox(dir, &["status", "--json"], None);
    if !ok {
        return None;
    }
    let value: serde_json::Value = serde_json::from_str(&out).ok()?;
    let row = value["rooms"]
        .as_array()?
        .iter()
        .find(|row| row["id"].as_str().is_some_and(|id| id.starts_with(room)))?["members"]
        .as_array()?
        .iter()
        .find(|row| row["id"].as_str() == Some(member))?;
    match row.get("held_through")? {
        serde_json::Value::Null => Some(None),
        serde_json::Value::Number(value) => value.as_u64().map(Some),
        _ => None,
    }
}

/// The local role-complete cursor for `member` as the shipped status command reports it.
fn member_holds_through(dir: &Path, room: &str, member: &str) -> Option<u64> {
    let (ok, out, _) = vox(dir, &["status", "--json"], None);
    if !ok {
        return None;
    }
    let value: serde_json::Value = serde_json::from_str(&out).ok()?;
    value["rooms"]
        .as_array()?
        .iter()
        .find(|row| row["id"].as_str().is_some_and(|id| id.starts_with(room)))?["members"]
        .as_array()?
        .iter()
        .find(|row| row["id"].as_str() == Some(member))?["verified_through"]
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

/// A room that cannot finish preparing says what it waits for, costs nothing while it waits, and
/// opens once the wait ends (ADR-038 FX-15, FX-16; #991). A test-only hold pauses the reopened
/// room's saved-history projection, after six ordinary posts have been accepted. Within
/// [`WAIT_NAMED_WITHIN`] `vox room list` MUST say `[preparing history:
/// waiting for …]`, `vox status --json` MUST list the room under `preparing` with the same words,
/// and `vox room read` MUST first say the wait once, then refuse with it if preparation stays held;
/// over [`PREPARING_IDLE`] the daemon's CPU time MUST grow by at most [`PREPARING_CPU`] and its
/// log MUST say once what the room waited for. A read and a post wait until the hold is removed,
/// then succeed; the room opens within [`OPENS_WITHIN`] and its six original rows read.
/// Found 2026-10-20 on the decider's work Mac (v0.4.7): a room stayed "[preparing history]" for
/// 20 hours with no words anywhere, re-queued every 50 ms, absent from `vox status`.
///
/// The former governance-fold hold and its unnamed-governance-wait mutant are not claimed here.
/// Since fe439467c, a peer's current Presence/consent facts are published at acceptance, outside
/// canonical-history replay; holding that replay no longer keeps this join/post fixture preparing.
/// The unchanged old arm opens on main too. This arm holds the reopened room's projection turn
/// instead; it does not claim coverage of a pending canonical-governance fold.
///
/// Mutant: the command's room guard refuses immediately instead of waiting; its read and post
/// then return the preparing refusal without the waiting line.
#[cfg(feature = "optional-proofs")]
#[test]
#[ignore = "a minute of a real vox daemon holding a room, and a test-only knob; optional, run it in release"]
fn a_room_that_cannot_finish_preparing_says_why_and_costs_nothing() {
    test_knobs::require(&["VOX_TEST_PREPARING_HOLD_FILE"]);
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap_or_else(|e| panic!("APPARATUS: no temp dir: {e}"));
    let root = tmp.path();
    let alice = root.join("alice");
    let bob = root.join("bob");
    for d in [&alice, &bob] {
        std::fs::create_dir_all(d.join("cfg"))
            .unwrap_or_else(|e| panic!("APPARATUS: could not create {}: {e}", d.display()));
    }
    let hold = root.join("preparing-hold");
    let hold_path = hold
        .to_str()
        .expect("APPARATUS: a UTF-8 temp path")
        .to_owned();
    let knob = [("VOX_TEST_PREPARING_HOLD_FILE", hold_path.as_str())];
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

    // Alice creates the room and posts; Bob joins and contributes three more ordinary rows.
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
    // Arm the reopened room's preparation; this does not hold its live-room maintenance.
    std::fs::write(&hold, b"").expect("APPARATUS: write the preparation hold file");
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
    // Allow the six ordinary rows to arrive before restarting.
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
            assert!(
                line.contains("waiting for building its saved history projection"),
                "PRODUCT: `vox room list` names another wait than the held projection: {line}"
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
    let snapshot_within = Instant::now() + WAIT_NAMED_WITHIN;
    while !said(&alice, "alice").contains("1 room(s) are preparing saved history") {
        assert!(
            Instant::now() < snapshot_within,
            "APPARATUS: startup did not report the held room as preparing: {}",
            said(&alice, "alice")
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    let startup_console = std::fs::read_to_string(alice.join("daemon-alice.out"))
        .expect("APPARATUS: read startup console");
    assert!(
        !startup_console
            .lines()
            .any(|line| line.contains("holding room") && line.contains(&room)),
        "APPARATUS: the held preparing room was already announced open: {startup_console}"
    );
    let mut refused = Vec::new();
    for args in [
        vec!["room", "read", &room, "--json"],
        vec!["room", "post", &room, "a word while it prepares"],
    ] {
        let (ok, out, err) = vox(&alice, &args, None);
        let wait_lines: Vec<_> = err
            .lines()
            .filter(|line| line.contains("to finish preparing; it waits for"))
            .collect();
        println!(
            "[proof] held preparation command {args:?}: ok={ok} stdout={out:?} stderr={err:?}"
        );
        refused.push((
            !ok && out.is_empty()
                && wait_lines.len() == 1
                && wait_lines[0].contains(&what)
                && err.contains(&format!("it waits for {what}"))
                && err.contains("that room is preparing its saved history"),
            format!("{args:?}: ok={ok} stdout={out:?} stderr={err:?}"),
        ));
    }
    assert!(
        refused.iter().all(|(correct, _)| *correct),
        "PRODUCT: held read and post must each say the named wait once, then today's refusal: {refused:?}"
    );
    // ---- the wait costs nothing -------------------------------------------------------------
    let pid = second.0.id();
    let cpu0 = cpu_time(pid);
    std::thread::sleep(PREPARING_IDLE);
    let spent = cpu_time(pid).saturating_sub(cpu0);
    let log = std::fs::read_to_string(alice.join(".daemon/log")).unwrap_or_default();
    let noted: Vec<&str> = log
        .lines()
        .filter(|l| l.contains("is still preparing: it waits for "))
        .collect();
    println!(
        "[proof] over {PREPARING_IDLE:?} the held room cost the daemon +{spent:?} of CPU (bound {PREPARING_CPU:?}); its log says: {noted:?}"
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

    // A read and a post must both go on by themselves when the hold is removed.
    let mut waiting = Vec::new();
    for (kind, args) in [
        ("read", vec!["room", "read", &room, "--json"]),
        (
            "post",
            vec!["room", "post", &room, "a word after preparation"],
        ),
    ] {
        let stderr = root.join(format!("preparing-{kind}.err"));
        let child = Command::new(VOX)
            .args(&args)
            .env("VOX_DATA_DIR", &alice)
            .env("VOX_CONFIG_DIR", alice.join("cfg"))
            .env("VOX_IDENTITY_PASSPHRASE", IDENTITY)
            .env_remove("VOX_ROOM")
            .env_remove("VOX_SESSION")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::from(
                std::fs::File::create(&stderr).expect("APPARATUS: command stderr"),
            ))
            .spawn()
            .expect("APPARATUS: start a command while the room is preparing");
        waiting.push((kind, child, stderr));
    }
    let deadline = Instant::now() + Duration::from_secs(10);
    for (kind, child, stderr) in &mut waiting {
        loop {
            let err = std::fs::read_to_string(&*stderr).expect("APPARATUS: waiting report");
            assert!(
                child
                    .try_wait()
                    .expect("APPARATUS: inspect waiting command")
                    .is_none(),
                "PRODUCT: {kind} exited before preparation was released: {err:?}"
            );
            if err.contains("to finish preparing; it waits for") {
                assert!(
                    err.contains(&what),
                    "PRODUCT: {kind} named another wait: {err:?}"
                );
                break;
            }
            assert!(
                Instant::now() < deadline,
                "APPARATUS: {kind} did not report its wait: {err:?}"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    // ---- the wait ends: both commands finish without another invocation --------------------
    let released = Instant::now();
    std::fs::remove_file(&hold).expect("APPARATUS: remove the hold file");
    for (kind, child, stderr) in waiting {
        let output = child
            .wait_with_output()
            .expect("APPARATUS: wait for command");
        let report = std::fs::read_to_string(stderr).expect("APPARATUS: wait report");
        let out = String::from_utf8(output.stdout).expect("PRODUCT: command output is not UTF-8");
        println!(
            "[proof] released preparation {kind}: status={} stdout={out:?} stderr={report:?}",
            output.status
        );
        assert!(
            output.status.success()
                && report.lines().filter(|line| line.contains("to finish preparing")).count() == 1
                && (kind != "read" || out.lines().all(|line| serde_json::from_str::<serde_json::Value>(line).is_ok())),
            "PRODUCT: {kind} did not resume after preparation with one wait line: status={} stdout={out:?} stderr={report:?}",
            output.status
        );
    }
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
    let console_within = Instant::now() + OPENS_WITHIN;
    loop {
        let console = std::fs::read_to_string(alice.join("daemon-alice.out"))
            .expect("APPARATUS: read resumed daemon console");
        let lines: Vec<_> = console
            .lines()
            .filter(|line| {
                line.starts_with("vox daemon: holding room ")
                    && line.contains(&room)
                    && line.ends_with(" open (node default)")
            })
            .collect();
        if !lines.is_empty() {
            assert_eq!(
                lines.len(),
                1,
                "PRODUCT: held room was announced open more than once: {console}"
            );
            println!(
                "[proof] preparation finished, daemon console says: {}",
                lines[0]
            );
            break;
        }
        assert!(
            Instant::now() < console_within,
            "PRODUCT: room opened after the startup snapshot but the daemon never said holding room open: {console}"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    // A fresh peer row makes the post-restart round useful, even if all six earlier rows
    // were already saved before the restart. A hint alone is not a completed useful sync.
    let (ok, out, err) = vox(
        &bob,
        &["room", "post", &room, "a fresh row after preparation"],
        None,
    );
    assert!(ok, "PRODUCT: bob's fresh post was refused: {out}{err}");
    let opened = Instant::now();
    loop {
        let (ok, out, err) = vox(&alice, &["room", "read", &room], None);
        if ok
            && (1..=6).all(|i| out.contains(&format!("row {i}")))
            && out.contains("a fresh row after preparation")
        {
            break;
        }
        assert!(
            opened.elapsed() < Duration::from_secs(60),
            "PRODUCT: the opened room does not read all six saved rows and bob's fresh row within 60 s: ok={ok}\n{out}{err}\nalice's daemon said: {}",
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
        let recorded = v["rooms"].as_array().is_some_and(|rooms| {
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
            out
        );
        std::thread::sleep(Duration::from_millis(500));
    }
    drop(second);
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

/// A process's CPU time so far, as Activity Monitor shows it (`ps -o cputime`).
fn cpu_time(pid: u32) -> Duration {
    let out = Command::new("ps")
        .args(["-o", "cputime=", "-p", &pid.to_string()])
        .output()
        .unwrap_or_else(|e| panic!("APPARATUS: ps: {e}"));
    assert!(
        out.status.success(),
        "APPARATUS: `ps` could not observe daemon {pid}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8_lossy(&out.stdout).trim().to_owned();
    // MM:SS.ss or HH:MM:SS
    let mut parts: Vec<&str> = text.split(':').collect();
    let secs: f64 = parts.pop().and_then(|s| s.parse().ok()).unwrap_or_else(|| {
        panic!("APPARATUS: `ps` printed no CPU seconds for daemon {pid}: {text}")
    });
    let mins: f64 = parts.pop().and_then(|s| s.parse().ok()).unwrap_or_else(|| {
        panic!("APPARATUS: `ps` printed no CPU minutes for daemon {pid}: {text}")
    });
    let hours: f64 = parts.pop().map_or(0.0, |s| {
        s.parse().unwrap_or_else(|_| {
            panic!("APPARATUS: `ps` printed bad CPU hours for daemon {pid}: {text}")
        })
    });
    assert!(
        parts.is_empty(),
        "APPARATUS: `ps` printed an unknown CPU time for daemon {pid}: {text}"
    );
    Duration::from_secs_f64(hours * 3600.0 + mins * 60.0 + secs)
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
        if history >= posts {
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
    // Diagnostics only (no assertion): bob's rounds by reason, e.g. how many inventory rounds
    // the announcements owed (`reasons.announce`).
    let (_, status, _) = vox(&bob, &["status", "--json"], None);
    for (at, _) in status.match_indices("\"reasons\":{") {
        let reasons = &status[at..];
        let end = reasons.find('}').map_or(reasons.len(), |end| end + 1);
        println!("[diag] bob sync {}", &reasons[..end]);
    }
    assert!(
        distinct.len() == posts,
        "PRODUCT: a member trusted before every post must read all {posts} of them on explicit \
         demand (V210-45), but read {}; missing posts {:?}",
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

/// ADR-052 RG-1 is optional until the admission, trust and delivery requirements land.
#[cfg(feature = "optional-proofs")]
#[test]
#[ignore = "four real daemons, three stepping Sessions and a paused member; optional"]
fn a_busy_room_newcomer_reads_every_member_with_a_paused_member() {
    rg1::journey(false);
}

#[cfg(feature = "optional-proofs")]
#[test]
#[ignore = "four real daemons, three stepping Sessions and a delayed relay path; optional"]
fn a_busy_room_newcomer_reads_every_member_with_a_delayed_path() {
    rg1::journey(true);
}

#[cfg(feature = "optional-proofs")]
#[test]
#[ignore = "five thousand CLI posts and one real daemon; optional"]
fn the_busy_room_reader_finds_the_first_of_five_thousand_rows() {
    rg1::paging_check();
}

/// ADR-052 RG-6: a member returns after 8,000 acknowledged posts. Its node owes itself every
/// post above its floor (it showed a post from before it left) and fetches them unasked
/// (ADR-054 PL-3). GREEN: the newest post shows before more than two pages of the backlog, and
/// a paged `vox room read` comes to show all 8,000 with no `--history` request. RED PRODUCT: the
/// newest is not among the first two pages shown, or the shown count stops moving short of
/// complete for ten answered reads a second apart. Mutant: `VOX_MUTANT_NO_PROMOTION=1` (ADR-054
/// M3, the returned reader's daemon only).
#[cfg(feature = "optional-proofs")]
#[test]
#[ignore = "eight thousand CLI posts and two real daemons; optional"]
fn a_returning_reader_eight_thousand_entries_behind_reads_and_pages_back() {
    rg1::returning_reader();
}

/// ADR-052 RG-6: a member that verified another author's evidence serves it again after a
/// restart. The author is stopped; a newcomer that reaches only that member reads its post.
#[cfg(feature = "optional-proofs")]
#[test]
#[ignore = "three real daemons, a stopped author and a restarted holder; optional"]
fn a_newcomer_reads_a_member_while_the_author_it_cites_is_stopped() {
    rg1::holder_serves_what_it_verified(rg1::Cited::Posts);
}

/// A newcomer admitted while the author was stopped is listed after the author returns.
#[cfg(feature = "optional-proofs")]
#[test]
#[ignore = "three real daemons, a stopped author, a stopped inviter; optional"]
fn a_returned_author_knows_the_newcomer_admitted_while_it_was_away() {
    rg1::a_returned_author_knows_the_newcomer();
}

/// A member whose own room save is held still answers another member's requests for headers,
/// proofs and bodies at once: the reader, back after the author posted, shows the author's posts
/// while the author's save stays held, the only holder of their headers and proofs being the
/// author.
#[cfg(feature = "optional-proofs")]
#[test]
#[ignore = "three real daemons and a held save; optional"]
fn a_member_whose_own_save_is_held_still_answers() {
    rg1::a_held_member_answers();
}

/// A member whose room cannot save (poisoned, as a failed write poisons it) answers nobody that
/// room's history, and answers again once the room has recovered: the reader, back after the
/// author posted, does not show the author's post while the author turns its requests away, and
/// shows it once the author's room can save again. RED PRODUCT when the reader shows the post
/// while the author's room is poisoned. Mutant: `VOX_MUTANT_POISON_KEEPS_SNAPSHOT`.
#[cfg(feature = "optional-proofs")]
#[test]
#[ignore = "three real daemons and a poisoned room; optional"]
fn a_member_whose_room_cannot_save_answers_nobody_until_it_recovers() {
    rg1::a_poisoned_member_answers_nobody();
}

/// ADR-053 MP-7 (a) without the misleading newer head: the holder's later post depends on a
/// control in the stopped author's feed (the author's context advance after the holder's post).
/// The holder restarts; a newcomer that reaches only the holder must verify that control
/// evidence from it, and ends up trusted, keyed and reading the holder's post.
#[cfg(feature = "optional-proofs")]
#[test]
#[ignore = "three real daemons, a stopped author with a later control and a restarted holder; optional"]
fn a_newcomer_reads_a_member_past_the_stopped_authors_control() {
    rg1::holder_serves_what_it_verified(rg1::Cited::AfterControl);
}

/// ADR-053 P (moving-head ruling §5): a holder serves a newcomer under the author's head the
/// newcomer committed, which the holder skipped: it rebuilds that prefix from its own committed
/// larger head. The author is stopped; the newcomer reads the holder's post from the holder
/// alone. Mutant: `VOX_MUTANT_PREFIX_GATE=header|proof|entry` (that stage serves committed
/// heads only; `proof` is all three proof kinds).
#[cfg(feature = "optional-proofs")]
#[test]
#[ignore = "three real daemons, a skipped head, a stopped author and a restarted holder; optional"]
fn a_newcomer_reads_from_a_holder_that_skipped_its_head_of_the_author() {
    rg1::holder_serves_a_prefix_it_never_committed(rg1::Provider::Honest);
}

/// ADR-053 P guard (moving-head ruling §5): the same staging, but the holder corrupts one
/// descriptor in every proof it serves under the newcomer's head, which it never committed.
/// The newcomer shows and applies nothing from it, stays pending on the author, calls nothing a
/// fork, and still reads the same holder in another room. Mutant: `VOX_MUTANT_ASKER_ROOT=1`
/// (the newcomer's verifiers skip the root check): it shows the holder's post.
#[cfg(feature = "optional-proofs")]
#[test]
#[ignore = "three real daemons, a corrupting holder, a stopped author; optional"]
fn a_newcomer_shows_nothing_a_corrupting_holder_serves_under_its_head() {
    rg1::holder_serves_a_prefix_it_never_committed(rg1::Provider::Corrupt);
}

/// ADR-053 P guard (moving-head ruling §5): the same staging, but the holder is on another fork
/// of the author (a copy of the author's profile from before the newcomer's head wrote other
/// posts there) and answers under the newcomer's head with its own branch's prefix. The
/// newcomer applies nothing from it (its anchor stays), stays pending, calls no fork from those
/// proofs, and still reads the same holder in another room. The author really signed two
/// histories, so with ADR-053 MP-9 the newcomer records that fork, but only through the holder's
/// listed proof (`Query::Fork`), never from its answers. Two things stand between the forked
/// holder's answers and the screen here: the fork proof freezes the author, and the newcomer's
/// root check refuses
/// the holder's proofs under its head. Mutant: `VOX_MUTANT_FORK=fork-unpropagated` (passed to
/// the holder alone: it records the fork but never lists it): RED on the positive assertion, the
/// fork is never recorded through the proof. No mutant reaches the show claim in this scene (the
/// proof freezes the author first; `VOX_MUTANT_ASKER_ROOT=1` never engages here), so here it is
/// printed as an observation ("observed: nothing of the forked holder's branch was shown"), not
/// asserted: the show claim is proven by
/// `a_newcomer_shows_nothing_a_corrupting_holder_serves_under_its_head`, RED under
/// `VOX_MUTANT_ASKER_ROOT=1`.
#[cfg(feature = "optional-proofs")]
#[test]
#[ignore = "three real daemons, a copied author on another fork, a stopped author; optional"]
fn a_newcomer_shows_nothing_a_holder_on_another_fork_serves_under_its_head() {
    rg1::holder_serves_a_prefix_it_never_committed(rg1::Provider::Forked);
}

/// ADR-053 P guard: the corrupting holder of the guard above corrupts only the consistency
/// proofs it serves under the newcomer's head; inclusion stays honest, so the newcomer reaches
/// the consistency kind and must refuse it there. Mutant: `VOX_MUTANT_ASKER_ROOT=1`.
#[cfg(feature = "optional-proofs")]
#[test]
#[ignore = "three real daemons, a holder corrupting consistency proofs, a stopped author; optional"]
fn a_newcomer_shows_nothing_a_holder_serves_with_a_corrupt_consistency_proof() {
    rg1::holder_serves_a_prefix_it_never_committed(rg1::Provider::CorruptConsistency);
}

/// ADR-053 P guard: as above, with only the control proofs corrupted. Mutant:
/// `VOX_MUTANT_ASKER_ROOT=1`.
#[cfg(feature = "optional-proofs")]
#[test]
#[ignore = "three real daemons, a holder corrupting control proofs, a stopped author; optional"]
fn a_newcomer_shows_nothing_a_holder_serves_with_a_corrupt_control_proof() {
    rg1::holder_serves_a_prefix_it_never_committed(rg1::Provider::CorruptControl);
}

/// change-14: a newcomer shows authors who keep posting past controls they wrote. See
/// `rg1::newcomer_reads_authors_past_their_controls`.
#[cfg(feature = "optional-proofs")]
#[test]
#[ignore = "ten real daemons, controls, a post a second from every author; optional, run it QUIET"]
fn a_newcomer_reads_authors_who_keep_posting_past_their_controls() {
    rg1::newcomer_reads_authors_past_their_controls();
}

#[cfg(feature = "optional-proofs")]
#[path = "support/port_forward.rs"]
mod port_forward;
#[cfg(feature = "optional-proofs")]
#[path = "support/relay.rs"]
mod relay;
#[cfg(feature = "optional-proofs")]
#[path = "support/room.rs"]
mod rg1_room;
#[cfg(feature = "optional-proofs")]
#[path = "support/world.rs"]
mod world;

/// Only apparatus lives here: every room, Session and observation belongs to a real binary.
#[cfg(feature = "optional-proofs")]
mod rg1 {
    use super::{port_forward, rg1_room as room, world, Daemon};
    use room::Worker;
    use serde_json::{json, Value};
    use std::collections::{BTreeMap, BTreeSet};
    use std::io::{BufRead, BufReader, Write};
    use std::path::Path;
    use std::process::{Command, Stdio};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    /// ADR-054 M3, the returning reader's mutant: no head a peer committed is ever promoted,
    /// so the reader stays on the author's head from before it went away.
    const PROMOTION_MUTANT: &str = "VOX_MUTANT_NO_PROMOTION";

    fn root() -> tempfile::TempDir {
        let mut builder = tempfile::Builder::new();
        builder.prefix("rg1-");
        let mut dir = match std::env::var_os("VOX_PROOF_RG1_EVIDENCE") {
            Some(at) => builder.tempdir_in(at),
            None => builder.tempdir(),
        }
        .expect("APPARATUS: create RG-1 scratch directory");
        if std::env::var_os("VOX_PROOF_KEEP_DIRS").is_some() {
            dir.disable_cleanup(true);
        }
        eprintln!("[RG-1] scratch={}", dir.path().display());
        dir
    }

    fn binary() -> String {
        std::env::var("VOX_PROOF_SHIPPED_BINARY").unwrap_or_else(|_| super::VOX.to_owned())
    }

    fn free_disk(at: &Path) {
        let out = Command::new("df")
            .args(["-Pk"])
            .arg(at)
            .output()
            .expect("APPARATUS: measure free disk");
        let text = String::from_utf8_lossy(&out.stdout);
        let available = text
            .lines()
            .nth(1)
            .and_then(|line| line.split_whitespace().nth(3))
            .and_then(|n| n.parse::<u64>().ok());
        assert!(
            out.status.success() && available.is_some_and(|kb| kb >= 10 * 1024 * 1024),
            "APPARATUS: RG-1 needs at least 10 GiB free disk: {text}"
        );
        eprintln!("[RG-1] free disk: {text}");
    }

    fn start(w: &Worker, listen: &str, anchor: Option<&str>) -> Daemon {
        start_with(w, listen, anchor, &[])
    }

    /// [`start`] with staging knob variables for this one daemon (a relay mode it runs in).
    fn start_with(
        w: &Worker,
        listen: &str,
        anchor: Option<&str>,
        knobs: &[(&str, std::path::PathBuf)],
    ) -> Daemon {
        std::fs::create_dir_all(w.data.with_extension("home"))
            .expect("APPARATUS: daemon scratch HOME");
        // Headless `node create` can auto-start this scratch computer's daemon.
        // Replace that owned setup service before taking ownership of the serving child.
        room::reap_daemon(&w.data);
        let mut cmd = Command::new(&w.exe);
        room::strip_harness_env(&mut cmd);
        cmd.args(["daemon", "--node"])
            .arg(
                w.paths
                    .profile_dir
                    .file_name()
                    .expect("APPARATUS: daemon node"),
            )
            .args(["--listen", listen, "--passphrase-file"])
            .arg(&w.pass)
            .env("HOME", w.data.with_extension("home"))
            .env("VOX_DATA_DIR", &w.data)
            .env("VOX_CONFIG_DIR", &w.cfg)
            .env("VOX_PROXY", "127.0.0.1:0")
            // Mutant switches, forwarded as the knobs the daemon reads.
            .envs(
                std::env::vars_os()
                    .filter(|(name, _)| name.to_string_lossy().starts_with("VOX_MUTANT_")),
            )
            .envs(knobs.iter().map(|(name, value)| (*name, value)))
            .stdout(Stdio::from(
                std::fs::File::create(w.data.with_extension("out"))
                    .expect("APPARATUS: daemon stdout"),
            ))
            .stderr(Stdio::from(
                std::fs::File::create(w.data.with_extension("err"))
                    .expect("APPARATUS: daemon stderr"),
            ));
        if let Some(anchor) = anchor {
            cmd.args(["--anchor", anchor]);
        }
        let mut daemon = Daemon(cmd.spawn().expect("APPARATUS: start RG-1 daemon"));
        eprintln!(
            "[RG-1] daemon {} pid={} binary={}",
            w.name,
            daemon.0.id(),
            w.exe
        );
        let since = Instant::now();
        // Do not run an auto-attaching verb before this daemon has its lock.
        while !world::daemon_lock(&w.data).exists() {
            assert!(
                daemon
                    .0
                    .try_wait()
                    .expect("APPARATUS: daemon wait")
                    .is_none()
                    && since.elapsed() < Duration::from_secs(240),
                "APPARATUS: {}'s serving daemon did not start; see {}",
                w.name,
                w.data.with_extension("err").display()
            );
            std::thread::sleep(Duration::from_millis(100));
        }
        loop {
            let out = w.vox(None, &["room", "list"]);
            if out.ok {
                assert_eq!(
                    world::daemon_pid(&w.data),
                    Some(daemon.0.id()),
                    "APPARATUS: spawned pid is not {}'s serving daemon",
                    w.name
                );
                return daemon;
            }
            assert!(
                since.elapsed() < Duration::from_secs(240),
                "APPARATUS: {} never attached for staging: {out:?}",
                w.name
            );
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// **A newcomer shows authors who keep posting past controls they wrote** (change-14; the
    /// busy-room journey j-c11: every author's control closure on the newcomer stopped at one
    /// control-source body, "lacks control-source-body" about 500 times per author while the
    /// newcomer asked that body zero times).
    ///
    /// Staging: `authors` posting members (`VOX_PROOF_CONTROL_AUTHORS`, default 8) and one more
    /// member C, each in its own daemon, all trusting each other. The first author A creates the
    /// room; the others and C join. A then writes controls between its posts: Session-step
    /// retention 7d, an admin grant to the second author, a rename, C's removal and retention
    /// 2d. Every author then posts about once a second (the journey's cadence); the newcomer N
    /// joins and posts about once a second too, as n-new does in the journey. An author's
    /// marker is its first post acknowledged after N's join returned.
    ///
    /// GREEN: for every author N shows the marker or a later post of it before that author has
    /// acknowledged 100 posts since the join (this act family's bound). RED PRODUCT: an author
    /// acknowledged 100 posts since the join and N shows none of them. Eight authors reproduce
    /// j-c11 on the stack before change-14 (two, four and six do not).
    ///
    /// Mutant (ADR-054 M13), forwarded to the daemons; its engaged line is required on N's
    /// stderr: `VOX_MUTANT_NEED_SETTLES_EVERY_ROOT` (a need settles every unsettled root of N's
    /// admission, every author's, as waiting on it: one author's need holds the others' posts).
    pub(super) fn newcomer_reads_authors_past_their_controls() {
        const SEED: usize = 4;
        const BOUND: usize = 100;
        const MUTANT: &str = "VOX_MUTANT_NEED_SETTLES_EVERY_ROOT";
        let authors_wanted: usize = std::env::var("VOX_PROOF_CONTROL_AUTHORS")
            .ok()
            .and_then(|n| n.parse().ok())
            .unwrap_or(8)
            .max(2);
        let mutant = std::env::var_os(MUTANT).is_some();
        if mutant {
            super::test_knobs::require_in(&binary(), &[MUTANT]);
            // The mutant is the newcomer's alone: the authors stage the room unmutated, so
            // `start` must not forward it; the newcomer's daemon is given it by name below.
            std::env::remove_var(MUTANT);
        }
        let root = root();
        let exe = binary();
        let authors: Vec<Worker> = (0..authors_wanted)
            .map(|i| room::worker_as(root.path(), &format!("ctl-author{i}"), &exe))
            .collect();
        let removed = room::worker_as(root.path(), "ctl-removed", &exe);
        let reader = room::worker_as(root.path(), "ctl-reader", &exe);
        let everyone: Vec<&Worker> = authors.iter().chain([&removed, &reader]).collect();
        let _daemons: Vec<Daemon> = everyone
            .iter()
            .map(|w| {
                let given = [(MUTANT, std::path::PathBuf::from("1"))];
                let knobs = if mutant && w.name == reader.name {
                    &given[..]
                } else {
                    &[]
                };
                start_with(w, "127.0.0.1:0", None, knobs)
            })
            .collect();
        for w in &everyone {
            for peer in &everyone {
                if w.name != peer.name {
                    w.vox_env(
                        None,
                        &[("VOX_IDENTITY_PASSPHRASE", room::ID_PASS)],
                        &["trust", "add", &peer.b32(), "--name", &peer.name],
                        None,
                    )
                    .expect_ok("mutual trust before the room");
                }
            }
        }
        let first = &authors[0];
        let id = create(first);
        post(first, &id, "CA-0-seed-00", true);
        let link = first.vox(None, &["room", "link", &id]);
        link.expect_ok("author room link");
        for w in authors[1..].iter().chain([&removed]) {
            w.vox_in(
                None,
                &["room", "join", "--passphrase-file", "-", link.stdout.trim()],
                Some(room::ROOM_PASS),
            )
            .expect_ok("a member joins before the controls");
            returning_reader_ready(w, &id);
            await_shown(w, &id, "CA-0-seed-00");
        }
        let second = authors[1].b32();
        let removed_fp = removed.b32();
        let controls: [Vec<&str>; 5] = [
            vec!["room", "retention", &id, "--steps", "7d"],
            vec!["room", "admin", "add", &id, &second],
            vec!["room", "rename", &id, "repo-to-cve-ctl"],
            vec!["room", "remove-member", &id, &removed_fp],
            vec!["room", "retention", &id, "--steps", "2d"],
        ];
        for (n, control) in controls.iter().enumerate() {
            // The room answers this while an earlier change (a join, the control before) is
            // still being applied, and says to ask again once it is: staging waits for that.
            let staging = Instant::now();
            loop {
                let out = first.vox(None, control);
                if out.ok {
                    break;
                }
                assert!(
                    (out.stderr
                        .contains("a previous change to this room is still being applied")
                        || out.stderr.contains("try again once the room is ready"))
                        && staging.elapsed() < Duration::from_secs(240),
                    "APPARATUS: the first author's control {control:?} was refused: {out:?}"
                );
                std::thread::sleep(Duration::from_millis(500));
            }
            for (i, w) in authors.iter().enumerate() {
                for k in 1..=SEED {
                    if i == 0 || n == 0 {
                        post(w, &id, &format!("CA-{i}-seed-{n}{k}"), true);
                    }
                }
            }
        }
        for w in &authors[1..] {
            await_shown(w, &id, &format!("CA-0-seed-{}{SEED}", controls.len() - 1));
        }
        let joined = AtomicBool::new(false);
        let stop = AtomicBool::new(false);
        // Per author, every post it acknowledged, with whether it was offered after N's join.
        let acknowledged: Vec<Mutex<Vec<(String, bool)>>> =
            authors.iter().map(|_| Mutex::new(Vec::new())).collect();
        std::thread::scope(|scope| {
            // Every way out of this block stops the posters, a panic included: `scope` joins
            // every thread before it re-raises a panic, and they post until `stop`.
            struct StopOnExit<'a>(&'a AtomicBool);
            impl Drop for StopOnExit<'_> {
                fn drop(&mut self) {
                    self.0.store(true, Ordering::SeqCst);
                }
            }
            let _stop_on_exit = StopOnExit(&stop);
            let posters: Vec<_> = authors
                .iter()
                .zip(&acknowledged)
                .enumerate()
                .map(|(i, (w, acknowledged))| {
                    let (joined, stop) = (&joined, &stop);
                    let id = &id;
                    scope.spawn(move || {
                        for n in 1.. {
                            if stop.load(Ordering::SeqCst) {
                                return;
                            }
                            let after = joined.load(Ordering::SeqCst);
                            let text = format!("CA-{i}-live-{n:04}");
                            post(w, id, &text, false);
                            acknowledged
                                .lock()
                                .expect("APPARATUS: acknowledged posts")
                                .push((text, after));
                            std::thread::sleep(Duration::from_secs(1));
                        }
                    })
                })
                .collect();
            reader
                .vox_in(
                    None,
                    &["room", "join", "--passphrase-file", "-", link.stdout.trim()],
                    Some(room::ROOM_PASS),
                )
                .expect_ok("the newcomer joins");
            joined.store(true, Ordering::SeqCst);
            eprintln!("[controls] the newcomer's join returned; authors={authors_wanted}");
            let newcomer = scope.spawn(|| {
                for n in 1.. {
                    if stop.load(Ordering::SeqCst) {
                        return;
                    }
                    // Staging: the newcomer posts as n-new did; what it is answered is not
                    // this act's verdict.
                    let _ = reader.vox(None, &["room", "post", &id, &format!("CA-N-{n:04}")]);
                    std::thread::sleep(Duration::from_secs(1));
                }
            });
            let mut shown: Vec<Option<String>> = vec![None; authors.len()];
            let verdict = loop {
                let mut red = None;
                for (i, acknowledged) in acknowledged.iter().enumerate() {
                    if shown[i].is_some() {
                        continue;
                    }
                    let since: Vec<String> = acknowledged
                        .lock()
                        .expect("APPARATUS: acknowledged posts")
                        .iter()
                        .filter(|(_, after)| *after)
                        .map(|(text, _)| text.clone())
                        .collect();
                    let Some(marker) = since.first() else {
                        continue;
                    };
                    let seen = read(&reader, &id, Some(marker)).0;
                    if let Some(post) = since.iter().find(|text| seen.contains(*text)) {
                        shown[i] = Some(format!("{post} ({} since the join)", since.len()));
                    } else if since.len() >= BOUND {
                        red = Some(format!(
                            "RED PRODUCT: {} acknowledged {} posts since the newcomer's join and \
                             the newcomer shows none of them (marker {marker:?})",
                            authors[i].name,
                            since.len()
                        ));
                    }
                }
                if let Some(red) = red {
                    break Err(red);
                }
                if shown.iter().all(Option::is_some) {
                    break Ok(format!("the newcomer shows every author: {shown:?}"));
                }
                std::thread::sleep(Duration::from_secs(2));
            };
            stop.store(true, Ordering::SeqCst);
            for poster in posters {
                poster.join().expect("APPARATUS: a poster thread");
            }
            newcomer
                .join()
                .expect("APPARATUS: the newcomer's poster thread");
            if mutant
                && !std::fs::read_to_string(reader.data.with_extension("err"))
                    .unwrap_or_default()
                    .contains(&format!("vox: {MUTANT} engaged"))
            {
                panic!("APPARATUS: {MUTANT} was set but the newcomer never said it engaged");
            }
            match verdict {
                Ok(what) => eprintln!("[controls] GREEN authors={authors_wanted}: {what}"),
                Err(why) => panic!("{why}; authors={authors_wanted} mutant={mutant}"),
            }
        });
    }

    fn create(w: &Worker) -> String {
        let out = w.vox_in(
            None,
            &[
                "room",
                "create",
                "--name",
                "repo-to-cve",
                "--passphrase-file",
                "-",
            ],
            Some(room::ROOM_PASS),
        );
        assert!(out.ok, "APPARATUS: room not created: {out:?}");
        let out = w.vox(None, &["status", "--json"]);
        assert!(out.ok, "APPARATUS: created room not reported: {out:?}");
        out.json()["rooms"][0]["id"]
            .as_str()
            .expect("APPARATUS: created room id")
            .to_owned()
    }

    fn post(w: &Worker, id: &str, text: &str, staging: bool) {
        let mut out = w.vox(None, &["room", "post", id, text]);
        // Staging only: a post refused while the room's permissions are still being read
        // (the retryable REFRESHING, e.g. right after a removal) is asked again, as the
        // controls' staging asks again "a previous change … is still being applied".
        let staging_since = Instant::now();
        while staging
            && !out.ok
            && out.stderr.contains("try again once the room is ready")
            && staging_since.elapsed() < Duration::from_secs(240)
        {
            std::thread::sleep(Duration::from_millis(500));
            out = w.vox(None, &["room", "post", id, text]);
        }
        assert!(
            out.ok,
            "RED PRODUCT: {} did not acknowledge {text:?} (staging={staging}): {out:?}",
            w.name
        );
    }

    /// The footer is on stderr. Its cursor, not a guessed row count, drives every older read.
    /// `wanted=None` walks to the start for the final all-acknowledged-posts assertion.
    fn read(
        w: &Worker,
        id: &str,
        wanted: Option<&str>,
    ) -> (BTreeSet<String>, usize, Option<String>) {
        try_read(w, id, wanted, None).unwrap_or_else(|why| panic!("RED PRODUCT: {why}"))
    }

    fn check_observation_process(
        name: &str,
        command: &str,
        code: Option<i32>,
        stdout: &str,
        stderr: &str,
        state: Option<&Mutex<LoadState>>,
    ) -> Result<(), String> {
        if code.is_none()
            || (code != Some(0) && stdout.trim().is_empty() && stderr.trim().is_empty())
        {
            let why = format!(
                "{name}'s {command} process ended without a complete product answer \
                (exit={code:?}); stdout:\n{stdout}\nstderr:\n{stderr}"
            );
            if let Some(state) = state {
                state
                    .lock()
                    .expect("APPARATUS: load state")
                    .errors
                    .push(why.clone());
                return Err(why);
            }
            panic!("APPARATUS: {why}");
        }
        Ok(())
    }

    fn try_read(
        w: &Worker,
        id: &str,
        wanted: Option<&str>,
        state: Option<&Mutex<LoadState>>,
    ) -> Result<(BTreeSet<String>, usize, Option<String>), String> {
        let mut before = None::<String>;
        let mut cursors = BTreeSet::new();
        let mut texts = BTreeSet::new();
        let mut pages = 0;
        let mut oldest = None;
        loop {
            let mut args = vec!["room", "read", id, "--json", "--limit", "200"];
            if let Some(cursor) = before.as_deref() {
                args.extend(["--before", cursor]);
            }
            let out = w.vox(None, &args);
            check_observation_process(
                &w.name,
                "room read",
                out.code,
                &out.stdout,
                &out.stderr,
                state,
            )?;
            if !out.ok && super::room_changed_while_reading(&out.stderr) {
                // The room asked to refresh: the person reads again from the newest page.
                before = None;
                cursors.clear();
                texts.clear();
                pages = 0;
                oldest = None;
                continue;
            }
            if !out.ok {
                return Err(format!("{}'s paging reader refused: {out:?}", w.name));
            }
            pages += 1;
            let rows: Vec<Value> = out
                .stdout
                .lines()
                .filter(|line| !line.trim().is_empty())
                .map(serde_json::from_str)
                .collect::<Result<_, _>>()
                .map_err(|error| format!("{}'s page is not NDJSON: {error}; {out:?}", w.name))?;
            if let Some(hash) = rows.first().and_then(|row| row["entry_hash"].as_str()) {
                oldest = Some(hash.to_owned());
            }
            for row in rows {
                if let Some(text) = row["text"].as_str() {
                    texts.insert(text.to_owned());
                }
            }
            let next = out
                .stderr
                .lines()
                .find(|line| line.contains("older messages not shown:"))
                .map(|line| {
                    line.split_whitespace()
                        .collect::<Vec<_>>()
                        .windows(2)
                        .find(|pair| pair[0] == "--before")
                        .map(|pair| pair[1].trim_matches(['\'', '"']).to_owned())
                        .ok_or_else(|| format!("{}'s unpageable footer: {line}", w.name))
                })
                .transpose()?;
            eprintln!(
                "[RG-1 page] member={} page={pages} before={before:?} next={next:?}",
                w.name
            );
            if wanted.is_some_and(|text| texts.contains(text))
                || next.is_none()
                || std::env::var_os("VOX_PROOF_RG1_NO_PAGING").is_some()
            {
                return Ok((texts, pages, oldest));
            }
            let next = next.expect("footer checked");
            if !cursors.insert(next.clone()) {
                return Err(format!("{}'s paging reader repeated cursor {next}", w.name));
            }
            before = Some(next);
        }
    }

    /// Sampling records product answers, including refusals; it never decides the verdict.
    fn sample_read(w: &Worker, id: &str) {
        let mut before = None::<String>;
        let mut cursors = BTreeSet::new();
        for page in 1.. {
            let mut args = vec!["room", "read", id, "--json", "--limit", "200"];
            if let Some(cursor) = before.as_deref() {
                args.extend(["--before", cursor]);
            }
            let out = w.vox(None, &args);
            eprintln!(
                "[RG-1 sample page] member={} page={page} before={before:?} result={out:?}",
                w.name
            );
            if !out.ok {
                return;
            }
            let Some(footer) = out
                .stderr
                .lines()
                .find(|line| line.contains("older messages not shown:"))
            else {
                return;
            };
            let words: Vec<_> = footer.split_whitespace().collect();
            let next = words
                .windows(2)
                .find(|pair| pair[0] == "--before")
                .map(|pair| pair[1].trim_matches(['\'', '"']).to_owned());
            let Some(next) = next else {
                eprintln!(
                    "[RG-1 sample page] member={} unpageable footer={footer:?}",
                    w.name
                );
                return;
            };
            if !cursors.insert(next.clone()) {
                eprintln!(
                    "[RG-1 sample page] member={} repeated cursor={next}",
                    w.name
                );
                return;
            }
            before = Some(next);
        }
    }

    pub(super) fn paging_check() {
        let root = root();
        free_disk(root.path());
        let w = room::worker_as(root.path(), "paging", &binary());
        let _daemon = start(&w, "127.0.0.1:0", None);
        let id = create(&w);
        let started = Instant::now();
        for n in 0..5000 {
            post(&w, &id, &format!("RG1-paging-{n:04}"), true);
        }
        let (texts, pages, _) = read(&w, &id, Some("RG1-paging-0000"));
        let mutant = std::env::var_os("VOX_PROOF_RG1_NO_PAGING").is_some();
        assert!(
            texts.contains("RG1-paging-0000"),
            "RED {}: RG-1 paging self-check: first planted row absent after {pages} pages \
             of a 5,000-row room; paging mutant={mutant}",
            if mutant { "APPARATUS" } else { "PRODUCT" }
        );
        assert!(
            pages >= 25,
            "APPARATUS: 5,000-row staging did not require paging: {pages}"
        );
        eprintln!(
            "GREEN: RG-1 first of 5,000 rows found in {pages} pages; run={:?}; daemons=1",
            started.elapsed()
        );
    }

    /// A room/governance wait arranges the journey; its deadline never pronounces a product red.
    fn returning_reader_ready(w: &Worker, id: &str) {
        let started = Instant::now();
        loop {
            let listed = w.vox(None, &["room", "list"]);
            let open = listed.ok
                && listed.stdout.lines().any(|line| {
                    line.trim_start().starts_with(&id[..12]) && !line.contains("[preparing")
                });
            if open {
                let governance = w.vox(
                    None,
                    &["room", "read", id, "--json", "--notices", "--limit", "1"],
                );
                if governance.ok {
                    return;
                }
                assert!(
                    started.elapsed() < Duration::from_secs(240),
                    "APPARATUS: {} did not reach current room governance for staging: {governance:?}",
                    w.name
                );
            }
            assert!(
                started.elapsed() < Duration::from_secs(240),
                "APPARATUS: {} did not open its room for staging: {listed:?}",
                w.name
            );
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    pub(super) fn returning_reader() {
        const POSTS: usize = 8000;
        let root = root();
        // The mutant is the returned reader's alone: staging (the join and the first post)
        // runs unmutated, so `start` must not forward it; the restarted reader gets it by name.
        let mutant = std::env::var_os(PROMOTION_MUTANT).is_some();
        if mutant {
            super::test_knobs::require_in(&binary(), &[PROMOTION_MUTANT]);
            std::env::remove_var(PROMOTION_MUTANT);
        }
        free_disk(root.path());
        let exe = binary();
        let alice = room::worker_as(root.path(), "behind-author", &exe);
        let bob = room::worker_as(root.path(), "behind-reader", &exe);
        let _alice = start(&alice, "127.0.0.1:0", None);
        let bob_daemon = start(&bob, "127.0.0.1:0", None);
        for (w, peer) in [(&alice, &bob), (&bob, &alice)] {
            w.vox_env(
                None,
                &[("VOX_IDENTITY_PASSPHRASE", room::ID_PASS)],
                &["trust", "add", &peer.b32(), "--name", &peer.name],
                None,
            )
            .expect_ok("mutual trust before the room");
        }
        let id = create(&alice);
        let link = alice.vox(None, &["room", "link", &id]);
        link.expect_ok("returning-reader room link");
        bob.vox_in(
            None,
            &["room", "join", "--passphrase-file", "-", link.stdout.trim()],
            Some(room::ROOM_PASS),
        )
        .expect_ok("reader joins before going away");
        post(&alice, &id, "RG6-before-away", true);
        returning_reader_ready(&bob, &id);
        let staging = Instant::now();
        while !read(&bob, &id, Some("RG6-before-away"))
            .0
            .contains("RG6-before-away")
        {
            assert!(
                staging.elapsed() < Duration::from_secs(240),
                "APPARATUS: reader never showed the pre-away staging post"
            );
            std::thread::sleep(Duration::from_millis(100));
        }
        bob_daemon.stop();
        for n in 1..=POSTS {
            post(&alice, &id, &format!("RG6-away-{n:04}"), true);
        }
        eprintln!(
            "[RG-6] {POSTS} posts acknowledged while reader stopped; first return starts now"
        );
        let given = [(PROMOTION_MUTANT, std::path::PathBuf::from("1"))];
        let _bob = start_with(
            &bob,
            "127.0.0.1:0",
            None,
            if mutant { &given[..] } else { &[] },
        );
        returning_reader_ready(&bob, &id);
        let connecting = Instant::now();
        loop {
            let report = status(&bob, &id);
            if member(&report, &alice.b32()).is_some_and(|row| row["connected"] == true) {
                break;
            }
            assert!(
                connecting.elapsed() < Duration::from_secs(240),
                "APPARATUS: returning reader never reported its author connected: {report}"
            );
            std::thread::sleep(Duration::from_millis(100));
        }
        // What a person is promised (ADR-054 PL-3: a returning member owes itself everything
        // above its floor and fetches it unasked): the newest post shows first, before more than
        // two pages of the backlog, and every post it missed comes to show without any
        // `--history` request. Sampled by full paged reads, one a second; red only when the
        // shown count stops moving short of complete for `NO_PROGRESS_READS` answered reads.
        const NO_PROGRESS_READS: usize = 10;
        const NEWEST_WITHIN: usize = 2 * 128;
        let returned = Instant::now();
        let mut engaged = None::<String>;
        let mut best = 0usize;
        let mut still = 0usize;
        let mut newest_seen = false;
        for sample in 1.. {
            let (texts, pages, _) = read(&bob, &id, None);
            let shown_n = |n: &usize| texts.contains(&format!("RG6-away-{n:04}"));
            let shown = (1..=POSTS).filter(shown_n).count();
            let newest = shown_n(&POSTS);
            if mutant && engaged.is_none() {
                engaged = std::fs::read_to_string(bob.data.with_extension("err"))
                    .ok()
                    .and_then(|err| {
                        err.lines()
                            .find(|line| line.contains(&format!("{PROMOTION_MUTANT} engaged")))
                            .map(str::to_owned)
                    });
                if let Some(line) = &engaged {
                    eprintln!("[RG-6 mutant] reader daemon: {line}");
                }
            }
            eprintln!(
                "[RG-6] sample={sample} t={}ms returning reader shows {shown}/{POSTS}; newest \
                 shown={newest}; pages={pages}",
                returned.elapsed().as_millis()
            );
            if !newest_seen && !newest && shown > NEWEST_WITHIN {
                panic!(
                    "RED PRODUCT: the returning reader shows {shown} of the {POSTS} posts it \
                     missed but not the newest, RG6-away-{POSTS:04}: the newest must show before \
                     more than {NEWEST_WITHIN} of the backlog"
                );
            }
            newest_seen |= newest;
            if shown == POSTS {
                assert!(
                    pages > 1,
                    "APPARATUS: {POSTS} posts were read in one page; paging was not exercised"
                );
                eprintln!(
                    "GREEN: returning reader showed the newest post first and came to show all \
                     {POSTS} posts it missed, unasked, paging back through {pages} pages \
                     (sample {sample})"
                );
                break;
            }
            if shown > best {
                best = shown;
                still = 0;
            } else {
                still += 1;
            }
            if still >= NO_PROGRESS_READS {
                assert!(
                    !mutant || engaged.is_some(),
                    "APPARATUS: {PROMOTION_MUTANT} was set but the reader's daemon never said it \
                     engaged; see {}",
                    bob.data.with_extension("err").display()
                );
                let missing = super::missing_ranges(&(1..=POSTS).filter(shown_n).collect(), POSTS);
                panic!(
                    "RED PRODUCT: the returning reader's shown count stopped at {shown} of the \
                     {POSTS} posts it missed over {NO_PROGRESS_READS} answered reads (newest \
                     shown: {newest}); missing: {:?}",
                    &missing[..missing.len().min(8)]
                );
            }
            std::thread::sleep(Duration::from_secs(1));
        }
    }

    /// What the holder's posts cite in the stopped author's feed.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub(super) enum Cited {
        /// The author's long run of posts (ADR-052 RG-6).
        Posts,
        /// A control after them: the author's context advance over the holder's post, written
        /// before the author's next post; the holder posts again after showing it (MP-7).
        AfterControl,
    }

    /// The author's long feed is held sparsely by the holder, whose entries cite it. With the
    /// author stopped and the holder restarted (no in-memory proof survives), the newcomer's
    /// only source of the author's evidence is what the holder kept with its own receipts and,
    /// for `Cited::AfterControl`, with its control coverage.
    pub(super) fn holder_serves_what_it_verified(cited: Cited) {
        const POSTS: usize = 200;
        let root = root();
        let exe = binary();
        let author = room::worker_as(root.path(), "witness-author", &exe);
        let holder = room::worker_as(root.path(), "witness-holder", &exe);
        let reader = room::worker_as(root.path(), "witness-reader", &exe);
        let author_daemon = start(&author, "127.0.0.1:0", None);
        let holder_daemon = start(&holder, "127.0.0.1:0", None);
        let trust = |w: &Worker, peer: &Worker| {
            w.vox_env(
                None,
                &[("VOX_IDENTITY_PASSPHRASE", room::ID_PASS)],
                &["trust", "add", &peer.b32(), "--name", &peer.name],
                None,
            )
            .expect_ok("trust before the room");
        };
        trust(&author, &holder);
        trust(&holder, &author);
        let id = create(&author);
        for n in 1..=POSTS {
            post(&author, &id, &format!("WK-A-{n:04}"), true);
        }
        let link = author.vox(None, &["room", "link", &id]);
        link.expect_ok("author room link");
        holder
            .vox_in(
                None,
                &["room", "join", "--passphrase-file", "-", link.stdout.trim()],
                Some(room::ROOM_PASS),
            )
            .expect_ok("holder joins the author's long room");
        returning_reader_ready(&holder, &id);
        let last = format!("WK-A-{POSTS:04}");
        let staging = Instant::now();
        while !read(&holder, &id, Some(&last)).0.contains(&last) {
            assert!(
                staging.elapsed() < Duration::from_secs(600),
                "APPARATUS: holder never showed the author's newest post"
            );
            std::thread::sleep(Duration::from_millis(200));
        }
        let held = status(&holder, &id);
        eprintln!(
            "[witness] holder's view of the author before its own post: {}",
            member(&held, &author.b32()).cloned().unwrap_or(Value::Null)
        );
        post(&holder, &id, "WK-H-after-reading-A", true);
        if cited == Cited::AfterControl {
            // The author's context changes with the holder's post: its next post is preceded by
            // a context advance (a control entry) citing the holder.
            let staging = Instant::now();
            while !read(&author, &id, Some("WK-H-after-reading-A"))
                .0
                .contains("WK-H-after-reading-A")
            {
                assert!(
                    staging.elapsed() < Duration::from_secs(600),
                    "APPARATUS: the author never showed the holder's post"
                );
                std::thread::sleep(Duration::from_millis(200));
            }
            post(&author, &id, "WK-A-after-H", true);
            let staging = Instant::now();
            while !read(&holder, &id, Some("WK-A-after-H"))
                .0
                .contains("WK-A-after-H")
            {
                assert!(
                    staging.elapsed() < Duration::from_secs(600),
                    "APPARATUS: the holder never showed the author's post after its control"
                );
                std::thread::sleep(Duration::from_millis(200));
            }
            // The holder holds the author's whole window before the author stops, so what the
            // newcomer later lacks is evidence, not entries the holder never had.
            let staging = Instant::now();
            let view = loop {
                let row = member(&status(&holder, &id), &author.b32())
                    .cloned()
                    .unwrap_or(Value::Null);
                if row["missing_live_entries"] == 0
                    && row["holds_through"].as_u64().is_some()
                    && row["holds_through"] == row["advertised_through"]
                {
                    break row;
                }
                assert!(
                    staging.elapsed() < Duration::from_secs(600),
                    "APPARATUS: the holder never held the author's whole window: {row}"
                );
                std::thread::sleep(Duration::from_millis(500));
            };
            eprintln!("[witness] holder's view of the author after its control: {view}");
            post(&holder, &id, "WK-H-after-A-control", true);
        }
        author_daemon.stop();
        eprintln!("[witness] author stopped for the rest of the act");
        holder_daemon.stop();
        let _ = std::fs::copy(
            holder.data.with_extension("err"),
            holder.data.with_extension("first.err"),
        );
        let _holder_daemon = start(&holder, "127.0.0.1:0", None);
        returning_reader_ready(&holder, &id);
        eprintln!("[witness] holder restarted: no in-memory proof survives");
        let _reader_daemon = start(&reader, "127.0.0.1:0", None);
        trust(&holder, &reader);
        trust(&reader, &holder);
        let link = holder.vox(None, &["room", "link", &id]);
        link.expect_ok("holder room link");
        reader
            .vox_in(
                None,
                &["room", "join", "--passphrase-file", "-", link.stdout.trim()],
                Some(room::ROOM_PASS),
            )
            .expect_ok("newcomer joins through the holder");
        post(&holder, &id, "WK-H-after-the-newcomer", true);
        let wanted = "WK-H-after-the-newcomer";
        let started = Instant::now();
        loop {
            let page = reader.vox(None, &["room", "read", &id, "--json", "--limit", "200"]);
            let shown: BTreeSet<String> = if page.ok {
                page.ndjson()
                    .iter()
                    .filter_map(|row| row["text"].as_str().map(str::to_owned))
                    .collect()
            } else {
                BTreeSet::new()
            };
            let report = reader.vox(None, &["status", "--json"]);
            report.expect_ok("newcomer status");
            let report = report.json();
            let room = report["rooms"]
                .as_array()
                .and_then(|rows| rows.iter().find(|row| row["id"].as_str() == Some(&id)))
                .cloned()
                .unwrap_or(Value::Null);
            if shown.contains(wanted) {
                let row = member(&room, &holder.b32()).cloned().unwrap_or(Value::Null);
                eprintln!(
                    "[witness] newcomer shows {} of the author's posts and the holder's: \
                     before-the-newcomer={}, after={}; holder row: {row}",
                    shown.iter().filter(|t| t.starts_with("WK-A-")).count(),
                    shown.contains("WK-H-after-reading-A"),
                    shown.contains(wanted)
                );
                assert!(
                    row["trusted"] == true,
                    "RED PRODUCT: the newcomer shows the holder's post but does not report \
                     trusting it: {row}"
                );
                eprintln!(
                    "GREEN: with the author stopped and the holder restarted, the newcomer \
                     reads the holder's post"
                );
                return;
            }
            assert!(
                started.elapsed() < Duration::from_secs(900),
                "APPARATUS: NO RESULT after 900 s: neither the holder's post nor a wedge; \
                 shows {shown:?}; newcomer's room: {room}"
            );
            std::thread::sleep(Duration::from_millis(500));
        }
    }

    /// See [`super::a_member_whose_own_save_is_held_still_answers`]. Alice writes, Carol serves
    /// Bob only heads (`VOX_TEST_HEADS_ONLY_FILE`), so Bob's headers, inclusion proofs and
    /// bodies come from Alice alone; Alice's save of Carol's post is held
    /// (`VOX_TEST_HOLD_ROOM_WRITE`) from before Bob starts until after the verdict.
    pub(super) fn a_held_member_answers() {
        const BOUND: Duration = Duration::from_secs(20);
        let root = root();
        let exe = binary();
        crate::test_knobs::require_in(&exe, &["history receiver", "VOX_TEST_HEADS_ONLY_FILE"]);
        if std::env::var_os("VOX_MUTANT_SERVE_WAITS_ON_ROOM").is_some() {
            crate::test_knobs::require_in(&exe, &["VOX_MUTANT_SERVE_WAITS_ON_ROOM answered busy"]);
        }
        let alice = room::worker_as(root.path(), "held-alice", &exe);
        let carol = room::worker_as(root.path(), "held-carol", &exe);
        let bob = room::worker_as(root.path(), "held-bob", &exe);
        let hold = alice.data.with_extension("hold");
        let heads_only = carol.data.with_extension("heads-only");
        std::fs::write(&heads_only, bob.b32()).expect("APPARATUS: heads-only staging file");
        let _alice_daemon = start_with(
            &alice,
            "127.0.0.1:0",
            None,
            &[("VOX_TEST_HOLD_ROOM_WRITE", hold.clone())],
        );
        let _carol_daemon = start_with(
            &carol,
            "127.0.0.1:0",
            None,
            &[("VOX_TEST_HEADS_ONLY_FILE", heads_only.clone())],
        );
        let bob_daemon = start(&bob, "127.0.0.1:0", None);
        for (w, peers) in [
            (&alice, [&bob, &carol]),
            (&bob, [&alice, &carol]),
            (&carol, [&alice, &bob]),
        ] {
            for peer in peers {
                w.vox_env(
                    None,
                    &[("VOX_IDENTITY_PASSPHRASE", room::ID_PASS)],
                    &["trust", "add", &peer.b32(), "--name", &peer.name],
                    None,
                )
                .expect_ok("trust before the room");
            }
        }
        let id = create(&alice);
        let link = alice.vox(None, &["room", "link", &id]);
        link.expect_ok("alice room link");
        for w in [&bob, &carol] {
            w.vox_in(
                None,
                &["room", "join", "--passphrase-file", "-", link.stdout.trim()],
                Some(room::ROOM_PASS),
            )
            .expect_ok("join alice's room");
            returning_reader_ready(w, &id);
        }
        post(&alice, &id, "HELD-A-00", true);
        await_shown(&bob, &id, "HELD-A-00");
        await_shown(&carol, &id, "HELD-A-00");
        bob_daemon.stop();
        eprintln!("[held] bob stopped");
        for n in 1..=5 {
            post(&alice, &id, &format!("HELD-A-{n:02}"), true);
        }
        let wanted = "HELD-A-05";
        let room = vox_core::node::link::b32_decode(&id, "room").expect("APPARATUS: room id");
        std::fs::write(&hold, room).expect("APPARATUS: arm alice's receiver hold");
        post(&carol, &id, "HELD-C-01", true);
        let staging = Instant::now();
        while !hold.with_extension("engaged").exists() {
            assert!(
                staging.elapsed() < Duration::from_secs(120),
                "APPARATUS: alice's save of carol's post never engaged the hold"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
        eprintln!(
            "[held] alice's save is held: {}",
            std::fs::read_to_string(hold.with_extension("engaged")).unwrap_or_default()
        );
        let back = Instant::now();
        let _bob_daemon = start(&bob, "127.0.0.1:0", None);
        let shown = loop {
            if read(&bob, &id, Some(wanted)).0.contains(wanted) {
                break Some(back.elapsed());
            }
            if back.elapsed() > BOUND {
                break None;
            }
            std::thread::sleep(Duration::from_millis(250));
        };
        let still_held = hold.exists() && hold.with_extension("engaged").exists();
        let _ = std::fs::remove_file(&hold);
        eprintln!(
            "[held] bob showed {wanted:?} {shown:?} after starting; alice's save held throughout: \
             {still_held}; bob's status: {}",
            status(&bob, &id)
        );
        assert!(
            still_held,
            "APPARATUS: alice's held save was released before the verdict"
        );
        assert!(
            shown.is_some(),
            "RED PRODUCT: bob, back after alice posted, did not show {wanted:?} within {BOUND:?} \
             while alice's own save was held; carol serves bob only heads, so only alice could \
             answer him"
        );
    }

    /// See [`super::a_member_whose_room_cannot_save_answers_nobody_until_it_recovers`]. As in
    /// [`a_held_member_answers`], Carol serves Bob only heads, so Bob's headers, proofs and
    /// bodies come from Alice alone. Alice's room is poisoned (`VOX_TEST_POISON_ROOM_FILE`: as a
    /// failed write poisons it, and its storage recovery fails while the file names it) before
    /// Bob starts again; the file is removed once Alice has turned two of Bob's requests away.
    pub(super) fn a_poisoned_member_answers_nobody() {
        const MUTANT: &str = "VOX_MUTANT_POISON_KEEPS_SNAPSHOT";
        const STAGING: Duration = Duration::from_secs(120);
        const RECOVERED: Duration = Duration::from_secs(180);
        let root = root();
        let exe = binary();
        crate::test_knobs::require_in(
            &exe,
            &[
                "VOX_TEST_HEADS_ONLY_FILE",
                "VOX_TEST_POISON_ROOM_FILE",
                "to the actor: no snapshot",
            ],
        );
        if std::env::var_os(MUTANT).is_some() {
            crate::test_knobs::require_in(&exe, &["VOX_MUTANT_POISON_KEEPS_SNAPSHOT engaged"]);
        }
        let alice = room::worker_as(root.path(), "sick-alice", &exe);
        let carol = room::worker_as(root.path(), "sick-carol", &exe);
        let bob = room::worker_as(root.path(), "sick-bob", &exe);
        let poison = alice.data.with_extension("poison");
        let heads_only = carol.data.with_extension("heads-only");
        std::fs::write(&heads_only, bob.b32()).expect("APPARATUS: heads-only staging file");
        let _alice_daemon = start_with(
            &alice,
            "127.0.0.1:0",
            None,
            &[("VOX_TEST_POISON_ROOM_FILE", poison.clone())],
        );
        let _carol_daemon = start_with(
            &carol,
            "127.0.0.1:0",
            None,
            &[("VOX_TEST_HEADS_ONLY_FILE", heads_only.clone())],
        );
        let bob_daemon = start(&bob, "127.0.0.1:0", None);
        for (w, peers) in [
            (&alice, [&bob, &carol]),
            (&bob, [&alice, &carol]),
            (&carol, [&alice, &bob]),
        ] {
            for peer in peers {
                w.vox_env(
                    None,
                    &[("VOX_IDENTITY_PASSPHRASE", room::ID_PASS)],
                    &["trust", "add", &peer.b32(), "--name", &peer.name],
                    None,
                )
                .expect_ok("trust before the room");
            }
        }
        let id = create(&alice);
        let link = alice.vox(None, &["room", "link", &id]);
        link.expect_ok("alice room link");
        for w in [&bob, &carol] {
            w.vox_in(
                None,
                &["room", "join", "--passphrase-file", "-", link.stdout.trim()],
                Some(room::ROOM_PASS),
            )
            .expect_ok("join alice's room");
            returning_reader_ready(w, &id);
        }
        post(&alice, &id, "SICK-A-00", true);
        await_shown(&bob, &id, "SICK-A-00");
        await_shown(&carol, &id, "SICK-A-00");
        bob_daemon.stop();
        eprintln!("[sick] bob stopped");
        for n in 1..=5 {
            post(&alice, &id, &format!("SICK-A-{n:02}"), true);
        }
        await_shown(&carol, &id, "SICK-A-05");
        let wanted = "SICK-A-05";
        let alice_err = alice.data.with_extension("err");
        let log = || std::fs::read_to_string(&alice_err).unwrap_or_default();
        let unhealthy = || alice.vox(None, &["status", "--json"]).json()["unhealthy"].clone();
        std::fs::write(&poison, &id).expect("APPARATUS: name alice's room in the poison file");
        let engaged = format!("VOX_TEST_POISON_ROOM_FILE engaged: room {id} cannot save");
        let staging = Instant::now();
        while !log().contains(&engaged) {
            assert!(
                staging.elapsed() < STAGING,
                "APPARATUS: NO RESULT: alice's room was never poisoned; see {}",
                alice_err.display()
            );
            std::thread::sleep(Duration::from_millis(100));
        }
        eprintln!("[sick] alice's room cannot save: {}", unhealthy());
        let turned_away = format!(
            "history request peer={} to the actor: no snapshot",
            bob.b32()
        );
        let back = Instant::now();
        let _bob_daemon = start(&bob, "127.0.0.1:0", None);
        loop {
            if read(&bob, &id, Some(wanted)).0.contains(wanted) {
                panic!(
                    "RED PRODUCT: bob showed {wanted:?} {:?} after starting while alice's room \
                     could not save; carol serves bob only heads, so alice answered him from a \
                     poisoned room (alice unhealthy: {}; {MUTANT} engaged {} times)",
                    back.elapsed(),
                    unhealthy(),
                    log()
                        .matches("VOX_MUTANT_POISON_KEEPS_SNAPSHOT engaged")
                        .count()
                );
            }
            if log().matches(turned_away.as_str()).count() >= 2 {
                break;
            }
            assert!(
                back.elapsed() < STAGING,
                "APPARATUS: NO RESULT: in {STAGING:?} bob neither showed {wanted:?} nor asked \
                 alice twice while her room could not save; bob's status: {}",
                status(&bob, &id)
            );
            std::thread::sleep(Duration::from_millis(250));
        }
        assert!(
            !read(&bob, &id, Some(wanted)).0.contains(wanted),
            "RED PRODUCT: bob showed {wanted:?} after alice turned two of his requests away \
             while her room could not save"
        );
        eprintln!(
            "[sick] alice turned bob away twice {:?} after he started, her room still unable to \
             save ({}); bob does not show {wanted:?}",
            back.elapsed(),
            unhealthy()
        );
        std::fs::remove_file(&poison).expect("APPARATUS: let alice's room save again");
        let healed = Instant::now();
        let shown = loop {
            if read(&bob, &id, Some(wanted)).0.contains(wanted) {
                break Some(healed.elapsed());
            }
            if healed.elapsed() > RECOVERED {
                break None;
            }
            std::thread::sleep(Duration::from_millis(250));
        };
        eprintln!(
            "[sick] bob showed {wanted:?} {shown:?} after alice's room could save again; alice \
             unhealthy: {}; bob's status: {}",
            unhealthy(),
            status(&bob, &id)
        );
        assert!(
            shown.is_some(),
            "RED PRODUCT: once alice's room could save again, bob did not show {wanted:?} within \
             {RECOVERED:?}"
        );
        eprintln!(
            "GREEN: while alice's room could not save she answered bob nothing, and once it \
             recovered bob showed {wanted:?}"
        );
    }

    /// Ledger 91: a newcomer admitted while the author was stopped, whose inviter then stops, is
    /// known to the author as soon as it is back. See the test's doc.
    pub(super) fn a_returned_author_knows_the_newcomer() {
        const BOUND: Duration = Duration::from_secs(10);
        const WATCH: Duration = Duration::from_secs(90);
        let root = root();
        let exe = binary();
        let author = room::worker_as(root.path(), "news-author", &exe);
        let holder = room::worker_as(root.path(), "news-holder", &exe);
        let reader = room::worker_as(root.path(), "news-reader", &exe);
        // The author starts again at the same address the others hold for it.
        let author_at = {
            let socket = std::net::UdpSocket::bind("127.0.0.1:0")
                .expect("APPARATUS: a free address for the author");
            socket
                .local_addr()
                .expect("APPARATUS: the author's address")
                .to_string()
        };
        let author_daemon = start(&author, &author_at, None);
        let refuse = holder.data.with_extension("refuse-entries");
        let holder_daemon = start_with(
            &holder,
            "127.0.0.1:0",
            None,
            &[("VOX_TEST_REFUSE_ENTRIES_FILE", refuse.clone())],
        );
        let trust = |w: &Worker, peer: &Worker| {
            w.vox_env(
                None,
                &[("VOX_IDENTITY_PASSPHRASE", room::ID_PASS)],
                &["trust", "add", &peer.b32(), "--name", &peer.name],
                None,
            )
            .expect_ok("trust before the room");
        };
        trust(&author, &holder);
        trust(&holder, &author);
        trust(&author, &reader);
        let id = create(&author);
        let feed = || {
            status(&author, &id)["own_feed_through"]
                .as_u64()
                .expect("APPARATUS: the author's status has no own_feed_through")
        };
        let before_posts = feed();
        for n in 1..=30 {
            post(&author, &id, &format!("NW-A-{n:02}"), true);
        }
        // The holder answers the newcomer's asks for the bodies of the last twenty, so the
        // newcomer moves those asks to the stopped author's port (as in the slot act).
        std::fs::write(
            &refuse,
            format!("{} {} {}", reader.b32(), before_posts + 11, feed()),
        )
        .expect("APPARATUS: refuse-entries staging file");
        let link = author.vox(None, &["room", "link", &id]);
        link.expect_ok("author room link");
        holder
            .vox_in(
                None,
                &["room", "join", "--passphrase-file", "-", link.stdout.trim()],
                Some(room::ROOM_PASS),
            )
            .expect_ok("holder joins the author's room");
        returning_reader_ready(&holder, &id);
        await_shown(&holder, &id, "NW-A-30");
        author_daemon.stop();
        eprintln!("[news] author stopped");
        let _reader_daemon = start(&reader, "127.0.0.1:0", None);
        trust(&holder, &reader);
        trust(&reader, &holder);
        trust(&reader, &author);
        let link = holder.vox(None, &["room", "link", &id]);
        link.expect_ok("holder room link");
        reader
            .vox_in(
                None,
                &["room", "join", "--passphrase-file", "-", link.stdout.trim()],
                Some(room::ROOM_PASS),
            )
            .expect_ok("newcomer joins through the holder");
        post(&holder, &id, "NW-H-while-the-author-is-stopped", true);
        await_shown(&reader, &id, "NW-H-while-the-author-is-stopped");
        holder_daemon.stop();
        eprintln!("[news] holder stopped");
        let back = Instant::now();
        let _author_daemon = start(&author, &author_at, None);
        eprintln!(
            "[news] author started again at {author_at}, {:.2} s",
            back.elapsed().as_secs_f64()
        );
        let wanted = "NW-A-back";
        post(&author, &id, wanted, true);
        eprintln!(
            "[news] author posted {wanted:?} {:.2} s after it started",
            back.elapsed().as_secs_f64()
        );
        let newcomer = reader.b32();
        let known = loop {
            let listed = status(&author, &id)["members"]
                .as_array()
                .is_some_and(|members| members.iter().any(|m| m["id"] == newcomer.as_str()));
            if listed {
                break Some(back.elapsed());
            }
            if back.elapsed() > WATCH {
                break None;
            }
            std::thread::sleep(Duration::from_millis(250));
        };
        // Printed only: whether the newcomer showed the post (the pull-loop change's act).
        eprintln!("[news] the author listed the newcomer {known:?} after starting; the newcomer shows {wanted:?} now: {}", read(&reader, &id, Some(wanted)).0.contains(wanted));
        let Some(known) = known else {
            panic!(
                "RED PRODUCT: the returned author never listed the newcomer as a member within {WATCH:?}"
            );
        };
        assert!(
            known <= BOUND,
            "RED PRODUCT: the returned author listed the newcomer {known:?} after starting (bound {BOUND:?})"
        );
    }

    /// Wait (staging) until `w` shows `text` in room `id`.
    fn await_shown(w: &Worker, id: &str, text: &str) {
        let staging = Instant::now();
        while !read(w, id, Some(text)).0.contains(text) {
            assert!(
                staging.elapsed() < Duration::from_secs(600),
                "APPARATUS: {} never showed {text:?}",
                w.name
            );
            std::thread::sleep(Duration::from_millis(200));
        }
    }

    /// Who the holder is when the newcomer finally asks it (ADR-053 P acts).
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub(super) enum Provider {
        /// The availability act: an honest holder on the author's branch.
        Honest,
        /// A guard: a holder on the author's branch that corrupts one descriptor in every proof
        /// it serves under a head it never committed (`VOX_TEST_BAD_PREFIX_FILE` = `corrupt`).
        Corrupt,
        /// A guard: a holder on another fork of the author (the author's profile copied before
        /// it wrote the newcomer's head, writing other posts there) that answers under the
        /// newcomer's head with its own branch's prefix (`VOX_TEST_BAD_PREFIX_FILE` = `fork`).
        Forked,
        /// A guard: as `Corrupt`, but only the consistency proofs it serves under such a head
        /// (`VOX_TEST_BAD_PREFIX_FILE` = `corrupt-consistency`); inclusion stays honest.
        CorruptConsistency,
        /// A guard: as `Corrupt`, but only the control proofs (`corrupt-control`).
        CorruptControl,
    }

    /// Stop as APPARATUS (the `test_knobs::require` convention) unless the `vox` this act runs,
    /// `VOX_PROOF_SHIPPED_BINARY` included, reads every staging knob and requested mutant it
    /// needs and prints every line it counts.
    fn require_prefix_knobs(exe: &str, provider: Provider) {
        let mut knobs = vec![
            "VOX_TEST_HEADS_ONLY_FILE",
            "VOX_TEST_UNAVAILABLE_HEAD_FILE",
            "history head committed author=",
            "prefix resolved stage=",
        ];
        if provider != Provider::Honest {
            knobs.extend(["VOX_TEST_BAD_PREFIX_FILE", "bad prefix served mode="]);
        }
        if provider == Provider::Forked {
            // MP-9: the newcomer's stderr says when it asked for a fork a peer listed.
            knobs.push("fork_asked=");
        }
        if std::env::var_os("VOX_MUTANT_FORK").is_some() {
            knobs.push("VOX_MUTANT_FORK");
        }
        for (asked, read) in [
            ("VOX_MUTANT_ASKER_ROOT", "VOX_TEST_ASKER_ROOT_MUTANT"),
            ("VOX_MUTANT_PREFIX_GATE", "VOX_MUTANT_PREFIX_GATE"),
        ] {
            if std::env::var_os(asked).is_some() {
                knobs.push(read);
            }
        }
        crate::test_knobs::require_in(exe, &knobs);
    }

    /// ADR-053 P (moving-head ruling §5, the availability act). The newcomer N commits a head
    /// n of the author A that the holder H never committed: H commits A's head n0, delivers its
    /// key to N and posts at that view, then is held still while A writes on and N commits A's
    /// head n > n0 from A. A serves N only heads, consistency proofs and contexts, and H serves
    /// N nothing while staging (`VOX_TEST_HEADS_ONLY_FILE`), so N holds A's head and none of
    /// its evidence. H then commits a larger head of A from n0, skipping n. A stops; H restarts
    /// and refuses N its own newer head of A (`VOX_TEST_UNAVAILABLE_HEAD_FILE`), so N stays
    /// anchored on n. From H alone N must verify, under n, the author's grants and H's package
    /// and post (headers, inclusion, consistency, control coverage and the bodies they need),
    /// apply them and read H's post. H's own stderr names each stage it served under a head it
    /// never committed (`prefix resolved`): that is the assertion that H never committed n.
    ///
    /// The guards (`Provider::Corrupt`, `Provider::Forked`) stage the same newcomer and author
    /// against a bad holder. The newcomer must neither show nor apply anything it served, stay
    /// pending on the author under n (anchor unchanged, still needing the stopped author, with
    /// the holder answering it more bad proofs or its holder rounds completing), call nothing a
    /// fork, and read the same holder's honest post in a second room. Mutant:
    /// `VOX_MUTANT_ASKER_ROOT=1`, passed to the newcomer alone as `VOX_TEST_ASKER_ROOT_MUTANT`:
    /// its verifiers skip the root check.
    pub(super) fn holder_serves_a_prefix_it_never_committed(provider: Provider) {
        let root = root();
        let exe = binary();
        require_prefix_knobs(&exe, provider);
        let author = room::worker_as(root.path(), "prefix-author", &exe);
        let holder = room::worker_as(root.path(), "prefix-holder", &exe);
        let reader = room::worker_as(root.path(), "prefix-reader", &exe);
        let author_only = author.data.with_extension("heads-only");
        let holder_only = holder.data.with_extension("heads-only");
        let refuse_head = holder.data.with_extension("refuse-author-head");
        for file in [&author_only, &holder_only] {
            std::fs::write(file, reader.b32()).expect("APPARATUS: heads-only staging file");
        }
        let author_knobs = [("VOX_TEST_HEADS_ONLY_FILE", author_only.clone())];
        let bad_prefix = holder.data.with_extension("bad-prefix");
        let mut holder_knobs = vec![
            ("VOX_TEST_HEADS_ONLY_FILE", holder_only.clone()),
            ("VOX_TEST_UNAVAILABLE_HEAD_FILE", refuse_head.clone()),
            ("VOX_TEST_BAD_PREFIX_FILE", bad_prefix.clone()),
        ];
        // MP-9's holder-side mutant (`fork-unpropagated`): the holder alone reads it.
        if let Some(mutant) = std::env::var_os("VOX_MUTANT_FORK") {
            holder_knobs.push(("VOX_MUTANT_FORK", std::path::PathBuf::from(mutant)));
        }
        let reader_knobs: Vec<(&str, std::path::PathBuf)> =
            std::env::var_os("VOX_MUTANT_ASKER_ROOT")
                .map(|on| ("VOX_TEST_ASKER_ROOT_MUTANT", std::path::PathBuf::from(on)))
                .into_iter()
                .collect();
        let mut author_daemon = start_with(&author, "127.0.0.1:0", None, &author_knobs);
        let mut holder_daemon = start_with(&holder, "127.0.0.1:0", None, &holder_knobs);
        let reader_daemon = start_with(&reader, "127.0.0.1:0", None, &reader_knobs);
        let trust = |w: &Worker, peer: &Worker| {
            w.vox_env(
                None,
                &[("VOX_IDENTITY_PASSPHRASE", room::ID_PASS)],
                &["trust", "add", &peer.b32(), "--name", &peer.name],
                None,
            )
            .expect_ok("trust before the room");
        };
        for (w, peer) in [
            (&author, &holder),
            (&holder, &author),
            (&author, &reader),
            (&reader, &author),
            (&holder, &reader),
            (&reader, &holder),
        ] {
            trust(w, peer);
        }
        let id = create(&author);
        for n in 1..=6 {
            post(&author, &id, &format!("PX-A-{n:02}"), true);
        }
        let link = author.vox(None, &["room", "link", &id]);
        link.expect_ok("author room link");
        holder
            .vox_in(
                None,
                &["room", "join", "--passphrase-file", "-", link.stdout.trim()],
                Some(room::ROOM_PASS),
            )
            .expect_ok("holder joins the author's room");
        returning_reader_ready(&holder, &id);
        await_shown(&holder, &id, "PX-A-06");
        reader
            .vox_in(
                None,
                &["room", "join", "--passphrase-file", "-", link.stdout.trim()],
                Some(room::ROOM_PASS),
            )
            .expect_ok("newcomer joins through the author");
        // H verifies the author's grant for N, delivers its own key to N and posts at that view.
        let staging = Instant::now();
        loop {
            let row = member(&status(&holder, &id), &reader.b32()).cloned();
            if row
                .as_ref()
                .is_some_and(|row| row["key_delivery_pending"] == false)
            {
                break;
            }
            assert!(
                staging.elapsed() < Duration::from_secs(600),
                "APPARATUS: the holder never delivered its key to the newcomer: {row:?}"
            );
            std::thread::sleep(Duration::from_millis(500));
        }
        post(&holder, &id, "PX-H-for-the-newcomer", true);
        // Every head of the author a daemon committed, from its own test-knobs stderr lines.
        let committed = |w: &Worker, files: &[&str]| -> Vec<u64> {
            let needle = format!("history head committed author={} size=", author.b32());
            files
                .iter()
                .flat_map(|ext| {
                    std::fs::read_to_string(w.data.with_extension(ext))
                        .unwrap_or_default()
                        .lines()
                        .filter_map(|line| {
                            line.split(&needle)
                                .nth(1)?
                                .split_whitespace()
                                .next()?
                                .parse()
                                .ok()
                        })
                        .collect::<Vec<u64>>()
                })
                .collect()
        };
        let n0 = committed(&holder, &["err"]).into_iter().max();
        eprintln!(
            "[prefix] holder's view of the author when it posted: committed {n0:?}; {:?}",
            member(&status(&holder, &id), &author.b32())
        );
        assert!(
            n0.is_some(),
            "APPARATUS: the holder never committed a head of the author"
        );
        // H is held still. A now serves N headers and inclusion past its current size, so N
        // can commit A's next heads, and A writes on until N commits one that is not a power of
        // two: n, which H never sees.
        // The forked guard's base: A's profile as it stands now, before it writes n. H stops
        // outright there, so no socket buffer carries A's next posts to it.
        let fork_base = author.data.with_extension("fork-base");
        let profile_dirs =
            |w: &Worker| [w.data.clone(), w.cfg.clone(), w.data.with_extension("home")];
        if provider == Provider::Forked {
            signal(holder_daemon.0.id(), "-TERM");
            let _ = holder_daemon.0.wait();
            author_daemon.stop();
            std::fs::create_dir_all(&fork_base).expect("APPARATUS: fork base directory");
            for (at, dir) in profile_dirs(&author).iter().enumerate() {
                let out = Command::new("cp")
                    .arg("-Rp")
                    .arg(dir)
                    .arg(fork_base.join(at.to_string()))
                    .output()
                    .expect("APPARATUS: copy the author's profile");
                assert!(out.status.success(), "APPARATUS: copy {dir:?}: {out:?}");
            }
            author_daemon = start_with(&author, "127.0.0.1:0", None, &author_knobs);
        } else {
            signal(holder_daemon.0.id(), "-STOP");
        }
        let floor = committed(&reader, &["err"])
            .into_iter()
            .chain(n0)
            .chain(
                member(&status(&reader, &id), &author.b32())
                    .and_then(|row| row["advertised_through"].as_u64()),
            )
            .max()
            .unwrap_or(0)
            + 1;
        std::fs::write(&author_only, format!("{} {floor}", reader.b32()))
            .expect("APPARATUS: open the author's tip to the newcomer");
        let mut extra = 0;
        let n = loop {
            extra += 1;
            post(&author, &id, &format!("PX-A-skipped-{extra:02}"), true);
            let staging = Instant::now();
            let size = loop {
                if let Some(size) = committed(&reader, &["err"])
                    .into_iter()
                    .max()
                    .filter(|size| *size >= floor + extra - 1)
                {
                    break size;
                }
                assert!(
                    staging.elapsed() < Duration::from_secs(240),
                    "APPARATUS: the newcomer committed no head of the author at or past {floor} \
                     after {extra} posts; see {}",
                    reader.data.with_extension("err").display()
                );
                std::thread::sleep(Duration::from_millis(300));
            };
            if !size.is_power_of_two() {
                break size;
            }
        };
        reader_daemon.stop();
        let n = committed(&reader, &["err"]).into_iter().max().unwrap_or(n);
        eprintln!(
            "[prefix] the newcomer committed the author's head of size {n} (the holder is held \
             still at {n0:?}; the author's tip was opened to the newcomer from {floor})"
        );
        assert!(
            !n.is_power_of_two(),
            "APPARATUS: the newcomer's last head of the author has a power-of-two size {n}"
        );
        let holder_heads = if provider == Provider::Forked {
            // A stops for good. Its copy from before n, the same identity, writes other posts
            // from there: another fork of A, which only H, started again, reads.
            author_daemon.stop();
            let _ = std::fs::copy(
                author.data.with_extension("err"),
                author.data.with_extension("branch.err"),
            );
            let aside = author.data.with_extension("branch-aside");
            std::fs::create_dir_all(&aside).expect("APPARATUS: the author's branch aside");
            for (at, dir) in profile_dirs(&author).iter().enumerate() {
                std::fs::rename(dir, aside.join(at.to_string()))
                    .expect("APPARATUS: set the author's branch aside");
                std::fs::rename(fork_base.join(at.to_string()), dir)
                    .expect("APPARATUS: the author's fork base in place");
            }
            author_daemon = start_with(&author, "127.0.0.1:0", None, &[]);
            let _ = std::fs::copy(
                holder.data.with_extension("err"),
                holder.data.with_extension("staged.err"),
            );
            holder_daemon = start_with(&holder, "127.0.0.1:0", None, &holder_knobs);
            let mut forked = 0;
            loop {
                forked += 1;
                assert!(
                    forked <= 64,
                    "APPARATUS: the holder committed no head of the author's fork past {n}"
                );
                let text = format!("PX-A-fork-{forked:02}");
                post(&author, &id, &text, true);
                await_shown(&holder, &id, &text);
                if committed(&holder, &["err"])
                    .into_iter()
                    .any(|size| size > n)
                {
                    break;
                }
            }
            committed(&holder, &["staged.err", "err"])
        } else {
            // A writes on while H is still held, then H resumes: its next head of A is past n.
            post(&author, &id, "PX-A-after-1", true);
            post(&author, &id, "PX-A-after-2", true);
            signal(holder_daemon.0.id(), "-CONT");
            await_shown(&holder, &id, "PX-A-after-2");
            committed(&holder, &["err"])
        };
        eprintln!(
            "[prefix] holder committed the author's heads {holder_heads:?} (the newcomer's is \
             {n}); holder's view before the stop: {:?}",
            member(&status(&holder, &id), &author.b32())
        );
        // On the forked guard H's heads are of A's other branch: one of size n there is not
        // the newcomer's head (another root), so only a larger one is required.
        assert!(
            (provider == Provider::Forked || !holder_heads.contains(&n))
                && holder_heads.iter().any(|size| *size > n),
            "APPARATUS: the holder was to skip the newcomer's head {n} and commit a larger one: \
             {holder_heads:?}"
        );
        author_daemon.stop();
        eprintln!("[prefix] author stopped for the rest of the act");
        std::fs::remove_file(&holder_only).expect("APPARATUS: end the holder's staging refusal");
        std::fs::write(&refuse_head, format!("{} {}", author.b32(), reader.b32()))
            .expect("APPARATUS: the holder keeps its newer head of the author from N");
        match provider {
            Provider::Honest => {}
            Provider::Corrupt => std::fs::write(&bad_prefix, "corrupt")
                .expect("APPARATUS: the holder corrupts what it serves under n"),
            Provider::CorruptConsistency => std::fs::write(&bad_prefix, "corrupt-consistency")
                .expect("APPARATUS: the holder corrupts consistency proofs under n"),
            Provider::CorruptControl => std::fs::write(&bad_prefix, "corrupt-control")
                .expect("APPARATUS: the holder corrupts control proofs under n"),
            Provider::Forked => std::fs::write(&bad_prefix, "fork")
                .expect("APPARATUS: the forked holder answers under n anyway"),
        }
        holder_daemon.stop();
        let _ = std::fs::copy(
            holder.data.with_extension("err"),
            holder.data.with_extension("first.err"),
        );
        let _holder_daemon = start_with(&holder, "127.0.0.1:0", None, &holder_knobs);
        returning_reader_ready(&holder, &id);
        eprintln!("[prefix] holder restarted: no in-memory proof survives");
        let _reader_daemon = start_with(&reader, "127.0.0.1:0", None, &reader_knobs);
        if provider != Provider::Honest {
            return bad_holder_verdict(provider, &author, &holder, &reader, &id, n, &committed);
        }
        // Every serving stage the holder names (`prefix resolved stage=`): Header, the three
        // proof kinds, and Entry/Page bodies.
        const STAGES: [&str; 5] = ["header", "inclusion", "consistency", "control", "entry"];
        let wanted = "PX-H-for-the-newcomer";
        let resolved = |stage: &str| {
            let needle = format!(
                "prefix resolved stage={stage} author={} size={n} ",
                author.b32()
            );
            std::fs::read_to_string(holder.data.with_extension("err"))
                .unwrap_or_default()
                .lines()
                .filter(|line| line.contains(&needle))
                .count()
        };
        let started = Instant::now();
        loop {
            let page = reader.vox(None, &["room", "read", &id, "--json", "--limit", "200"]);
            let shown: BTreeSet<String> = if page.ok {
                page.ndjson()
                    .iter()
                    .filter_map(|row| row["text"].as_str().map(str::to_owned))
                    .collect()
            } else {
                BTreeSet::new()
            };
            let report = reader.vox(None, &["status", "--json"]);
            report.expect_ok("newcomer status");
            let report = report.json();
            let room = report["rooms"]
                .as_array()
                .and_then(|rows| rows.iter().find(|row| row["id"].as_str() == Some(&id)))
                .cloned()
                .unwrap_or(Value::Null);
            if shown.contains(wanted) {
                let row = member(&room, &holder.b32()).cloned().unwrap_or(Value::Null);
                let stages: BTreeMap<&str, usize> = STAGES
                    .into_iter()
                    .map(|stage| (stage, resolved(stage)))
                    .collect();
                eprintln!(
                    "[prefix] newcomer shows {shown:?}; holder row: {row}; author row: {}; the \
                     holder served under the author's head of size {n} it never committed: \
                     {stages:?}",
                    member(&room, &author.b32()).cloned().unwrap_or(Value::Null)
                );
                assert!(
                    row["trusted"] == true,
                    "RED PRODUCT: the newcomer shows the holder's post but does not report \
                     trusting it: {row}"
                );
                let holder_heads = committed(&holder, &["first.err", "err"]);
                assert!(
                    !holder_heads.contains(&n),
                    "APPARATUS: the holder committed the newcomer's head {n} after all: \
                     {holder_heads:?}"
                );
                assert!(
                    stages.values().all(|count| *count > 0),
                    "APPARATUS: the newcomer read the holder's post, but this staging did not make \
                     the holder serve every stage ({STAGES:?}) under the author's head \
                     of size {n}: {stages:?}; see {}",
                    holder.data.with_extension("err").display()
                );
                eprintln!(
                    "GREEN: with the author stopped, the newcomer anchored on the author's head \
                     of size {n}, which the holder never committed, reads the holder's post \
                     from the holder alone"
                );
                return;
            }
            assert!(
                started.elapsed() < Duration::from_secs(900),
                "APPARATUS: NO RESULT after 900 s: neither the holder's post nor a wedge; \
                 shows {shown:?}; newcomer's room: {room}"
            );
            std::thread::sleep(Duration::from_millis(500));
        }
    }

    /// The P guards' verdict (`Provider::Corrupt`, `Provider::Forked`), with the bad holder and
    /// the newcomer N, anchored on the author's head n, running and the author stopped. Every
    /// post in the author's room cites the author's grants, so all of them wait on the same
    /// prefix of the author; the unrelated sender is the same holder in a second room it makes
    /// now, whose key it delivers to N. RED if N shows anything in the author's room, calls the
    /// author's history a fork other than through a listed fork proof (`Provider::Forked`: the
    /// author really signed two histories, ADR-053 MP-9), or commits another head of the author.
    /// GREEN when, in three status answers in a row, N still needs the stopped author while the
    /// holder has answered it bad proofs under n and keeps answering (or N's holder rounds keep
    /// completing), N reads the holder's post in the second room, and (`Provider::Forked`) N has
    /// recorded the author's fork through that proof.
    fn bad_holder_verdict(
        provider: Provider,
        author: &Worker,
        holder: &Worker,
        reader: &Worker,
        id: &str,
        n: u64,
        committed: &dyn Fn(&Worker, &[&str]) -> Vec<u64>,
    ) {
        let ids = |w: &Worker| -> BTreeSet<String> {
            let out = w.vox(None, &["status", "--json"]);
            out.expect_ok("room ids");
            out.json()["rooms"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|row| row["id"].as_str().map(str::to_owned))
                .collect()
        };
        let before = ids(holder);
        holder
            .vox_in(
                None,
                &[
                    "room",
                    "create",
                    "--name",
                    "unrelated",
                    "--passphrase-file",
                    "-",
                ],
                Some(room::ROOM_PASS),
            )
            .expect_ok("the holder makes a second room");
        let second = ids(holder)
            .difference(&before)
            .next()
            .cloned()
            .expect("APPARATUS: the holder's second room");
        let link = holder.vox(None, &["room", "link", &second]);
        link.expect_ok("second room link");
        reader
            .vox_in(
                None,
                &["room", "join", "--passphrase-file", "-", link.stdout.trim()],
                Some(room::ROOM_PASS),
            )
            .expect_ok("the newcomer joins the holder's second room");
        let staging = Instant::now();
        loop {
            let row = member(&status(holder, &second), &reader.b32()).cloned();
            if row
                .as_ref()
                .is_some_and(|row| row["key_delivery_pending"] == false)
            {
                break;
            }
            assert!(
                staging.elapsed() < Duration::from_secs(600),
                "APPARATUS: the holder never delivered its second room's key to the newcomer: \
                 {row:?}"
            );
            std::thread::sleep(Duration::from_millis(500));
        }
        let unrelated = "UR-H-unrelated";
        post(holder, &second, unrelated, true);
        // The holder's own count of what it served badly under n, per proof kind or stage.
        let bad = || -> BTreeMap<String, usize> {
            let size = format!(" size={n}");
            let mut served = BTreeMap::new();
            for line in std::fs::read_to_string(holder.data.with_extension("err"))
                .unwrap_or_default()
                .lines()
                .filter(|line| line.ends_with(&size))
            {
                if let Some(rest) = line.split("vox: bad prefix served ").nth(1) {
                    let what = rest
                        .split_whitespace()
                        .take(2)
                        .collect::<Vec<_>>()
                        .join(" ");
                    *served.entry(what).or_default() += 1;
                }
            }
            served
        };
        let texts = |room: &str| -> BTreeSet<String> {
            let page = reader.vox(None, &["room", "read", room, "--json", "--limit", "200"]);
            if !page.ok {
                return BTreeSet::new();
            }
            page.ndjson()
                .iter()
                .filter_map(|row| row["text"].as_str().map(str::to_owned))
                .collect()
        };
        let started = Instant::now();
        // In the Forked scene no mutant reaches the show claim (the fork proof freezes the author
        // first): it is observed and printed, not asserted; the corrupting-holder act proves it.
        let mut forked_shown: Option<BTreeSet<String>> = None;
        loop {
            let shown = texts(id);
            let served = bad();
            if provider == Provider::Forked {
                if !shown.is_empty() && forked_shown.is_none() {
                    eprintln!(
                        "[prefix] observed: the newcomer shows {shown:?} in the author's room, \
                         which only the Forked holder could have served under the author's head \
                         of size {n}; the holder's bad answers under {n}: {served:?}"
                    );
                    forked_shown = Some(shown);
                }
            } else {
                assert!(
                    shown.is_empty(),
                    "RED PRODUCT: the newcomer shows {shown:?} in the author's room, which only \
                     the {provider:?} holder could have served under the author's head of size \
                     {n}; the holder's bad answers under {n}: {served:?}"
                );
            }
            let report = reader.vox(None, &["status", "--json"]);
            report.expect_ok("newcomer status");
            let report = report.json();
            let forks: Vec<Value> = report["equivocations"]
                .as_array()
                .into_iter()
                .flatten()
                .filter(|fork| fork["room"].as_str() == Some(id))
                .cloned()
                .collect();
            // Compare the visible fork and frozen-author status on the two nodes.
            let (asked, held, frozen) = if provider == Provider::Forked && !forks.is_empty() {
                let asked = std::fs::read_to_string(reader.data.with_extension("err"))
                    .unwrap_or_default()
                    .lines()
                    .any(|line| {
                        line.contains("history inventory listed forks=")
                            && line.contains("fork_asked=true")
                    });
                let holder_report = holder.vox(None, &["status", "--json"]);
                holder_report.expect_ok("holder status");
                let held: Vec<Value> = holder_report.json()["equivocations"]
                    .as_array()
                    .cloned()
                    .unwrap_or_default();
                let frozen = report["rooms"]
                    .as_array()
                    .and_then(|rows| rows.iter().find(|row| row["id"].as_str() == Some(id)))
                    .and_then(|row| row["frozen"].as_array())
                    .is_some_and(|frozen| {
                        frozen
                            .iter()
                            .any(|member| member.as_str() == Some(&author.b32()))
                    });
                (asked, held, frozen)
            } else {
                (false, Vec::new(), false)
            };
            let proven = frozen
                && forks.iter().all(|fork| {
                    fork["author"].as_str() == Some(&author.b32())
                        && fork["position"].as_u64().is_some_and(|at| at <= n)
                        && held.contains(fork)
                });
            assert!(
                forks.is_empty() || proven,
                "RED PRODUCT: the newcomer calls a fork from the {provider:?} holder's answers: \
                 {forks:?}, inconsistent with the holder's forks {held:?} or the author frozen \
                 in the newcomer's room ({frozen}); bad answers under {n}: {served:?}"
            );
            let anchors = committed(reader, &["err"]);
            eprintln!("[prefix] newcomer's committed author heads: {anchors:?}");
            let room = report["rooms"]
                .as_array()
                .and_then(|rows| rows.iter().find(|row| row["id"].as_str() == Some(id)))
                .cloned()
                .unwrap_or(Value::Null);
            let unrelated_shown = texts(&second).contains(unrelated);
            if unrelated_shown && (provider != Provider::Forked || proven) {
                eprintln!("[prefix] listed fork requested: {asked}");
                eprintln!("[prefix] the {provider:?} holder's bad answers under head {n}: {served:?}; second room shows {unrelated:?}");
                let forks_said = if provider == Provider::Forked {
                    format!(
                        "records the author's fork {forks:?} only through the holder's listed \
                         proof (two signed entries of the author)"
                    )
                } else {
                    "calls nothing a fork".to_owned()
                };
                if provider == Provider::Forked {
                    match &forked_shown {
                        None => eprintln!(
                            "[prefix] observed: nothing of the forked holder's branch was shown"
                        ),
                        Some(shown) => eprintln!(
                            "[prefix] observed: the newcomer showed {shown:?} from the forked \
                             holder's branch"
                        ),
                    }
                    eprintln!(
                        "GREEN: the newcomer anchored on the author's head of size {n} \
                         {forks_said}, keeps its anchor and still needs the stopped author, and \
                         reads the same holder's post in another room"
                    );
                } else {
                    eprintln!(
                        "GREEN: the newcomer anchored on the author's head of size {n} shows \
                         nothing the {provider:?} holder served under it, {forks_said}, keeps its \
                         anchor and still needs the stopped author, and reads the same holder's \
                         post in another room"
                    );
                }
                return;
            }
            assert!(
                started.elapsed() < Duration::from_secs(900),
                "APPARATUS: NO RESULT after 900 s: holder answers {served:?}; second room read {unrelated_shown}; newcomer's room: {room}"
            );
            std::thread::sleep(Duration::from_millis(500));
        }
    }

    /// The prototype's OMP Session stand-in, with the same watcher ownership and bridge events.
    struct Session {
        process: Daemon,
        lines: std::sync::mpsc::Receiver<String>,
        id: String,
        scratch: tempfile::TempDir,
    }

    impl Session {
        fn ask(&mut self, command: &str) {
            writeln!(
                self.process
                    .0
                    .stdin
                    .as_mut()
                    .expect("APPARATUS: Session stdin"),
                "{command}"
            )
            .expect("APPARATUS: write Session command");
            let line = self
                .lines
                .recv_timeout(Duration::from_secs(180))
                .unwrap_or_else(|e| panic!("APPARATUS: Session did not answer {command}: {e}"));
            let reply: Value = serde_json::from_str(&line)
                .unwrap_or_else(|e| panic!("APPARATUS: Session reply {line}: {e}"));
            assert_ne!(
                reply["kind"], "apparatus",
                "APPARATUS: Session staging: {reply}"
            );
        }

        fn start(w: &Worker, id: &str, index: usize) -> Self {
            // This is the Sess wire conversation in arm-replace/rig.py:378-512, not a model.
            const HOST: &str = r#"
import atexit,json,os,secrets,socket,subprocess,sys,threading,time
sid=sys.argv[1]; route=secrets.token_hex(32); token=secrets.token_hex(32)
endpoint=os.path.join(os.environ["TMPDIR"],"bridge")
assert len(os.fsencode(endpoint)) < 104, "Session socket path exceeds Unix socket limit"
listener=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); listener.bind(endpoint)
os.chmod(endpoint,0o600); listener.listen(8)
state={"ready":False,"confirmed":False}; conns=[]; frames=[]; cv=threading.Condition()
def serve(sock):
    try:
        reader=sock.makefile("rb")
        auth=json.loads(reader.readline()); first=json.loads(reader.readline())
        assert auth.get("type")=="auth" and auth.get("token")==token
        if first.get("type")=="route":
            sock.sendall((json.dumps({"outcome":"available","session":sid,"route":route,"client":route,"admission":True})+"\n").encode()); return
        assert first.get("type")=="subscribe" and first.get("session")==sid
        deadline=time.monotonic()+30
        while not (state["ready"] and state["confirmed"]) and time.monotonic()<deadline: time.sleep(.1)
        assert state["ready"] and state["confirmed"]
        sock.sendall((json.dumps({"type":"subscribed","session":sid})+"\n"+json.dumps({"type":"event","event":{"type":"state","busy":False}})+"\n").encode())
        conns.append(sock)
        for _ in reader: pass
    except Exception as e: print("bridge: "+repr(e),file=sys.stderr,flush=True)
def accept():
    while True:
        sock,_=listener.accept(); threading.Thread(target=serve,args=(sock,),daemon=True).start()
threading.Thread(target=accept,daemon=True).start()
watch=subprocess.Popen([os.environ["VOX_BIN"],"agent","omp-watch","--node",os.environ["VOX_NODE"]],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=sys.stderr)
def cleanup():
    if watch.poll() is None: watch.kill()
    watch.wait()
atexit.register(cleanup)
def receive():
    for line in watch.stdout:
        f=json.loads(line)
        if f.get("type")=="ready": state["ready"]=True
        if f.get("type")=="unavailable": state.update(ready=False,confirmed=False)
        with cv: frames.append(f); cv.notify_all()
threading.Thread(target=receive,daemon=True).start()
def frame(match,within=120):
    deadline=time.monotonic()+within
    with cv:
        while True:
            for f in frames:
                if match(f): return f
            remaining=deadline-time.monotonic()
            if remaining<=0: raise RuntimeError("no watcher frame: "+repr(frames[-5:]))
            cv.wait(remaining)
def command(i,**args):
    watch.stdin.write((json.dumps(dict(id=i,**args))+"\n").encode()); watch.stdin.flush()
    assert frame(lambda f:f.get("type")=="ack" and f.get("id")==i)["ok"]
try:
    instance=frame(lambda f:f.get("type")=="owner")["instance"]
    frame(lambda f:f.get("type")=="ready"); generation=secrets.token_hex(32)
    command("1",op="revoke")
    command("2",op="install",generation=generation,session=sid,endpoint=endpoint,token=token,route=route)
    env=dict(os.environ,VOX_HARNESS="omp",VOX_SESSION=sid,VOX_OPENCODE_WAKE_SOCKET=endpoint,VOX_OPENCODE_WAKE_TOKEN=token,
        VOX_OPENCODE_MIRROR_SOCKET=endpoint,VOX_OPENCODE_ATTENTION_SOCKET=endpoint,VOX_OPENCODE_ATTENTION_TOKEN=token,
        VOX_OPENCODE_ATTENTION_ROUTE=route,VOX_OMP_INSTANCE=instance,VOX_OMP_GENERATION=generation)
    for option,extra in (("--attention-register",[]),("--omp-check-uncertainty",[]),("--omp-prepare",["--format","opencode"])):
        p=subprocess.run([os.environ["VOX_BIN"],"agent","hook","--node",os.environ["VOX_NODE"],"--session",sid,*extra,option],
            env=env,input="commit\n" if option=="--omp-prepare" else "",text=True,capture_output=True)
        print(sid+" "+option+" rc="+str(p.returncode)+" "+p.stderr,file=sys.stderr,flush=True)
        if option=="--omp-prepare": continue
        assert p.returncode==0,(option,p.stdout,p.stderr)
        if option=="--omp-check-uncertainty": state["confirmed"]=True
    deadline=time.monotonic()+30
    while not conns and time.monotonic()<deadline: time.sleep(.1)
    assert conns,"no subscribed bridge"
    for line in sys.stdin:
        try:
            if line.strip()=="register": pass
            else:
                k=int(line); assert conns and watch.poll() is None
                text=sid+" step "+str(k)+" "+"y"*400
                conns[-1].sendall((json.dumps({"type":"event","event":{"type":"user" if k%2==0 else "reply","text":text}})+"\n").encode())
            print(json.dumps({"session":sid}),flush=True)
        except Exception as e: print(json.dumps({"kind":"apparatus","error":repr(e)}),flush=True)
except Exception as e: print(json.dumps({"kind":"apparatus","error":repr(e)}),flush=True)
"#;
            use std::os::unix::process::CommandExt as _;
            let scratch = tempfile::Builder::new()
                .prefix("rg1-omp-")
                .tempdir_in("/tmp")
                .expect("APPARATUS: short Session scratch");
            assert!(
                scratch
                    .path()
                    .join("bridge")
                    .as_os_str()
                    .as_encoded_bytes()
                    .len()
                    < 104,
                "APPARATUS: Session socket path exceeds Unix socket limit"
            );
            let session_id = format!("trial-session-{index:04}");
            let mut cmd = Command::new("python3");
            room::strip_harness_env(&mut cmd);
            cmd.process_group(0);
            let mut child = cmd
                .args(["-u", "-c", HOST, &session_id])
                .env("HOME", w.data.with_extension("home"))
                .env("TMPDIR", scratch.path())
                .env("VOX_BIN", &w.exe)
                .env("VOX_NODE", &w.name)
                .env("VOX_DATA_DIR", &w.data)
                .env("VOX_CONFIG_DIR", &w.cfg)
                .env("VOX_ROOM", id)
                .env("VOX_PROXY", "127.0.0.1:0")
                .env("VOX_LISTEN", "127.0.0.1:0")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::from(
                    std::fs::File::create(w.data.with_extension(format!("session-{index}.err")))
                        .expect("APPARATUS: Session stderr"),
                ))
                .spawn()
                .expect("APPARATUS: start OMP Session stand-in");
            let stdout = child.stdout.take().expect("APPARATUS: Session stdout");
            let (tx, lines) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                    if tx.send(line).is_err() {
                        break;
                    }
                }
            });
            let mut session = Self {
                process: Daemon(child),
                lines,
                id: session_id,
                scratch,
            };
            session.ask("register");
            session
        }

        fn step(&mut self, n: usize) -> String {
            self.ask(&n.to_string());
            // `room session` abbreviates long bodies, but retains this event identity.
            format!("{} step {n} ", self.id)
        }
    }

    impl Drop for Session {
        fn drop(&mut self) {
            // EOF lets the stand-in reap the omp-watch process it owns.
            drop(self.process.0.stdin.take());
            let started = Instant::now();
            loop {
                match self.process.0.try_wait() {
                    Ok(Some(_)) => break,
                    Ok(None) if started.elapsed() < Duration::from_secs(10) => {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    _ => {
                        // The unreaped owned child reserves this private group: stand-in + watcher.
                        let _ = Command::new("/bin/bash")
                            .args([
                                "-c",
                                "kill -KILL -- \"-$1\"",
                                "rg1",
                                &self.process.0.id().to_string(),
                            ])
                            .status();
                        let _ = self.process.0.kill();
                        break;
                    }
                }
            }
            let _ = self.process.0.wait();
            let _ = std::fs::remove_file(self.scratch.path().join("bridge"));
        }
    }

    struct PostRefusal {
        number: u64,
        at: Instant,
        words: String,
    }

    #[derive(Default)]
    struct LoadState {
        // The immutable flag belongs to the offer, even if a pre-join command answers later.
        acknowledged: BTreeMap<String, Vec<(String, bool)>>,
        errors: Vec<String>,
        refused_posts: BTreeMap<String, Vec<PostRefusal>>,
        refused_joins: Vec<String>,
        refused_commands: Vec<String>,
        newcomer_create_started: Option<Instant>,
        offered: BTreeMap<String, Vec<u128>>,
        joined: bool,
        steps: BTreeMap<String, usize>,
        // Per member, every other member its own `vox agent doctor --room` has said, about this
        // room, that it trusts ("you trust …").
        trust_seen: BTreeMap<String, BTreeSet<String>>,
        // Per acknowledged post, the members its author's room doctor said it trusts before the
        // post was offered: consent is forward-only (ADR-006 S-18), so a member trusted after
        // the room's first post is owed only what its author wrote after trusting it.
        trusted_at_offer: BTreeMap<String, BTreeSet<String>>,
    }

    fn record_refused_post(
        state: &mut LoadState,
        author: &str,
        number: u64,
        at: Instant,
        code: Option<i32>,
        stdout: &str,
        stderr: &str,
    ) {
        let words = format!("stdout:\n{stdout}\nstderr:\n{stderr}");
        if code.is_none() || (stdout.trim().is_empty() && stderr.trim().is_empty()) {
            state.errors.push(format!(
                "author {author} post {number} ended without a product refusal (exit={code:?}); {words}"
            ));
        } else {
            eprintln!("RED PRODUCT: author {author} post {number} refused; {words}");
            state
                .refused_posts
                .entry(author.to_owned())
                .or_default()
                .push(PostRefusal { number, at, words });
        }
    }

    fn refusal_summary(state: &Mutex<LoadState>) -> String {
        let state = state.lock().expect("APPARATUS: load state");
        let posts: usize = state.refused_posts.values().map(Vec::len).sum();
        if state.refused_joins.is_empty() && posts == 0 && state.refused_commands.is_empty() {
            return "no product refusals recorded".to_owned();
        }
        format!(
            "also RED PRODUCT already recorded: refused {} joins {:?}; {posts} posts; {} commands",
            state.refused_joins.len(),
            state.refused_joins,
            state.refused_commands.len()
        )
    }

    struct Load {
        stop: Arc<AtomicBool>,
        threads: Vec<std::thread::JoinHandle<()>>,
    }

    impl Load {
        fn finish(&mut self) -> bool {
            self.stop.store(true, Ordering::SeqCst);
            let mut healthy = true;
            for thread in self.threads.drain(..) {
                healthy &= thread.join().is_ok();
            }
            healthy
        }
    }

    impl Drop for Load {
        fn drop(&mut self) {
            let _ = self.finish();
        }
    }

    fn sleep(stop: &AtomicBool, duration: Duration) {
        let started = Instant::now();
        while !stop.load(Ordering::SeqCst) && started.elapsed() < duration {
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn report_post_refusals(state: &Mutex<LoadState>) -> usize {
        let state = state.lock().expect("APPARATUS: load state");
        let mut count = 0;
        for (author, refusals) in &state.refused_posts {
            count += refusals.len();
            if let Some(first) = refusals.iter().min_by_key(|refusal| refusal.at) {
                let since_create_ms = state.newcomer_create_started.map(|created| {
                    first.at.checked_duration_since(created).map_or_else(
                        || -(created.duration_since(first.at).as_millis() as i128),
                        |after| after.as_millis() as i128,
                    )
                });
                eprintln!("RED PRODUCT: author {author}: {} posts refused; first_post={} \
                    first_refusal_ms_from_newcomer_create_start={since_create_ms:?}; product words:\n{}",
                    refusals.len(), first.number, first.words);
            }
            for refusal in refusals {
                eprintln!(
                    "[RG-1 refused post] author={author} post={} product words:\n{}",
                    refusal.number, refusal.words
                );
            }
        }
        count
    }

    fn report_command_refusals(state: &Mutex<LoadState>) -> usize {
        let state = state.lock().expect("APPARATUS: load state");
        for refusal in &state.refused_commands {
            eprintln!("RED PRODUCT: {refusal}");
        }
        state.refused_commands.len()
    }

    fn check_errors(state: &Mutex<LoadState>, staging: bool) {
        let errors = std::mem::take(&mut state.lock().expect("APPARATUS: load state").errors);
        assert!(
            errors.is_empty(),
            "RED APPARATUS: posting processes failed (staging={staging}): {errors:?}; {}",
            refusal_summary(state)
        );
    }

    fn check_load(load: &Load, state: &Mutex<LoadState>, staging: bool) {
        check_errors(state, staging);
        assert!(
            load.threads.iter().all(|thread| !thread.is_finished()),
            "APPARATUS: a posting or Session thread stopped; {}",
            refusal_summary(state)
        );
        check_cadence(state);
    }

    fn check_cadence(state: &Mutex<LoadState>) {
        let bad = {
            let state = state.lock().expect("APPARATUS: load state");
            state
                .offered
                .iter()
                .find(|(_, times)| {
                    times
                        .windows(2)
                        .any(|pair| !(750..=1250).contains(&(pair[1] - pair[0])))
                })
                .map(|(author, times)| (author.clone(), times.clone()))
        };
        assert!(
            bad.is_none(),
            "APPARATUS: offered cadence was not one second: {bad:?}; {}",
            refusal_summary(state)
        );
    }

    fn post_count(state: &LoadState, author: &str) -> usize {
        state
            .acknowledged
            .get(author)
            .into_iter()
            .flatten()
            .filter(|(_, after_join)| *after_join)
            .count()
    }

    fn poster(
        w: Arc<Worker>,
        id: String,
        state: Arc<Mutex<LoadState>>,
        stop: Arc<AtomicBool>,
    ) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            std::thread::scope(|scope| {
                let started = Instant::now();
                let mut replies = Vec::new();
                let mut n = 0;
                while !stop.load(Ordering::SeqCst) {
                    sleep(
                        &stop,
                        (started + Duration::from_secs(n))
                            .saturating_duration_since(Instant::now()),
                    );
                    if stop.load(Ordering::SeqCst) {
                        break;
                    }
                    n += 1;
                    let text = format!("load {} {n:05}", w.name);
                    let (after_join, trusted) = {
                        let state = state.lock().expect("APPARATUS: load state");
                        let trusted = state.trust_seen.get(&w.name).cloned().unwrap_or_default();
                        (state.joined, trusted)
                    };
                    let node = w
                        .paths
                        .profile_dir
                        .file_name()
                        .expect("APPARATUS: posting node");
                    let mut cmd = Command::new(&w.exe);
                    room::strip_harness_env(&mut cmd);
                    cmd.args(["room", "post", &id, &text, "--node"])
                        .arg(node)
                        .env("VOX_DATA_DIR", &w.data)
                        .env("VOX_CONFIG_DIR", &w.cfg)
                        .env("VOX_PROXY", "127.0.0.1:0")
                        .env("HOME", w.data.with_extension("home"))
                        .env("VOX_LISTEN", "127.0.0.1:0")
                        .stdin(Stdio::null())
                        .stdout(Stdio::piped())
                        .stderr(Stdio::piped());
                    let offered = Instant::now();
                    let child = match cmd.spawn() {
                        Ok(child) => child,
                        Err(error) => {
                            state
                                .lock()
                                .expect("APPARATUS: load state")
                                .errors
                                .push(format!("{} could not offer post {n}: {error}", w.name));
                            break;
                        }
                    };
                    let offered_ms = offered.duration_since(started).as_millis();
                    state
                        .lock()
                        .expect("APPARATUS: load state")
                        .offered
                        .entry(w.name.clone())
                        .or_default()
                        .push(offered_ms);
                    eprintln!(
                        "[RG-1 offer] author={} post={n} pid={} offered_ms={offered_ms} \
                    data={} config={} command={} room post {id} {text} --node {}",
                        w.name,
                        child.id(),
                        w.data.display(),
                        w.cfg.display(),
                        w.exe,
                        node.to_string_lossy()
                    );
                    let (w, state) = (Arc::clone(&w), Arc::clone(&state));
                    // Waiting for one answer never holds up the next scheduled process.
                    replies.push(scope.spawn(move || {
                        let out = child.wait_with_output();
                        let answered = Instant::now();
                        let mut state = state.lock().expect("APPARATUS: load state");
                        match out {
                            Ok(out) => {
                                eprintln!(
                                    "[RG-1 ack] author={} post={n} offered_ms={offered_ms} \
                                acknowledged_ms={} lag_ms={} exit={} stdout={} stderr={}",
                                    w.name,
                                    answered.duration_since(started).as_millis(),
                                    answered.duration_since(offered).as_millis(),
                                    out.status,
                                    String::from_utf8_lossy(&out.stdout),
                                    String::from_utf8_lossy(&out.stderr)
                                );
                                if out.status.success() {
                                    state.trusted_at_offer.insert(text.clone(), trusted);
                                    state
                                        .acknowledged
                                        .entry(w.name.clone())
                                        .or_default()
                                        .push((text, after_join));
                                } else {
                                    record_refused_post(
                                        &mut state,
                                        &w.name,
                                        n,
                                        answered,
                                        out.status.code(),
                                        &String::from_utf8_lossy(&out.stdout),
                                        &String::from_utf8_lossy(&out.stderr),
                                    );
                                }
                            }
                            Err(error) => state.errors.push(format!(
                                "{} post {n} answer could not be collected: {error}",
                                w.name
                            )),
                        }
                    }));
                }
                let mut healthy = true;
                for reply in replies {
                    healthy &= reply.join().is_ok();
                }
                if !healthy {
                    state
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .errors
                        .push(format!("{}'s post collector stopped", w.name));
                }
            })
        })
    }

    fn load(
        workers: &[Arc<Worker>],
        slow: &Arc<Worker>,
        id: &str,
        state: Arc<Mutex<LoadState>>,
    ) -> Load {
        let stop = Arc::new(AtomicBool::new(false));
        let mut load = Load {
            stop: Arc::clone(&stop),
            threads: Vec::new(),
        };
        for w in workers {
            load.threads.push(poster(
                Arc::clone(w),
                id.to_owned(),
                Arc::clone(&state),
                Arc::clone(&stop),
            ));
        }
        for index in 0..3 {
            let w = slow;
            let mut session = Session::start(w, id, index);
            let text = session.step(0);
            let started = Instant::now();
            loop {
                let out = w.vox(None, &["room", "session", id, &session.id]);
                if out.ok && out.stdout.contains(&text) {
                    break;
                }
                assert!(
                    started.elapsed() < Duration::from_secs(120),
                    "APPARATUS: {}'s Session did not step: {out:?}",
                    w.name
                );
                std::thread::sleep(Duration::from_millis(100));
            }
            eprintln!("[RG-1] Session {} step 0 shown by product", session.id);
            let (state, stop) = (Arc::clone(&state), Arc::clone(&stop));
            load.threads.push(std::thread::spawn(move || {
                let mut n = 0;
                while !stop.load(Ordering::SeqCst) {
                    let at = Instant::now();
                    n += 1;
                    session.step(n);
                    *state
                        .lock()
                        .expect("APPARATUS: load state")
                        .steps
                        .entry(session.id.clone())
                        .or_default() += 1;
                    sleep(&stop, Duration::from_secs(1).saturating_sub(at.elapsed()));
                }
            }));
        }
        load
    }

    struct Pauses {
        stop: Arc<AtomicBool>,
        thread: Option<std::thread::JoinHandle<()>>,
        cycles: Arc<AtomicUsize>,
        pid: u32,
    }

    fn signal(pid: u32, name: &str) {
        let out = Command::new("kill")
            .args([name, &pid.to_string()])
            .output()
            .expect("APPARATUS: signal owned daemon");
        assert!(
            out.status.success(),
            "APPARATUS: {name} owned pid {pid}: {out:?}"
        );
    }

    impl Pauses {
        fn start(pid: u32) -> Self {
            let stop = Arc::new(AtomicBool::new(false));
            let cycles = Arc::new(AtomicUsize::new(0));
            let (stopped, observed) = (Arc::clone(&stop), Arc::clone(&cycles));
            let thread = std::thread::spawn(move || {
                while !stopped.load(Ordering::SeqCst) {
                    signal(pid, "-STOP");
                    let out = Command::new("ps")
                        .args(["-o", "stat=", "-p", &pid.to_string()])
                        .output();
                    let paused = out.as_ref().is_ok_and(|out| {
                        out.status.success() && String::from_utf8_lossy(&out.stdout).contains('T')
                    });
                    if !paused {
                        resume(pid);
                    }
                    assert!(
                        paused,
                        "APPARATUS: owned serving pid {pid} was not stopped: {out:?}"
                    );
                    let at = Instant::now();
                    sleep(&stopped, Duration::from_millis(1500));
                    signal(pid, "-CONT");
                    if !stopped.load(Ordering::SeqCst) {
                        observed.fetch_add(1, Ordering::SeqCst);
                        eprintln!(
                            "[RG-1 slow] serving_pid={pid} observed_state=T paused_ms={}",
                            at.elapsed().as_millis()
                        );
                    }
                    sleep(&stopped, Duration::from_millis(1500));
                }
            });
            Self {
                stop,
                thread: Some(thread),
                cycles,
                pid,
            }
        }
    }

    impl Drop for Pauses {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::SeqCst);
            if let Some(thread) = self.thread.take() {
                let _ = thread.join();
            }
            resume(self.pid);
        }
    }

    fn resume(pid: u32) {
        // Cleanup must not panic while another verdict is unwinding.
        let _ = Command::new("kill")
            .args(["-CONT", &pid.to_string()])
            .output();
    }

    fn check_slow(pauses: &Option<Pauses>, daemon: &mut Daemon, state: &Mutex<LoadState>) {
        assert!(
            pauses.as_ref().is_none_or(|pause| pause
                .thread
                .as_ref()
                .is_some_and(|thread| !thread.is_finished())),
            "APPARATUS: the slow-member pause thread stopped; {}",
            refusal_summary(state)
        );
        let exited = daemon.0.try_wait().unwrap_or_else(|error| {
            panic!(
                "APPARATUS: observe slow serving daemon: {error}; {}",
                refusal_summary(state)
            )
        });
        assert!(
            exited.is_none(),
            "APPARATUS: slow serving daemon exited: {exited:?}; {}",
            refusal_summary(state)
        );
    }

    #[allow(clippy::too_many_arguments)]
    fn join(
        w: &Worker,
        link: &str,
        via: &str,
        pauses: &Option<Pauses>,
        slow: &mut Daemon,
        load: &Load,
        state: &Mutex<LoadState>,
    ) -> bool {
        check_slow(pauses, slow, state);
        check_load(load, state, true);
        let started = Instant::now();
        let suffix = w.name.strip_prefix("n-").unwrap_or(&w.name);
        let bind = w
            .data
            .parent()
            .expect("APPARATUS: computer root")
            .join(format!("repo-{suffix}"));
        std::fs::create_dir_all(&bind).expect("APPARATUS: join bind directory");
        let out = w.vox_in(
            None,
            &[
                "room",
                "join",
                "--bind",
                bind.to_str().expect("APPARATUS: bind UTF-8"),
                "--passphrase-file",
                "-",
                link,
            ],
            Some(room::ROOM_PASS),
        );
        if !out.ok {
            state
                .lock()
                .expect("APPARATUS: load state")
                .refused_joins
                .push(w.name.clone());
            eprintln!(
                "RED PRODUCT: {}'s join through {via} was refused; join={:?}; \
                product stdout:\n{}\nproduct stderr:\n{}",
                w.name,
                started.elapsed(),
                out.stdout,
                out.stderr
            );
        } else {
            eprintln!("[RG-1 join] {} admitted in {:?}", w.name, started.elapsed());
        }
        check_slow(pauses, slow, state);
        assert!(
            load.threads.iter().all(|thread| !thread.is_finished()),
            "APPARATUS: posting or Session thread stopped during {}'s join; {}",
            w.name,
            refusal_summary(state)
        );
        check_cadence(state);
        out.ok
    }

    fn status(w: &Worker, id: &str) -> Value {
        try_status(w, id, None).unwrap_or_else(|why| panic!("RED PRODUCT: {why}"))
    }

    fn try_status(w: &Worker, id: &str, state: Option<&Mutex<LoadState>>) -> Result<Value, String> {
        let out = w.vox(None, &["status", "--json"]);
        check_observation_process(&w.name, "status", out.code, &out.stdout, &out.stderr, state)?;
        if !out.ok {
            return Err(format!("{}'s status refused: {out:?}", w.name));
        }
        let report: Value = serde_json::from_str(&out.stdout)
            .map_err(|error| format!("{}'s status is not JSON: {error}; {out:?}", w.name))?;
        report["rooms"]
            .as_array()
            .and_then(|rows| rows.iter().find(|row| row["id"].as_str() == Some(id)))
            .cloned()
            .ok_or_else(|| format!("{} does not report joined room: {report}", w.name))
    }

    fn member<'a>(status: &'a Value, fp: &str) -> Option<&'a Value> {
        status["members"]
            .as_array()?
            .iter()
            .find(|row| row["id"].as_str() == Some(fp))
    }

    /// Needs the authenticated contiguous verified position, not every retained sparse copy.
    /// That is `verified_through`; `holds_through` is the latest message the room can show, and
    /// only the paged read establishes showability.
    fn held_position(status: &Value, author: &str) -> Option<u64> {
        member(status, author)?["verified_through"].as_u64()
    }

    fn doctor(
        w: &Worker,
        id: &str,
        name: &str,
        state: &Mutex<LoadState>,
    ) -> Result<(bool, Value), String> {
        let out = w.vox(None, &["agent", "doctor", "--room", id, "--json"]);
        check_observation_process(
            &w.name,
            "agent doctor",
            out.code,
            &out.stdout,
            &out.stderr,
            Some(state),
        )?;
        // A nonzero doctor exit can report unrelated failed harness hooks; its JSON still carries trust.
        let report: Value = serde_json::from_str(&out.stdout)
            .map_err(|error| format!("{}'s doctor is not JSON: {error}; {out:?}", w.name))?;
        let trust = format!("trust {name}");
        let applied = report["checks"].as_array().is_some_and(|checks| {
            checks.iter().any(|row| {
                row["check"].as_str() == Some(&trust)
                    && row["detail"]
                        .as_str()
                        .is_some_and(|s| s.contains("you trust each other"))
            })
        });
        Ok((applied, report))
    }

    #[derive(Default, Debug)]
    struct Timeline {
        held: Option<usize>,
        grant: Option<usize>,
        key: Option<usize>,
        shown: Option<usize>,
    }

    /// A post's acknowledged feed fence and the exact displayed text identify each direction.
    #[allow(clippy::too_many_arguments)]
    fn observe(
        source: &Worker,
        target: &Worker,
        id: &str,
        marker: &str,
        through: u64,
        posted: usize,
        timeline: &mut Timeline,
        since: Instant,
        state: &Mutex<LoadState>,
    ) -> Result<(), String> {
        let source_status = try_status(source, id, Some(state))?;
        let target_status = try_status(target, id, Some(state))?;
        let (grant, doctor) = doctor(source, id, &target.name, state)?;
        let held = held_position(&target_status, &source.b32()).is_some_and(|n| n >= through);
        let key = member(&source_status, &target.b32())
            .is_some_and(|row| row["key_delivery_pending"] == false);
        let (texts, pages, _) = try_read(target, id, Some(marker), Some(state))?;
        // A later acknowledged post still proves this direction; convergence checks the anchor too.
        let shown_post = if texts.contains(marker) {
            Some(marker.to_owned())
        } else {
            state
                .lock()
                .expect("APPARATUS: load state")
                .acknowledged
                .get(&source.name)
                .into_iter()
                .flatten()
                .find(|(text, after)| *after && texts.contains(text))
                .map(|(text, _)| text.clone())
        };
        let shown = shown_post.is_some();
        for (name, yes, slot) in [
            ("contiguous_verified", held, &mut timeline.held),
            ("mutual_room_trust", grant, &mut timeline.grant),
            ("no_key_owed", key, &mut timeline.key),
            ("shown", shown, &mut timeline.shown),
        ] {
            if yes && slot.is_none() {
                *slot = Some(posted);
                eprintln!(
                    "[RG-1 FIRST] {}->{} {name} at_post={posted} join_ms={}",
                    source.name,
                    target.name,
                    since.elapsed().as_millis()
                );
            }
        }
        eprintln!(
            "[RG-1 timeline] {}",
            json!({
                "source": source.name, "target": target.name, "post": marker,
                "feed_through": through, "posts_since_join": posted, "pages": pages,
                "join_ms": since.elapsed().as_millis(), "source_status": source_status,
                "target_status": target_status, "doctor": doctor,
                "contiguous_verified": held, "mutual_room_trust": grant,
                "no_key_owed": key, "shown": shown, "shown_post": shown_post
            })
        );
        Ok(())
    }

    fn pair(inviter: &Worker, invitee: &Worker) {
        // Initial review plus two fresh reviews; persistent policy churn is a staging stop.
        const ATTEMPTS: usize = 3;
        let mut refusals = Vec::new();
        for attempt in 1..=ATTEMPTS {
            let invite = inviter.vox(None, &["computer", "pair", "--json"]);
            invite.expect_ok("computer pair");
            let invitation = invite.json();
            let link = invitation["invite_link"]
                .as_str()
                .expect("APPARATUS: computer invitation");
            let paired = invitee.vox_in(None, &["computer", "pair", link, "--json"], Some("yes\n"));
            if !paired.ok
                && paired.stderr.trim()
                    == "vox computer: computer peer refused the request: node: this computer's policy changed while pairing; review again"
            {
                eprintln!(
                    "[RG-1 pairing] attempt {attempt}/{ATTEMPTS}: fresh invitation required: {paired:?}"
                );
                refusals.push(paired);
                continue;
            }
            paired.expect_ok("computer pair");
            let paired = paired.json();
            let op = paired["pairing"]["operation_id"]
                .as_str()
                .expect("APPARATUS: pairing operation");
            inviter
                .vox(None, &["computer", "approve", op, "--json"])
                .expect_ok("computer approval");
            let started = Instant::now();
            loop {
                let a = inviter.vox(None, &["computer", "status", "--json"]).json();
                let b = invitee.vox(None, &["computer", "status", "--json"]).json();
                eprintln!(
                    "[RG-1 pairing] {}={} {}={}",
                    inviter.name, a, invitee.name, b
                );
                if a["state"] == "confirmed" && b["state"] == "confirmed" {
                    return;
                }
                assert!(
                    started.elapsed() < Duration::from_secs(120),
                    "APPARATUS: pairing not confirmed: {}={a} {}={b}",
                    inviter.name,
                    invitee.name
                );
                std::thread::sleep(Duration::from_secs(1));
            }
        }
        panic!(
            "APPARATUS: staging: all {ATTEMPTS} fresh computer pair attempts refused after policy changed while pairing: {refusals:?}"
        );
    }

    pub(super) fn journey(delayed: bool) {
        let root = root();
        free_disk(root.path());
        let exe = binary();
        let (_anchor, anchor) = room::spawn_anchor_as(root.path(), &exe, "127.0.0.1:0", "anchor");
        let forward =
            delayed.then(|| port_forward::PortForward::start(world::spec_addr(&anchor), true));
        let olds: Vec<_> = (1..=6)
            .map(|n| {
                Arc::new(room::named_worker_as(
                    root.path(),
                    "X",
                    &format!("n-old{n}"),
                    &exe,
                ))
            })
            .collect();
        let sib = Arc::new(room::named_worker_as(root.path(), "X", "sib", &exe));
        let x = start(&olds[0], "127.0.0.1:0", Some(&anchor));
        let slow = Arc::new(room::named_worker_as(root.path(), "Y", "y1", &exe));
        let slow_anchor = forward.as_ref().map(|f| world::respec(&anchor, f.public));
        let y = start(
            &slow,
            if delayed { "[::1]:0" } else { "127.0.0.1:0" },
            Some(slow_anchor.as_deref().unwrap_or(&anchor)),
        );
        let fast = Arc::new(room::named_worker_as(root.path(), "Z", "z1", &exe));
        let z = start(&fast, "127.0.0.1:0", Some(&anchor));
        let sibw = Arc::new(room::named_worker_as(root.path(), "W", "sibw", &exe));
        let w = start(&sibw, "127.0.0.1:0", Some(&anchor));
        let computers = [&sib, &slow, &fast, &sibw];
        let mut workers = vec![Arc::clone(&fast), Arc::clone(&slow)];
        workers.extend(olds.iter().map(Arc::clone));
        let mut daemons = [x, y, z, w];
        let ready = sib.vox(None, &["node", "list"]);
        assert!(
            ready.ok && ready.stdout.matches("Ready").count() == 7,
            "APPARATUS: X's seven siblings are not Ready: {ready:?}"
        );
        for w in computers {
            w.vox(None, &["computer", "personal", &w.name, "--json"])
                .expect_ok("personal computer node");
        }
        for w in [&slow, &fast, &sibw] {
            pair(&sib, w);
        }
        let id = create(&slow);
        let link = slow.vox(None, &["room", "link", &id]);
        link.expect_ok("slow member room link");
        let link = link.stdout.trim().to_owned();
        fast.vox_in(
            None,
            &["room", "join", "--passphrase-file", "-", &link],
            Some(room::ROOM_PASS),
        )
        .expect_ok("initial fast member join");
        let link = fast.vox(None, &["room", "link", &id]);
        link.expect_ok("fast member room link");
        let link = link.stdout.trim().to_owned();
        // Every acknowledged post, with its author.
        let mut acknowledged = BTreeMap::<String, String>::new();
        std::thread::scope(|scope| {
            for (parity, w) in [(0, &fast), (1, &slow)] {
                let id = &id;
                scope.spawn(move || {
                    for n in (parity..3000).step_by(2) {
                        post(w, id, &format!("seed {n:05} {}", "x".repeat(120)), true);
                    }
                });
            }
        });
        for n in 0..3000 {
            let author = if n % 2 == 0 { &fast.name } else { &slow.name };
            acknowledged.insert(format!("seed {n:05} {}", "x".repeat(120)), author.clone());
        }
        for (parity, w) in [(0, &fast), (1, &slow)] {
            let (shown, pages, _) = read(w, &id, None);
            assert!(
                (parity..3000)
                    .step_by(2)
                    .all(|n| shown.contains(&format!("seed {n:05} {}", "x".repeat(120)))),
                "APPARATUS: own half of 3,000 seeded posts not shown by {}",
                w.name
            );
            eprintln!("[RG-1 seed] {} own1500 shown pages={pages}", w.name);
        }
        let state = Arc::new(Mutex::new(LoadState::default()));
        let authors = [Arc::clone(&fast), Arc::clone(&slow)];
        let mut load = load(&authors, &slow, &id, Arc::clone(&state));
        std::thread::sleep(Duration::from_secs(3));
        let no_pause = std::env::var("VOX_PROOF_RG1_NO_PAUSE").as_deref() == Ok("1");
        if no_pause {
            eprintln!("[RG-1 apparatus smoke] pause disabled; never a requirement verdict");
        }
        let pauses = if delayed {
            let forward = forward.as_ref().expect("delayed forward");
            forward.set_delay(Duration::from_millis(350));
            let at = Instant::now();
            forward.open_and_verify();
            assert!(
                at.elapsed() >= Duration::from_millis(300),
                "APPARATUS: path delay below 300 ms"
            );
            let started = Instant::now();
            loop {
                let report = workers[1].vox(None, &["status", "--json"]).json();
                let slow = report["peers"].as_array().is_some_and(|peers| {
                    peers
                        .iter()
                        .any(|peer| peer["rtt_ms"].as_u64().is_some_and(|ms| ms >= 300))
                });
                if slow && forward.to_host() > 0 && forward.to_guest() > 0 {
                    eprintln!("[RG-1 slow] delayed only path, 350ms/datagram; product={report}");
                    break;
                }
                assert!(
                    started.elapsed() < Duration::from_secs(120),
                    "APPARATUS: slow member's product RTT not attained: {report}"
                );
                std::thread::sleep(Duration::from_millis(100));
            }
            None
        } else if no_pause {
            None
        } else {
            let pauses = Pauses::start(daemons[1].0.id());
            while pauses.cycles.load(Ordering::SeqCst) == 0 {
                assert!(
                    !pauses.thread.as_ref().expect("pause thread").is_finished(),
                    "APPARATUS: serving-pid pause not attained"
                );
                std::thread::sleep(Duration::from_millis(10));
            }
            Some(pauses)
        };
        let staging = Instant::now();
        loop {
            check_slow(&pauses, &mut daemons[1], &state);
            check_load(&load, &state, true);
            let ready = {
                let state = state.lock().expect("APPARATUS: load state");
                state.steps.len() == 3
                    && state.steps.values().all(|n| *n > 0)
                    && authors.iter().all(|w| {
                        state
                            .offered
                            .get(&w.name)
                            .is_some_and(|times| times.len() >= 3)
                    })
            };
            if ready {
                break;
            }
            assert!(
                staging.elapsed() < Duration::from_secs(120),
                "APPARATUS: three one-second authors with stepping Sessions not attained"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        for index in 0..3 {
            let w = &slow;
            let started = Instant::now();
            let session = format!("trial-session-{index:04}");
            let prefix = format!("{session} step ");
            loop {
                let out = w.vox(None, &["room", "session", &id, &session]);
                let stepping = out.stdout.split(&prefix).skip(1).any(|tail| {
                    tail.chars()
                        .take_while(char::is_ascii_digit)
                        .collect::<String>()
                        .parse::<usize>()
                        .is_ok_and(|n| n > 0)
                });
                if out.ok && stepping {
                    eprintln!("[RG-1] {session} continued steps shown by product");
                    break;
                }
                assert!(
                    started.elapsed() < Duration::from_secs(120),
                    "APPARATUS: continuing Session steps not attained: {out:?}"
                );
                std::thread::sleep(Duration::from_millis(100));
            }
        }
        eprintln!("[RG-1 staged before late joins] 3000 entries; y1/z1 offer1/s; three OMP Sessions on y1; daemons=4 anchor_processes=1");
        for (n, w) in olds.iter().enumerate() {
            if join(w, &link, "fast z1", &pauses, &mut daemons[1], &load, &state) {
                let hello = format!("hello from {}", w.name);
                let out = w.vox(None, &["room", "post", &id, &hello]);
                if out.ok {
                    acknowledged.insert(hello, w.name.clone());
                } else {
                    record_refused_post(
                        &mut state.lock().expect("APPARATUS: load state"),
                        &w.name,
                        0,
                        Instant::now(),
                        out.code,
                        &out.stdout,
                        &out.stderr,
                    );
                }
                if n == 0 {
                    load.threads.push(poster(
                        Arc::clone(w),
                        id.clone(),
                        Arc::clone(&state),
                        Arc::clone(&load.stop),
                    ));
                }
            }
            if n < 5 {
                std::thread::sleep(Duration::from_secs(10));
            }
        }
        let refusals = state
            .lock()
            .expect("APPARATUS: load state")
            .refused_joins
            .clone();
        std::thread::sleep(Duration::from_secs(30));
        for w in workers.iter().filter(|w| !refusals.contains(&w.name)) {
            eprintln!("[RG-1 before create] {} {}", w.name, status(w, &id));
        }
        eprintln!(
            "[RG-1 before create doctor] {:?}",
            olds[0].vox(None, &["agent", "doctor", "--room", &id, "--json"])
        );
        // Match the prototype's product polling load during creation and the join.
        let newcomer = Arc::new(Mutex::new(None::<Arc<Worker>>));
        let (sample_workers, sample_new, sample_id, sample_stop) = (
            vec![Arc::clone(&slow), Arc::clone(&olds[0]), Arc::clone(&fast)],
            Arc::clone(&newcomer),
            id.clone(),
            Arc::clone(&load.stop),
        );
        load.threads.push(std::thread::spawn(move || {
            let mut round = 0;
            while !sample_stop.load(Ordering::SeqCst) {
                let at = Instant::now();
                let mut observed = sample_workers.clone();
                if let Some(w) = sample_new
                    .lock()
                    .expect("APPARATUS: sampler newcomer")
                    .as_ref()
                {
                    observed.insert(0, Arc::clone(w));
                }
                for w in observed {
                    let s = w.vox(None, &["status", "--json"]);
                    eprintln!("[RG-1 admission sample] member={} status={s:?}", w.name);
                    sample_read(&w, &sample_id);
                    if round % 10 == 0 && (w.name == "y1" || w.name == "n-new") {
                        eprintln!(
                            "[RG-1 admission doctor] member={} {:?}",
                            w.name,
                            w.vox(None, &["agent", "doctor", "--room", &sample_id, "--json"])
                        );
                    }
                }
                round += 1;
                sleep(
                    &sample_stop,
                    Duration::from_secs(1).saturating_sub(at.elapsed()),
                );
            }
        }));
        let created = Instant::now();
        state
            .lock()
            .expect("APPARATUS: load state")
            .newcomer_create_started = Some(created);
        eprintln!("[RG-1 newcomer] node create started");
        let new = Arc::new(room::named_worker_as(root.path(), "W", "n-new", &exe));
        let newcomer_created = Instant::now();
        eprintln!(
            "[RG-1 newcomer] node create completed elapsed_ms={}",
            created.elapsed().as_millis()
        );
        *newcomer.lock().expect("APPARATUS: sampler newcomer") = Some(Arc::clone(&new));
        workers.push(Arc::clone(&new));
        // Each member's own product says, about this room, whom it trusts. Per member, the moment
        // its `vox agent doctor --room` first says "you trust …" of another member is the moment
        // from which its posts are owed to that member, if it did not trust that member from
        // before the room's first post. The node's `vox trust list` names a member as soon as the
        // node saves the grant; the room releases its key later, from where the room's own trust
        // reconciliation marks the decision, so posts between the two are not promised.
        let (observed, seen_state, seen_stop, seen_room) = (
            workers.clone(),
            Arc::clone(&state),
            Arc::clone(&load.stop),
            id.clone(),
        );
        load.threads.push(std::thread::spawn(move || {
            let names: BTreeSet<String> = observed.iter().map(|w| w.name.clone()).collect();
            while !seen_stop.load(Ordering::SeqCst) {
                let at = Instant::now();
                for w in &observed {
                    let complete = seen_state
                        .lock()
                        .expect("APPARATUS: load state")
                        .trust_seen
                        .get(&w.name)
                        .is_some_and(|seen| seen.len() + 1 >= names.len());
                    if complete || seen_stop.load(Ordering::SeqCst) {
                        continue;
                    }
                    let out = w.vox(None, &["agent", "doctor", "--room", &seen_room, "--json"]);
                    // A nonzero doctor exit can report unrelated harness hooks; its JSON still
                    // carries trust.
                    let Ok(report) = serde_json::from_str::<Value>(&out.stdout) else {
                        continue;
                    };
                    let named: BTreeSet<String> = report["checks"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .filter(|row| {
                            row["detail"]
                                .as_str()
                                .is_some_and(|detail| detail.starts_with("you trust"))
                        })
                        .filter_map(|row| row["check"].as_str()?.strip_prefix("trust "))
                        .filter(|name| names.contains(*name))
                        .map(str::to_owned)
                        .collect();
                    let mut state = seen_state.lock().expect("APPARATUS: load state");
                    let seen = state.trust_seen.entry(w.name.clone()).or_default();
                    let added: Vec<String> = named.difference(seen).cloned().collect();
                    if !added.is_empty() {
                        eprintln!(
                            "[RG-1 room trust seen] member={} doctor --room now says it trusts {added:?}",
                            w.name
                        );
                        seen.extend(added);
                    }
                }
                sleep(&seen_stop, Duration::from_secs(1).saturating_sub(at.elapsed()));
            }
        }));
        std::thread::sleep(Duration::from_secs(2));
        for w in computers {
            eprintln!(
                "[RG-1 revisions after create] {} {:?}",
                w.name,
                w.vox(None, &["computer", "status", "--json"])
            );
        }
        for w in [&slow, &new] {
            eprintln!(
                "[RG-1 trust after create] {} {:?}",
                w.name,
                w.vox(None, &["trust", "list"])
            );
        }
        std::thread::sleep(Duration::from_secs(8).saturating_sub(created.elapsed()));
        let fresh_link = fast.vox(None, &["room", "link", &id]);
        let newcomer_link = if fresh_link.ok {
            fresh_link.stdout.trim()
        } else {
            let words = format!(
                "fresh room link from fast z1 refused; ms_from_newcomer_create_start={} \
                 ms_after_newcomer_create_completed={}; product stdout:\n{}\nproduct stderr:\n{}",
                created.elapsed().as_millis(),
                newcomer_created.elapsed().as_millis(),
                fresh_link.stdout,
                fresh_link.stderr
            );
            let mut state = state.lock().expect("APPARATUS: load state");
            if fresh_link.code.is_none()
                || (fresh_link.stdout.trim().is_empty() && fresh_link.stderr.trim().is_empty())
            {
                state.errors.push(format!(
                    "room-link process ended without a complete product refusal: {fresh_link:?}"
                ));
            } else {
                eprintln!("RED PRODUCT: {words}");
                state.refused_commands.push(words);
            }
            // Same admitting member, same already-successful link; the refused command is not retried.
            link.as_str()
        };
        let join_started = Instant::now();
        let newcomer_admitted = join(
            &new,
            newcomer_link,
            "fast z1",
            &pauses,
            &mut daemons[1],
            &load,
            &state,
        );
        let refusals = state
            .lock()
            .expect("APPARATUS: load state")
            .refused_joins
            .clone();
        check_slow(&pauses, &mut daemons[1], &state);
        eprintln!(
            "[RG-1 admission] refused {} of 7 joins: {refusals:?}",
            refusals.len()
        );
        if !newcomer_admitted {
            let healthy = load.finish();
            let refused_posts = report_post_refusals(&state);
            let refused_commands = report_command_refusals(&state);
            check_slow(&pauses, &mut daemons[1], &state);
            check_errors(&state, true);
            assert!(
                healthy,
                "APPARATUS: admission collection stopped; {}",
                refusal_summary(&state)
            );
            panic!(
                "RED PRODUCT: apparatus_smoke={no_pause}; refused {} of 7 joins: {refusals:?}; {refused_posts} posts refused; \
                {refused_commands} other commands refused; newcomer was refused; \
                each member/author/post/command/refusal is quoted above",
                refusals.len()
            );
        }
        // Only admitted people are room members; their earlier refusals remain in the verdict.
        workers.retain(|w| !refusals.contains(&w.name));
        eprintln!(
            "[RG-1 admission] newcomer admitted; continuing with {} members",
            workers.len()
        );
        state.lock().expect("APPARATUS: load state").joined = true;
        if no_pause {
            eprintln!(
                "[RG-1 apparatus smoke] post-admission path entered; never a requirement verdict"
            );
        }
        // Every admitted person keeps offering posts, including after a refused post.
        for w in &workers {
            let posting = state
                .lock()
                .expect("APPARATUS: load state")
                .offered
                .contains_key(&w.name);
            if !posting {
                load.threads.push(poster(
                    Arc::clone(w),
                    id.clone(),
                    Arc::clone(&state),
                    Arc::clone(&load.stop),
                ));
            }
        }
        let joined = Instant::now();
        let new_index = workers.len() - 1;
        // Anchor each direction on its first acknowledged post, never on a refused marker.
        let mut markers: Vec<Option<(String, u64)>> = vec![None; workers.len()];
        let mut toward_new: Vec<Timeline> = (0..new_index).map(|_| Timeline::default()).collect();
        let mut from_new: Vec<Timeline> = (0..new_index).map(|_| Timeline::default()).collect();
        let mut tail_failure = None::<String>;
        'timeline: loop {
            check_slow(&pauses, &mut daemons[1], &state);
            check_load(&load, &state, false);
            for (n, w) in workers.iter().enumerate() {
                if markers[n].is_none() {
                    let (text, refused, total) = {
                        let state = state.lock().expect("APPARATUS: load state");
                        let text = state
                            .acknowledged
                            .get(&w.name)
                            .and_then(|rows| rows.iter().find(|(_, after)| *after))
                            .map(|(text, _)| text.clone());
                        let refused = state
                            .refused_posts
                            .get(&w.name)
                            .into_iter()
                            .flatten()
                            .filter(|refusal| refusal.at >= joined)
                            .count();
                        let total = post_count(&state, &w.name) + refused;
                        (text, refused, total)
                    };
                    if text.is_none() && total >= 100 {
                        tail_failure = Some(format!(
                            "{}: {refused} of {total} posts since join refused, none acknowledged",
                            w.name
                        ));
                        break 'timeline;
                    }
                    if let Some(text) = text {
                        let report = match try_status(w, &id, Some(&state)) {
                            Ok(report) => report,
                            Err(why) => {
                                tail_failure = Some(why);
                                break 'timeline;
                            }
                        };
                        let Some(through) = report["own_feed_through"].as_u64() else {
                            tail_failure = Some(format!(
                                "{}'s acknowledged post has no feed fence: {report}",
                                w.name
                            ));
                            break 'timeline;
                        };
                        markers[n] = Some((text, through));
                    }
                }
            }
            let Some((new_marker, new_through)) = markers[new_index].as_ref() else {
                std::thread::sleep(Duration::from_millis(100));
                continue;
            };
            for n in 0..new_index {
                let Some((marker, through)) = markers[n].as_ref() else {
                    continue;
                };
                let count = post_count(
                    &state.lock().expect("APPARATUS: load state"),
                    &workers[n].name,
                );
                let new_count =
                    post_count(&state.lock().expect("APPARATUS: load state"), &new.name);
                if let Err(why) = observe(
                    &workers[n],
                    &new,
                    &id,
                    marker,
                    *through,
                    count,
                    &mut toward_new[n],
                    joined,
                    &state,
                )
                .and_then(|()| {
                    observe(
                        &new,
                        &workers[n],
                        &id,
                        new_marker,
                        *new_through,
                        new_count,
                        &mut from_new[n],
                        joined,
                        &state,
                    )
                }) {
                    tail_failure = Some(why);
                    break 'timeline;
                }
                for (source, target, marker, marks) in [
                    (workers[n].as_ref(), new.as_ref(), marker, &toward_new[n]),
                    (new.as_ref(), workers[n].as_ref(), new_marker, &from_new[n]),
                ] {
                    let count =
                        post_count(&state.lock().expect("APPARATUS: load state"), &source.name);
                    if count >= 100 {
                        let shown = match try_read(target, &id, None, Some(&state)) {
                            Ok((shown, _, _)) => shown,
                            Err(why) => {
                                tail_failure = Some(why);
                                break 'timeline;
                            }
                        };
                        let has_live_post = state
                            .lock()
                            .expect("APPARATUS: load state")
                            .acknowledged
                            .get(&source.name)
                            .into_iter()
                            .flatten()
                            .any(|(text, after_join)| *after_join && shown.contains(text));
                        check_slow(&pauses, &mut daemons[1], &state);
                        if !shown.contains(marker) && !has_live_post {
                            tail_failure = Some(format!(
                                "{} acknowledged {count} posts since join; {} shows none; \
                                observed/unobserved marks (independent, not prerequisites)={marks:?}",
                                source.name, target.name));
                            break 'timeline;
                        }
                    }
                }
            }
            if toward_new
                .iter()
                .chain(&from_new)
                .all(|t| t.shown.is_some())
            {
                break;
            }
            if markers[..new_index].iter().all(Option::is_none) {
                // No direction is ready for an observation yet; avoid an all-refused busy loop.
                std::thread::sleep(Duration::from_millis(100));
            }
        }
        check_slow(&pauses, &mut daemons[1], &state);
        assert!(
            load.finish(),
            "APPARATUS: a load thread stopped while final answers were collected; {}",
            refusal_summary(&state)
        );
        drop(load);
        check_errors(&state, false);
        {
            let state = state.lock().expect("APPARATUS: load state");
            for (author, texts) in &state.acknowledged {
                acknowledged.extend(texts.iter().map(|(text, _)| (text.clone(), author.clone())));
            }
        }
        // What each member is owed after the authors stop (consent is forward-only, ADR-006
        // S-18; `a_member_reads_only_what_follows_trust_proof`): its own posts; every post of an
        // author that trusted it from before the room's first post (every member paired before
        // the room was created); and every post another author offered after that author's own
        // `vox agent doctor --room` said it trusts the reader.
        let from_start: BTreeSet<String> = std::iter::once(&fast)
            .chain([&slow])
            .chain(&olds)
            .map(|w| w.name.clone())
            .collect();
        let trusted_at_offer = std::mem::take(
            &mut state
                .lock()
                .expect("APPARATUS: load state")
                .trusted_at_offer,
        );
        let owed: BTreeMap<String, BTreeSet<String>> = workers
            .iter()
            .map(|reader| {
                let reader = &reader.name;
                let texts = acknowledged
                    .iter()
                    .filter(|(text, author)| {
                        *author == reader
                            || (from_start.contains(*author) && from_start.contains(reader))
                            || trusted_at_offer
                                .get(*text)
                                .is_some_and(|trusted| trusted.contains(reader))
                    })
                    .map(|(text, _)| text.clone())
                    .collect();
                (reader.clone(), texts)
            })
            .collect();
        for (reader, texts) in &owed {
            let mut by_author = BTreeMap::<&str, (usize, usize)>::new();
            for (text, author) in &acknowledged {
                let counts = by_author.entry(author).or_default();
                counts.1 += 1;
                counts.0 += usize::from(texts.contains(text));
            }
            eprintln!(
                "[RG-1 owed] member={reader} owed={} of acknowledged={}; per author (owed, acknowledged)={by_author:?}",
                texts.len(),
                acknowledged.len()
            );
        }
        // Keep the slow condition in force through convergence; no elapsed-time verdict.
        // Ten answered demands give repeated discovery/fetch opportunities without an
        // unbounded wait. Only a new smallest missing count resets a member's budget; a member
        // whose budget is spent is asked no more, and every other member goes on.
        const NO_PROGRESS_DEMANDS: usize = 10;
        let mut convergence = BTreeMap::<String, (usize, usize)>::new();
        let mut short = BTreeMap::<String, (usize, String)>::new();
        let mut requests = BTreeMap::<String, usize>::new();
        if tail_failure.is_none() {
            'convergence: loop {
                check_slow(&pauses, &mut daemons[1], &state);
                let mut complete = true;
                for w in &workers {
                    if short.contains_key(&w.name) {
                        continue;
                    }
                    let (shown, pages, oldest) = match try_read(w, &id, None, Some(&state)) {
                        Ok(page) => page,
                        Err(why) => {
                            tail_failure = Some(why);
                            break 'convergence;
                        }
                    };
                    let missing: BTreeSet<_> = owed[&w.name].difference(&shown).cloned().collect();
                    eprintln!("[RG-1 stopped authors] member={} owed={} acknowledged={} pages={pages} missing={} {missing:?}",
                        w.name, owed[&w.name].len(), acknowledged.len(), missing.len());
                    if missing.is_empty() {
                        continue;
                    }
                    let answered = match convergence.get_mut(&w.name) {
                        Some((smallest, answered)) if missing.len() >= *smallest => {
                            *answered += 1;
                            *answered
                        }
                        _ => {
                            convergence.insert(w.name.clone(), (missing.len(), 0));
                            0
                        }
                    };
                    check_slow(&pauses, &mut daemons[1], &state);
                    if answered >= NO_PROGRESS_DEMANDS {
                        let first = missing.first().cloned().unwrap_or_default();
                        short.insert(w.name.clone(), (missing.len(), first));
                        continue;
                    }
                    complete = false;
                    let mut args = vec!["room", "read", &id, "--history", "older"];
                    if let Some(oldest) = oldest.as_deref() {
                        args.extend(["--before", oldest]);
                    }
                    let demand = w.vox(None, &args);
                    *requests.entry(w.name.clone()).or_default() += 1;
                    if let Err(why) = check_observation_process(
                        &w.name,
                        "room read --history older",
                        demand.code,
                        &demand.stdout,
                        &demand.stderr,
                        Some(&state),
                    ) {
                        tail_failure = Some(why);
                        break 'convergence;
                    }
                    let answer = demand
                        .stderr
                        .lines()
                        .find(|line| line.starts_with("vox: history"))
                        .unwrap_or_default();
                    eprintln!(
                        "[RG-1 older] member={} missing={} answer={answer:?}",
                        w.name,
                        missing.len()
                    );
                    if !demand.ok {
                        tail_failure = Some(format!(
                            "{} refused older history while missing post {:?}: {demand:?}",
                            w.name,
                            missing.first()
                        ));
                        break 'convergence;
                    }
                }
                check_slow(&pauses, &mut daemons[1], &state);
                if complete {
                    break;
                }
            }
        }
        for w in &workers {
            eprintln!(
                "[RG-1 requests] member={} --history older requests={} still short={:?}",
                w.name,
                requests.get(&w.name).copied().unwrap_or(0),
                short.get(&w.name).map(|(count, _)| count)
            );
        }
        if tail_failure.is_none() && !short.is_empty() {
            tail_failure = Some(format!(
                "{} member(s) still miss posts they are owed after {NO_PROGRESS_DEMANDS} answered \
                 --history older demands without progress: {}",
                short.len(),
                short
                    .iter()
                    .map(|(name, (count, first))| format!(
                        "{name} misses {count} (first {first:?})"
                    ))
                    .collect::<Vec<_>>()
                    .join("; ")
            ));
        }
        check_slow(&pauses, &mut daemons[1], &state);
        check_errors(&state, false);
        drop(pauses);
        free_disk(root.path());
        let refused_posts = report_post_refusals(&state);
        let refused_commands = report_command_refusals(&state);
        let tail = tail_failure.as_deref().unwrap_or(
            "every admitted member shown both ways; every post each member is owed shown on it after authors stop");
        if no_pause {
            eprintln!("apparatus smoke: the post-admission code ran to a verdict; tail={tail}");
        }
        assert!(
            refusals.is_empty()
                && refused_posts == 0
                && refused_commands == 0
                && tail_failure.is_none(),
            "RED PRODUCT: apparatus_smoke={no_pause}; refused {} of 7 joins: {refusals:?}; {refused_posts} posts refused; \
             {refused_commands} other commands refused; tail={tail}; \
             each member/author/post/command/refusal is quoted above",
            refusals.len()
        );
        eprintln!(
            "GREEN: RG-1 apparatus_smoke={no_pause}; every member shown both ways; every post each member is owed \
            (of {} acknowledged) shown on it after authors stop; daemons=4 anchor_processes=1 run={:?}",
            acknowledged.len(),
            join_started.elapsed()
        );
    }
}
