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
// 257-post history BLOCKS: a newcomer reads every post exactly once and in order, the part below
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
    hosted_nodes_read_each_other_and_the_flow_state_pool_holds_no_port,
    a_quiet_room_costs_no_rounds_and_says_when_it_last_synced,
    retained_rows_render_once_their_key_and_consent_arrive,
);

#[path = "support/test_knobs.rs"]
mod test_knobs;
#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/attach.rs"]
mod attach;

#[path = "support/typed.rs"]
mod typed;

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::io::Write;
#[cfg(feature = "optional-proofs")]
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const VOX: &str = env!("CARGO_BIN_EXE_vox");
const IDENTITY: &str = "an identity passphrase";
const ROOMPASS: &str = "the room passphrase";
// The product constant is intentionally compiled out without `test-knobs`; this optional proof
// must still compile in the ordinary optional-proof profile.
const TEST_EXPIRING_ADMIN_ENV: &str = "VOX_TEST_EXPIRING_ADMIN";
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

/// The same, with more shipped daemon arguments (`--no-node`, for a multi-node host).
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

struct Fx35Status {
    status: String,
}

/// One shipped, single-snapshot status document for the named hosted node.
fn fx35_synced(dir: &Path, node: Option<&str>) -> Fx35Status {
    let (ok, status, err) = vox(dir, &as_node(&["status", "--json"], node), None);
    assert!(ok, "PRODUCT: `vox status --json` failed: {err}");
    serde_json::from_str::<serde_json::Value>(&status).unwrap_or_else(|error| {
        panic!("PRODUCT: `vox status --json` is not JSON: {error}: {status}")
    });
    Fx35Status { status }
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

/// Only the explicit shipped startup transition is retryable; all other errors retain their
/// original PRODUCT verdict. A caller must discard any partial snapshot before refreshing.
fn room_preparing_error(err: &str) -> bool {
    err.trim() == "vox: that room is preparing its saved history; the node is Ready, and the room will become available when preparation finishes — no passphrase is needed"
}

/// Every row a person reads, oldest first, in one exact paged JSON observation. A malformed row
/// or a refused read is a product red because both are what the shipped command returned.
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
        if !ok && room_preparing_error(&err) {
            // A prior page belongs to an earlier room view; restart the observation intact.
            before = None;
            pages_newest_first.clear();
            let _ = room_status(dir, "reader", room);
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

/// The user-visible SAY body; an owed placeholder is not readable plaintext.
fn readable_say_body(row: &serde_json::Value) -> Option<&str> {
    assert_eq!(
        row["schema"], "vox.room.row/1",
        "PRODUCT: malformed room row: {row}"
    );
    if row["owed"] == true && row["text"] == "" {
        return None;
    }
    assert_eq!(
        row["owed"], false,
        "PRODUCT: readable row has no false owed flag: {row}"
    );
    assert_eq!(
        row["envelope"]["v"], 1,
        "PRODUCT: SAY has no version 1 envelope: {row}"
    );
    assert_eq!(
        row["envelope"]["type"], "say",
        "PRODUCT: row is not SAY: {row}"
    );
    assert_eq!(
        row["parse_error"],
        serde_json::Value::Null,
        "PRODUCT: SAY did not parse: {row}"
    );
    Some(
        row["envelope"]["body"]
            .as_str()
            .unwrap_or_else(|| panic!("PRODUCT: SAY has no string body: {row}")),
    )
}

/// The shipped hash view includes held ciphertext; the ordinary timeline includes only rows
/// the reader can decrypt. Both observations are needed to stage the missing-fact boundary.
fn held_row_observation(
    dir: &Path,
    room: &str,
    expected_hashes: &[String],
) -> Option<(Vec<String>, Vec<serde_json::Value>)> {
    let (ok, out, err) = vox(dir, &["room", "read", room, "--hashes"], None);
    if !ok && room_preparing_error(&err) {
        let _ = room_status(dir, "reader", room);
        return None;
    }
    if !ok && err.trim() == "vox: the room changed while reading; refresh and retry" {
        // This output is a partial snapshot. The product explicitly asks for a fresh read.
        return None;
    }
    assert!(
        ok,
        "PRODUCT: reader's `vox room read --hashes` failed for {room}: {out}{err}"
    );
    let held: Vec<String> = parse_room_hashes(&out, "reader")
        .into_iter()
        .filter(|hash| expected_hashes.contains(hash))
        .collect();
    let visible: Vec<_> = room_rows(dir, room)
        .into_iter()
        .filter(|row| {
            row["entry_hash"]
                .as_str()
                .is_some_and(|hash| expected_hashes.iter().any(|expected| expected == hash))
        })
        .collect();
    Some((held, visible))
}

fn wait_for_held_rows(dir: &Path, room: &str, expected_hashes: &[String], hold: &str) {
    loop {
        let Some((held, visible)) = held_row_observation(dir, room, expected_hashes) else {
            std::thread::yield_now();
            continue;
        };
        assert!(visible.iter().all(|row| readable_say_body(row).is_none()),
            "PRODUCT: an exact row was readable while its required {hold} fact was absent in room {room}: {visible:?}");
        if held.len() < expected_hashes.len() {
            std::thread::sleep(Duration::from_millis(100));
            continue;
        }
        assert_eq!(
            held, expected_hashes,
            "APPARATUS: exact rows were not held once in source order under {hold} in room {room}"
        );
        return;
    }
}

fn assert_held_rows_at_boundary(
    dir: &Path,
    room: &str,
    expected_hashes: &[String],
    boundary: &str,
) {
    let (held, visible) = loop {
        if let Some(observation) = held_row_observation(dir, room, expected_hashes) {
            break observation;
        }
        std::thread::yield_now();
    };
    assert_eq!(
        held, expected_hashes,
        "APPARATUS: exact rows not held once in order at {boundary}: {held:?}"
    );
    assert!(
        visible.iter().all(|row| readable_say_body(row).is_none()),
        "APPARATUS: rows rendered before {boundary}: {visible:?}"
    );
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
                    .then(|| (hash.to_owned(), readable_say_body(row).map(str::to_owned)))
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
                        .then(|| (hash.to_owned(), readable_say_body(row).map(str::to_owned)))
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
    governance_revision: u64,
    render_backfill_pending: bool,
    key_delivery_pending: Vec<String>,
}

/// What the shipped status command says about one room. Refused or malformed output is a product
/// red even while the proof is arranging its deliberate holds: it is still the shipped command's
/// user-visible answer.
fn room_status(dir: &Path, reader: &str, room: &str) -> RoomStatus {
    let mut last_preparation = None;
    let value: serde_json::Value = loop {
        let (ok, out, err) = vox(dir, &["status", "--json"], None);
        assert!(ok, "PRODUCT: {reader}'s `vox status --json` was unavailable while staging room {room}: {out}{err}");
        let value: serde_json::Value = serde_json::from_str(&out).unwrap_or_else(|error| {
            panic!("PRODUCT: {reader}'s `vox status --json` was malformed while staging room {room} ({error}): {out}{err}")
        });
        if value["rooms"].as_array().is_some_and(|rooms| {
            rooms
                .iter()
                .any(|row| row["id"].as_str().is_some_and(|id| id.starts_with(room)))
        }) {
            break value;
        }
        let preparing = value["preparing"].as_array().and_then(|rooms| {
            let mut exact = rooms
                .iter()
                .filter(|row| row["id"].as_str().is_some_and(|id| id.starts_with(room)));
            let first = exact.next()?;
            if exact.next().is_some() {
                return None;
            }
            Some(first)
        });
        if value["status"] == "Ready" {
            if let Some(preparing) = preparing {
                let observation = preparing.to_string();
                if last_preparation.as_deref() != Some(observation.as_str()) {
                    eprintln!("[proof] {reader}'s exact room {room} is preparing: {observation}");
                    last_preparation = Some(observation);
                }
                std::thread::sleep(Duration::from_millis(100));
                continue;
            }
        }
        panic!("PRODUCT: {reader}'s `vox status --json` did not contain staged room {room}: {out}");
    };
    let row = value["rooms"]
        .as_array()
        .and_then(|rooms| {
            rooms
                .iter()
                .find(|row| row["id"].as_str().is_some_and(|id| id.starts_with(room)))
        })
        .unwrap_or_else(|| {
            panic!(
                "PRODUCT: {reader}'s `vox status --json` did not contain staged room {room}: \
                 {value}"
            )
        });
    RoomStatus {
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
                    .unwrap_or_else(|| {
                        panic!("PRODUCT: {reader}'s room member has no id: {member}")
                    })
                    .to_owned()
            })
            .collect(),
        received_key_generations: row["received_key_generations"].as_u64().unwrap_or_else(|| {
            panic!(
                "PRODUCT: {reader}'s room status has no numeric `received_key_generations`: {row}"
            )
        }),
        governance_revision: row["governance_revision"].as_u64().unwrap_or_else(|| {
            panic!("PRODUCT: {reader}'s room status has no numeric `governance_revision`: {row}")
        }),
        render_backfill_pending: row["render_backfill_pending"].as_bool().unwrap_or_else(|| {
            panic!(
                "PRODUCT: {reader}'s room status has no boolean `render_backfill_pending`: {row}"
            )
        }),
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
    loop {
        let (ok, out, err) = vox(dir, &["room", "read", room, "--hashes"], None);
        if !ok && room_preparing_error(&err) {
            let _ = room_status(dir, reader, room);
            continue;
        }
        assert!(
            ok,
            "PRODUCT: {reader}'s `vox room read --hashes` failed for {room}: {out}{err}"
        );
        return parse_room_hashes(&out, reader);
    }
}

fn parse_room_hashes(out: &str, reader: &str) -> Vec<String> {
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

/// Rename through the shipped command and return the exact authenticated row it says it appended.
fn rename_hash(dir: &Path, reader: &str, room: &str, name: &str) -> String {
    let (ok, out, err) = vox(dir, &["room", "rename", room, name], None);
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

/// Wait for the shipped admin page to include or exclude one exact member. A refreshing page is
/// causal work in flight; any other refusal and failure to reach the expected roster are product
/// reds for this authority claim, not a generic harness timeout.
fn wait_admin_membership(dir: &Path, reader: &str, room: &str, member: &str, present: bool) {
    loop {
        let (ok, out, err) = vox(dir, &["room", "admin", "list", room], None);
        if ok
            && out
                .lines()
                .any(|line| line.split_whitespace().next() == Some(member))
                == present
        {
            return;
        }
        if !ok && room_preparing_error(&err) {
            let _ = room_status(dir, reader, room);
            continue;
        }
        assert!(
            ok || err.contains("governance") && err.contains("refreshing"),
            "PRODUCT: {reader}'s `vox room admin list` failed for {room}: {out}{err}"
        );
        std::thread::yield_now();
    }
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
        if room_preparing_error(&err) {
            let _ = room_status(dir, reader, room);
            continue;
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
    loop {
        let (_, out, err) = vox(dir, &["agent", "doctor", "--room", room, "--json"], None);
        let report: serde_json::Value = serde_json::from_str(&out).unwrap_or_else(|error| {
            panic!("PRODUCT: {reader}'s `vox agent doctor --json` was malformed while staging room {room} ({error}): {out}{err}")
        });
        let checks = report["checks"].as_array().unwrap_or_else(|| {
            panic!("PRODUCT: {reader}'s doctor reported no checks for room {room}: {report}")
        });
        let trust_check = format!("trust {member}");
        if let Some(detail) = checks
            .iter()
            .find(|check| check["check"].as_str() == Some(trust_check.as_str()))
            .and_then(|check| check["detail"].as_str())
        {
            return detail.to_owned();
        }
        let node_ready = checks
            .iter()
            .any(|check| check["check"] == "node" && check["status"] == "ok");
        let room_preparing = checks.iter().any(|check| check["check"] == "room" && check["status"] == "fail"
            && check["detail"].as_str() == Some("that room is preparing its saved history; the node is Ready, and the room will become available when preparation finishes — no passphrase is needed"));
        if node_ready && room_preparing {
            // Doctor explicitly reports a named product transition; this is not a trust verdict.
            std::thread::sleep(Duration::from_millis(100));
            continue;
        }
        panic!("PRODUCT: {reader}'s doctor reported no `trust {member}` detail for staged room {room}: {report}");
    }
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
fn wait_reader_one_way_trust(dir: &Path, reader: &str, room: &str, member: &str) {
    loop {
        let actual = trust_detail(dir, reader, room, member);
        match actual.as_str() {
            "you trust it, but it has not trusted you: it cannot read you" => return,
            "you have not trusted it: it cannot read you, and you do not read it" => {
                std::thread::sleep(Duration::from_millis(100));
            }
            _ => panic!("APPARATUS: required missing-consent boundary was not staged for {reader}/{member} in {room}: {actual}"),
        }
    }
}

/// The local trust decision is visible even if the offline peer's reciprocal grant has not
/// arrived. Mutual trust is checked separately after that peer starts again.
fn wait_local_trust(dir: &Path, reader: &str, room: &str, member: &str) {
    loop {
        let actual = trust_detail(dir, reader, room, member);
        match actual.as_str() {
            "you trust each other"
            | "you trust it, but it has not trusted you: it cannot read you" => return,
            "you have not trusted it: it cannot read you, and you do not read it" => {
                std::thread::sleep(Duration::from_millis(100));
            }
            _ => panic!(
                "APPARATUS: unexpected local-trust state for {reader}/{member} in {room}: {actual}"
            ),
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

/// Whether `vox room read` on `dir` shows `text` now. A read that fails is a red, never silence.
fn reads(dir: &Path, room: &str, text: &str) -> bool {
    let (ok, out, err) = vox(dir, &["room", "read", room], None);
    assert!(ok, "PRODUCT: `vox room read` refused: {out}{err}");
    out.contains(text)
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

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct HistoryDemandReply {
    schema: String,
    instance: String,
    request: Option<String>,
    status: vox_core::node::api::HistoryDemandStatus,
}

#[derive(Clone)]
struct ArchiveOwner {
    room: [u8; 32],
    instance: String,
    request: String,
    author: Option<[u8; 32]>,
    head: Option<[u8; 32]>,
}

struct ArchiveStage {
    room: String,
    owners: BTreeMap<&'static str, ArchiveOwner>,
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

/// A requested page that has not arrived must still have an exact shipped owner. This detects
/// the wedge itself: the history request is incomplete while neither its demand controller, its
/// bounded flow nor an exact admission owns it. It does not infer failure from elapsed time,
/// retry count, queue depth or CPU load.
fn assert_history_owned(dir: &Path, room: &str, peer: &str, held: usize, expected: usize) {
    let (ok, out, err) = vox(dir, &["status", "--json"], None);
    assert!(
        ok,
        "PRODUCT: the shipped status command failed while {held} of {expected} requested rows \
         were held: {err}"
    );
    let status: serde_json::Value = serde_json::from_str(&out).unwrap_or_else(|error| {
        panic!("PRODUCT: shipped status returned malformed JSON during catch-up: {error}: {out}")
    });
    let history = &status["lanes"]["history"];
    let exact = |row: &serde_json::Value| {
        row["room"]
            .as_str()
            .is_some_and(|candidate| candidate.starts_with(room))
            && row["peer"].as_str() == Some(peer)
    };
    let demand_owned = history["owner"].as_object().is_some_and(|_| {
        let exact_request = history["owner"]["room"]
            .as_str()
            .is_some_and(|candidate| candidate.starts_with(room))
            && history["owner"]["request"].as_str().is_some()
            && history["owner"]["instance"].as_str().is_some();
        exact_request
            && if history["owner"]["stage"] == "resume_owed" {
                history["owner"]["ticket"].as_u64().is_some() && history["owner"]["wake"] == true
            } else {
                history["owner"]["peer"].as_str() == Some(peer)
            }
    });
    let bounded = &status["lanes"]["bounded"];
    let flow_owned = [
        "ready",
        "running",
        "deferred",
        "retiring",
        "required",
        "admissions",
    ]
    .iter()
    .any(|field| {
        bounded[*field]
            .as_array()
            .is_some_and(|rows| rows.iter().any(|row| !row.is_null() && exact(row)))
    });
    let cleanup_owned = bounded["cleanup"]
        .as_object()
        .is_some_and(|_| exact(&bounded["cleanup"]));
    let release_owned = status["lanes"]["budget"]["flow_state"]["waiting"]
        .as_array()
        .is_some_and(|rows| rows.iter().any(exact));
    assert!(
        demand_owned || flow_owned || cleanup_owned || release_owned,
        "PRODUCT: connected catch-up is structurally wedged at {held} of {expected} requested \
         rows: shipped status names no exact demand, flow, admission, dependency, cleanup or \
         release-edge owner for room {room} and peer {peer}; status: {out}"
    );
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
    let tmp = tempfile::tempdir().unwrap_or_else(|e| panic!("APPARATUS: no temp dir: {e}"));
    newcomer_reads_the_whole_history(tmp.path(), BACKLOG, PAGE);
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

/// How long the converged room idles while its sync rounds are counted.
const IDLE: Duration = Duration::from_secs(60);

/// One live round per hosted node plus every daemon archive job exceeds the pool floor by one.
/// This derives the required population from the product's two source-owned capacities.
const FX35_HOSTED_COUNT: usize = vox_core::node::history_budget::FLOW_STATE_CAPACITY
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
/// Source-derived hosted nodes on one daemon and one peer on another, in two quiet rooms, as this
/// proof stages them: the roots, every node (its root, its `--node`, its name, its fingerprint;
/// the hosted nodes first), the rooms, the two daemons (killed when dropped), when the posts were
/// made and the longest a post waited for a room applying its last change.
struct Staged {
    // The daemons first: they are killed before their directories go.
    _host_daemon: Daemon,
    peer_daemon: Option<Daemon>,
    host: std::path::PathBuf,
    everyone: Vec<(
        std::path::PathBuf,
        Option<&'static str>,
        &'static str,
        String,
    )>,
    rooms: Vec<String>,
    posted: Instant,
    waited: Duration,
    hosted: usize,
    live_hold: Option<std::path::PathBuf>,
    archive_hold: Option<std::path::PathBuf>,
    release_hold: Option<std::path::PathBuf>,
    pool_floor: Option<std::path::PathBuf>,
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

/// Create ordinary shipped archive demand on two hosted nodes. The peer posts beyond the live
/// window before either joins; each node then asks for the page below its oldest held row with
/// `vox room read --history older`. Returning means both shipped requests were accepted and the
/// daemon reported both archive jobs admitted together.
fn stage_two_archive_jobs(staged: &Staged) -> ArchiveStage {
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
    let room_selector = listed
        .lines()
        .find(|line| line.contains("pool-archive"))
        .and_then(|line| line.split_whitespace().next())
        .unwrap_or_else(|| panic!("APPARATUS: archive-pressure room is not listed: {listed}"))
        .to_owned();
    let room_id = room_id_as(peer_dir, *peer_node, peer_name, &room_selector);
    let room = vox_core::node::link::b32_encode(&room_id);

    // More rows than the live window leaves a real older page. Derive the record count from
    // the product's live window and archive-job count; large bodies are not this pressure stage.
    let archive_rows =
        vox_core::log::history::MAX_PAGE_ENTRIES + vox_core::node::history_budget::ARCHIVE_JOBS;
    for index in 0..archive_rows {
        let body = format!("archive-pressure-{index} ");
        stage_post(peer_dir, *peer_node, peer_name, &room, &body);
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
            // The live window counts raw author positions, including hidden controls.
            // A person's actual readable Content cursor is the page boundary; waiting for
            // exactly128 visible rows can never establish that boundary reliably.
            if let Some(oldest) = rows.iter().find(|row| {
                row["text"]
                    .as_str()
                    .is_some_and(|text| text.starts_with("archive-pressure-"))
            }) {
                break oldest["entry_hash"]
                    .as_str()
                    .unwrap_or_else(|| {
                        panic!("APPARATUS: {name}'s oldest archive-pressure row has no entry_hash")
                    })
                    .to_owned();
            }
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

    let expected: BTreeSet<&str> = staged.everyone[..vox_core::node::history_budget::ARCHIVE_JOBS]
        .iter()
        .map(|(_, _, _, fingerprint)| fingerprint.as_str())
        .collect();
    loop {
        let shown = fx35_synced(&staged.host, Some(FX35_HOSTED[0]));
        let value: serde_json::Value = serde_json::from_str(&shown.status).unwrap_or_default();
        let archives: BTreeSet<&str> = value["lanes"]["budget"]["archive_nodes"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(serde_json::Value::as_str)
            .collect();
        if archives == expected {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }

    // Bind the later forced-disconnect verdict to the two exact public operations accepted above.
    // This observation happens before the connection is stopped and before either held worker is
    // released; it cannot repair the later missing-owner defect.
    let mut owners = BTreeMap::new();
    for (dir, node, name, _) in &staged.everyone[..vox_core::node::history_budget::ARCHIVE_JOBS] {
        loop {
            let (ok, out, err) = vox(
                dir,
                &as_node(
                    &["room", "read", &room, "--history", "status", "--json"],
                    *node,
                ),
                None,
            );
            assert!(
                ok,
                "PRODUCT: {name}'s accepted archive request could not be observed: {out}{err}"
            );
            let reply: HistoryDemandReply = serde_json::from_str(&out).unwrap_or_else(|error| {
                panic!("PRODUCT: {name}'s archive status was not valid JSON ({error}): {out}")
            });
            if matches!(
                reply.status.phase,
                vox_core::node::api::HistoryDemandPhase::Preparing
            ) {
                std::thread::sleep(Duration::from_millis(20));
                continue;
            }
            let hex = |bytes: &[u8]| {
                bytes
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>()
            };
            assert!(
                reply.schema == "vox.room.history/1"
                    && reply.status.room == room_id
                    && reply.instance == hex(&reply.status.instance)
                    && reply.status.request.is_some()
                    && reply.request == reply.status.request.as_ref().map(|id| hex(id))
                    && reply.status.author.is_some()
                    && reply.status.head.is_some()
                    && matches!(
                        reply.status.phase,
                        vox_core::node::api::HistoryDemandPhase::Pending
                    ),
                "APPARATUS: {name}'s Older did not establish one held Pending archive operation: \
                 {out}"
            );
            let request = reply.request.expect("checked archive request");
            owners.insert(
                *name,
                ArchiveOwner {
                    room: room_id,
                    instance: reply.instance,
                    request,
                    author: reply.status.author,
                    head: reply.status.head,
                },
            );
            break;
        }
    }
    ArchiveStage { room, owners }
}

/// Stage [`HOSTED`] on one `vox daemon --no-node` (each made Ready with `vox node unlock`) and
/// bob on a daemon of his own; trust in every direction before anyone posts; [`QUIET_ROOMS`]
/// made by the first hosted node and joined by every other node; one post each in each room.
fn stage_hosted_nodes(
    hosted: &'static [&'static str],
    hold_live_jobs: bool,
    single_foreground_job: bool,
    disable_tick_schedule: bool,
) -> Staged {
    if single_foreground_job {
        assert_eq!(
            hosted,
            FX35_WAKE_HOSTED.as_slice(),
            "APPARATUS: one-foreground fixture requires the exact two reader topology"
        );
        assert_eq!(
            hosted.len(),
            QUIET_ROOMS.len(),
            "APPARATUS: each strict foreground reader requires its own Bob-only room"
        );
    }
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
    let live_hold = hold_live_jobs.then(|| root.join("hold-live-job"));
    let archive_hold = hold_live_jobs.then(|| root.join("hold-archive-job"));
    let release_hold = hold_live_jobs.then(|| root.join("hold-flow-release"));
    let pool_floor = hold_live_jobs.then(|| root.join("flow-state-floor"));
    let live_hold_text = live_hold
        .as_ref()
        .map(|path| path.to_string_lossy().into_owned());
    let archive_hold_text = archive_hold
        .as_ref()
        .map(|path| path.to_string_lossy().into_owned());
    let release_hold_text = release_hold
        .as_ref()
        .map(|path| path.to_string_lossy().into_owned());
    let pool_floor_text = pool_floor
        .as_ref()
        .map(|path| path.to_string_lossy().into_owned());
    let mut env: Vec<(&str, &str)> = vec![("VOX_TEST_KEYCHAIN", keychain.as_str())];
    if disable_tick_schedule {
        env.push(("VOX_TEST_DISABLE_TICK_SCHEDULE", "1"));
    }
    if let Some(path) = live_hold_text.as_deref() {
        env.push(("VOX_TEST_HOLD_LIVE_JOB_FILE", path));
        // The full-pool fixture accepts either actual foreground lane. The strict one-job wake
        // fixture must keep Control free so its requested Live worker can reach this barrier.
        if !single_foreground_job {
            env.push(("VOX_TEST_HOLD_CONTROL_JOB_FILE", path));
        }
    }
    if let Some(path) = archive_hold_text.as_deref() {
        env.push(("VOX_TEST_HOLD_ARCHIVE_JOB_FILE", path));
    }
    if let Some(path) = release_hold_text.as_deref() {
        env.push(("VOX_TEST_HOLD_FLOW_RELEASE_FILE", path));
    }
    if let Some(path) = pool_floor_text.as_deref() {
        env.push(("VOX_TEST_FLOW_STATE_FLOOR_FILE", path));
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
    let peer_daemon = if disable_tick_schedule {
        daemon_env(&peer, "peer", &[("VOX_TEST_DISABLE_TICK_SCHEDULE", "1")])
    } else {
        daemon(&peer, "peer")
    };
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
    // Full delivery uses the original clique. The separate strict-FG fixture gives each
    // reader a Bob-only room: a sibling server must not need the same FG1 to answer HAVE.
    let mut rooms = Vec::with_capacity(QUIET_ROOMS.len());
    for (index, name) in QUIET_ROOMS.into_iter().enumerate() {
        let maker_name = if single_foreground_job {
            hosted[index]
        } else {
            hosted[0]
        };
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
            if *node == maker || (single_foreground_job && node.is_some()) {
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
    let posted = Instant::now();
    let mut waited = Duration::ZERO;
    for (index, room) in rooms.iter().enumerate() {
        for (dir, node, name, _) in &everyone {
            if single_foreground_job && node.is_some_and(|node| node != hosted[index]) {
                continue;
            }
            let text = format!("{name} is here");
            waited = waited.max(stage_post(dir, *node, name, room, &text));
        }
    }
    eprintln!(
        "[delivery] all {} posts accepted across {} identities and {} rooms; actual member reads follow",
        if single_foreground_job { 2 * rooms.len() } else { everyone.len() * rooms.len() },
        everyone.len(),
        rooms.len()
    );
    Staged {
        _host_daemon: host_daemon,
        peer_daemon: Some(peer_daemon),
        host,
        everyone,
        rooms,
        posted,
        waited,
        hosted: hosted.len(),
        live_hold,
        archive_hold,
        release_hold,
        pool_floor,
        _tmp: tmp,
    }
}

/// Every member reads every other's post. Semantic completion and the product's own ownership
/// invariants decide the verdict; elapsed time belongs only to the external APPARATUS deadman.
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
        // FX-35's park mutant must fail a structural product assertion, not wait for the
        // apparatus watchdog: in the same shipped status document, this node's charge count
        // is exactly its running controller Flows and the daemon total is exactly the by-node sum.
        for (dir, node, name, fingerprint) in everyone {
            let shown = fx35_synced(dir, *node);
            let value: serde_json::Value =
                serde_json::from_str(&shown.status).unwrap_or_else(|error| {
                    panic!(
                        "PRODUCT: {name}'s flow-state status was not JSON during convergence: \
                             {error}: {}",
                        shown.status
                    )
                });
            let pool = &value["lanes"]["budget"]["flow_state"];
            // The controller's actual worker slots are independent of the budget pool's
            // charge ledger. Comparing those catches `Flow::park` retaining a charge; port
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
/// means a parked flow retained one. Each comparison uses the same node's single status
/// snapshot. Daemon-wide Control jobs also serve incoming requests and do not identify parked
/// outbound Flow ownership.
#[cfg(feature = "optional-proofs")]
fn parked_flow_charge_discriminator(staged: &Staged) {
    for (dir, node, name, fingerprint) in &staged.everyone {
        let shown = fx35_synced(dir, *node);
        let value: serde_json::Value = serde_json::from_str(&shown.status).unwrap_or_else(|e| {
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
    }
}

/// The gates a start attempt can end at, in the order the daemon tests them (ADR-038 FX-35).
const START_REASONS: [&str; 10] = [
    "room_busy",
    "archive_budget_busy",
    "control_budget_busy",
    "live_lane_busy",
    "no_outbound_slot",
    "flow_state_node_busy",
    "flow_state_pool_full",
    "flow_state_pool_overcommitted",
    "flow_state_owner_missing",
    "flow_state_order_exhausted",
];

/// User-visible health messages for this exact room, from one shipped status snapshot.
#[cfg(feature = "optional-proofs")]
fn room_health_messages<'a>(status: &'a serde_json::Value, room: &str) -> Vec<&'a str> {
    let stale = format!("room-stale:{room}");
    let retained = format!("room-flow-state-pool:{room}");
    status["unhealthy"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|health| {
            health["key"]
                .as_str()
                .is_some_and(|key| key == stale || key == retained)
        })
        .filter_map(|health| health["message"].as_str())
        .collect()
}

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
    child: std::sync::Mutex<Child>,
    reader: Option<std::thread::JoinHandle<()>>,
    lines: std::sync::mpsc::Receiver<(Instant, Result<String, String>)>,
    stderr_path: std::path::PathBuf,
    public_command: String,
}

#[cfg(feature = "optional-proofs")]
impl TailObserver {
    fn attach(dir: &Path, node: Option<&str>, room: &str, since: Option<&str>) -> Self {
        let stderr = tempfile::Builder::new()
            .prefix("vox-tail-")
            .suffix(".stderr")
            .tempfile()
            .expect("APPARATUS: create retained tail stderr");
        let (stderr_file, stderr_path) =
            stderr.keep().expect("APPARATUS: preserve tail stderr file");
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
            .stderr(Stdio::from(stderr_file));
        let public_command = format!(
            "{:?} {:?}",
            command.get_program(),
            command.get_args().collect::<Vec<_>>()
        );
        let mut child = command
            .spawn()
            .unwrap_or_else(|error| panic!("APPARATUS: could not start room tail: {error}"));
        eprintln!(
            "[tail apparatus] pid={} command={} stderr={}",
            child.id(),
            public_command,
            stderr_path.display()
        );
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
            child: std::sync::Mutex::new(child),
            reader: Some(reader),
            lines,
            stderr_path,
            public_command,
        }
    }

    /// Observe only; EOF is not permission to wait for, restart or otherwise heal a tail.
    fn diagnostic(&self) -> String {
        let mut child = self
            .child
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let pid = child.id();
        let status = match child.try_wait() {
            Ok(Some(status)) => format!("naturally exited: {status}"),
            Ok(None) => "not exited at this observation".to_owned(),
            Err(error) => format!("exit status unavailable: {error}"),
        };
        let stderr = std::fs::read(&self.stderr_path)
            .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
            .unwrap_or_else(|error| format!("stderr read failed: {error}"));
        format!(
            "pid={pid}; command={}; {status}; stderr_file={}; stderr={stderr:?}",
            self.public_command,
            self.stderr_path.display()
        )
    }

    fn wait_for(&self, target: &str, who: &str, product: bool) {
        self.wait_for_after(target, who, product, None);
    }

    fn wait_for_after(&self, target: &str, who: &str, product: bool, after: Option<Instant>) {
        loop {
            match self.lines.recv() {
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
                    panic!(
                        "PRODUCT: {who}'s shipped room tail failed: {error}; {}",
                        self.diagnostic()
                    )
                }
                Err(error) if product => panic!(
                    "PRODUCT: {who}'s already-running shipped room tail ended without showing \
                     {target:?} from the exact release edge: {error}; {}",
                    self.diagnostic()
                ),
                Ok((_, Err(error))) => {
                    panic!(
                        "APPARATUS: {who}'s staging room tail failed: {error}; {}",
                        self.diagnostic()
                    )
                }
                Err(error) => panic!(
                    "APPARATUS: {who}'s staging room tail ended without showing {target:?}: \
                     {error}; {}",
                    self.diagnostic()
                ),
            }
        }
    }
}

#[cfg(feature = "optional-proofs")]
impl Drop for TailObserver {
    fn drop(&mut self) {
        let observed = self.diagnostic();
        let child = self
            .child
            .get_mut()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let _ = child.kill();
        let reaped = child.wait();
        eprintln!("[tail apparatus cleanup] before_cleanup={observed}; cleanup_wait={reaped:?}");
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}

#[cfg(feature = "optional-proofs")]
fn observe_flow_release_handoff(
    dir: &Path,
    node: Option<&str>,
    who: &str,
    wait_order: u64,
    room: &str,
    peer: &str,
) {
    loop {
        let shown = fx35_synced(dir, node);
        let status: serde_json::Value =
            serde_json::from_str(&shown.status).unwrap_or_else(|error| {
                panic!(
                    "PRODUCT: {who}'s release-edge status was not JSON ({error}): {}",
                    shown.status
                )
            });
        let continuation = status["lanes"]["budget"]["flow_state"]["waiting"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|continuation| continuation["order"] == wait_order);
        let admission = status["lanes"]["bounded"]["admissions"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|admission| admission["wait_order"] == wait_order);
        let Some(continuation) = continuation else {
            // Consuming the exact promise removes both records before the round becomes visible;
            // that is causal product progress, not a wall-clock inference.
            assert!(
                admission.is_none_or(|admission| admission["handed_off"] == true),
                "PRODUCT: {who}'s actor still retains flow-state admission {wait_order} for \
                 {room}/{peer} after its exact pool promise disappeared, but status says the \
                 release was not handed off: {}",
                shown.status
            );
            return;
        };
        if continuation["granted"] != true {
            let pool = &status["lanes"]["budget"]["flow_state"];
            let waiting = pool["waiting"].as_array().cloned().unwrap_or_default();
            let promised = waiting
                .iter()
                .filter(|candidate| candidate["granted"] == true)
                .count() as u64;
            let capacity_available = pool["in_use"]
                .as_u64()
                .zip(pool["limit"].as_u64())
                .is_some_and(|(in_use, limit)| in_use + promised < limit);
            let earliest_eligible = capacity_available.then(|| {
                waiting
                    .iter()
                    .filter(|candidate| candidate["granted"] != true)
                    .filter(|candidate| {
                        let Some(node) = candidate["node"].as_str() else {
                            return false;
                        };
                        let charged = pool["by_node"][node].as_u64().unwrap_or(u64::MAX);
                        let promised_here = waiting
                            .iter()
                            .filter(|other| {
                                other["granted"] == true && other["node"].as_str() == Some(node)
                            })
                            .count() as u64;
                        charged + promised_here
                            < vox_core::node::history_budget::BOUNDED_SYNC_RUNNING_SLOTS as u64
                    })
                    .filter_map(|candidate| candidate["order"].as_u64())
                    .min()
            });
            assert_ne!(
                earliest_eligible.flatten(),
                Some(wait_order),
                "PRODUCT: flow-state continuation {wait_order} for {who} ({room}/{peer}) is the \
                 earliest eligible retained Flow after capacity was released, but the pool did \
                 not grant and hand it to its actor: {}",
                shown.status
            );
            std::thread::sleep(Duration::from_millis(20));
            continue;
        }
        let admission = admission.unwrap_or_else(|| {
            panic!(
                "PRODUCT: flow-state continuation {wait_order} for {who} ({room}/{peer}) owns a \
                 release promise but the actor no longer reports its exact retained admission: \
                 {}",
                shown.status
            )
        });
        assert_eq!(
            admission["handed_off"], true,
            "PRODUCT: flow-state continuation {wait_order} for {who} ({room}/{peer}) owns the \
             earliest eligible release promise, but its actor did not receive that causal \
             handoff: {}",
            shown.status
        );
        return;
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
            let identity = std::fs::read_to_string(entry.path()).ok()?;
            let node = identity.lines().next()?;
            Some((actor, node.to_owned(), entry.path()))
        })
        .collect()
}

#[cfg(feature = "optional-proofs")]
type HeldFlowOwners = BTreeMap<(u64, String, String, String), usize>;

#[cfg(feature = "optional-proofs")]
fn charged_flow_hold_owners(hold: &Path) -> HeldFlowOwners {
    let mut owners = BTreeMap::new();
    for (actor, node, marker) in charged_flow_hold_entries(hold) {
        let identity = std::fs::read_to_string(&marker).unwrap_or_else(|error| {
            panic!(
                "APPARATUS: could not read flow-state hold marker {}: {error}",
                marker.display()
            )
        });
        let room = identity
            .lines()
            .find_map(|line| line.strip_prefix("room="))
            .unwrap_or_else(|| {
                panic!(
                    "APPARATUS: flow-state hold marker omitted its room: {}",
                    marker.display()
                )
            });
        let peer = identity
            .lines()
            .find_map(|line| line.strip_prefix("peer="))
            .unwrap_or_else(|| {
                panic!(
                    "APPARATUS: flow-state hold marker omitted its peer: {}",
                    marker.display()
                )
            });
        *owners
            .entry((actor, node, room.to_owned(), peer.to_owned()))
            .or_insert(0) += 1;
    }
    owners
}

#[cfg(feature = "optional-proofs")]
fn running_flow_owners(status: &serde_json::Value) -> HeldFlowOwners {
    let running = status["lanes"]["budget"]["flow_state"]["running"]
        .as_array()
        .expect("PRODUCT: flow-state running owners were not an array");
    let mut owners = BTreeMap::new();
    for owner in running {
        let actor = owner["actor"]
            .as_u64()
            .expect("PRODUCT: running flow-state owner omitted actor");
        let field = |name| {
            owner[name]
                .as_str()
                .unwrap_or_else(|| panic!("PRODUCT: running flow-state owner omitted {name}"))
                .to_owned()
        };
        *owners
            .entry((actor, field("node"), field("room"), field("peer")))
            .or_insert(0) += 1;
    }
    owners
}

#[cfg(feature = "optional-proofs")]
fn all_flow_state_charges_held(
    status: &serde_json::Value,
    shared_hold: &Path,
    archive_hold: &Path,
    scoped_room: Option<&str>,
) -> Option<HeldFlowOwners> {
    let shared = charged_flow_hold_owners(shared_hold);
    if let Some(room) = scoped_room {
        assert!(
            shared.keys().all(|(_, _, held_room, _)| held_room == room),
            "APPARATUS: scoped Control/Live barrier captured work outside pressure room {room}: \
             {shared:?}"
        );
    }
    let archive = charged_flow_hold_owners(archive_hold);
    if archive.values().sum::<usize>() != vox_core::node::history_budget::ARCHIVE_JOBS {
        return None;
    }
    let mut held = shared;
    for (owner, count) in archive {
        *held.entry(owner).or_insert(0) += count;
    }
    let running = running_flow_owners(status);
    (running == held).then_some(running)
}

#[cfg(feature = "optional-proofs")]
fn generation_accounting_keeps_actor_incarnations_exact(
    staged: &Staged,
    pressure_members: &[PressureMember],
    _archive_room: &str,
) {
    let (_, _, name, fingerprint) = &staged.everyone[vox_core::node::history_budget::ARCHIVE_JOBS];
    let name = *name;
    let nonce = staged
        ._tmp
        .path()
        .file_name()
        .expect("APPARATUS: fresh fixture nonce")
        .to_string_lossy();
    let scoped = |text: &str| format!("{text}-{nonce}");
    let (peer_dir, peer_node, peer_name, peer_fp) = &staged.everyone[staged.hosted];
    let room = &staged.rooms[0];
    let other_room = &staged.rooms[1];
    assert_ne!(
        room, other_room,
        "APPARATUS: physical restart proof needs two distinct actual rooms"
    );
    assert!(
        staged.pool_floor.as_ref().is_none_or(|path| !path.exists()),
        "APPARATUS: retiring-identity accounting cannot use a proof floor"
    );
    let hold = staged
        .live_hold
        .as_ref()
        .expect("APPARATUS: generation hold missing");
    let archive_hold = staged
        .archive_hold
        .as_ref()
        .expect("APPARATUS: Archive hold missing");
    assert!(
        !hold.exists() && !archive_hold.exists(),
        "APPARATUS: previous pressure holds are still installed"
    );

    // A plain fresh replay handshake makes the existing Bob tail ready without depending on
    // old structured warm posts or on the actor that this fixture will deliberately panic.
    let baseline = scoped("retirement-tail-baseline");
    stage_post(peer_dir, *peer_node, peer_name, other_room, &baseline);
    let (ok, out, err) = vox(
        peer_dir,
        &as_node(&["room", "read", other_room, "--json"], *peer_node),
        None,
    );
    assert!(ok, "APPARATUS: Bob baseline read failed: {out}{err}");
    let baseline_row = out
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            serde_json::from_str::<serde_json::Value>(line)
                .expect("APPARATUS: Bob baseline row JSON")
        })
        .find(|row| {
            row["schema"] == "vox.room.row/1"
                && row["room"] == *other_room
                && row["author"] == *peer_fp
                && row["text"] == baseline
                && row["owed"] == false
        })
        .expect("APPARATUS: Bob's exact plain baseline row is absent");
    let cursor = baseline_row["entry_hash"]
        .as_str()
        .expect("APPARATUS: baseline omitted actual hash");
    let tail = TailObserver::attach(peer_dir, *peer_node, other_room, Some(cursor));
    let handshake = scoped("retirement-tail-attached");
    stage_post(peer_dir, *peer_node, peer_name, other_room, &handshake);
    tail.wait_for(&handshake, peer_name, false);
    // Hold one actual ordinary quiet1 worker. The main two Archive recovery assertions have
    // already finished; no new Older is needed merely to construct an impossible overlap.
    for (_, _, marker) in charged_flow_hold_entries(hold) {
        std::fs::remove_file(marker).expect("APPARATUS: clear old generation marker");
    }
    let decoded = vox_core::node::link::b32_decode(room, "retirement held room")
        .expect("APPARATUS: retirement room is not a full ID");
    assert_eq!(
        vox_core::node::link::b32_encode(&decoded),
        *room,
        "APPARATUS: retirement room must be canonical"
    );
    let temporary = hold.with_extension("retirement-scope");
    std::fs::write(&temporary, format!("room={room}\n"))
        .expect("APPARATUS: write retirement room selector");
    std::fs::rename(&temporary, hold).expect("APPARATUS: publish retirement room selector");
    assert_eq!(
        std::fs::read_to_string(hold).expect("APPARATUS: read selector"),
        format!("room={room}\n"),
        "APPARATUS: retirement selector changed"
    );
    let target = scoped("generation-accounting-target");
    let (ok, out, err) = stage_post_once(peer_dir, *peer_node, room, &target);
    assert!(
        ok,
        "APPARATUS: one retirement target post refused: {out}{err}"
    );
    let (old_actor, held_owner) = loop {
        let shown = fx35_synced(&staged.host, Some(name));
        let status: serde_json::Value =
            serde_json::from_str(&shown.status).expect("PRODUCT: held generation status JSON");
        let running = &status["lanes"]["bounded"]["running"][0];
        if running["archive"] == false && running["room"] == *room {
            if let Some(actor) = running["actor"].as_u64() {
                let peer = running["peer"].as_str().expect("PRODUCT: held worker peer");
                if charged_flow_hold_owners(hold).get(&(
                    actor,
                    fingerprint.clone(),
                    room.clone(),
                    peer.to_owned(),
                )) == Some(&1)
                {
                    let owners: Vec<_> = status["lanes"]["budget"]["flow_state"]["running"]
                        .as_array()
                        .expect("PRODUCT: actual running owners")
                        .iter()
                        .filter(|owner| {
                            owner["actor"] == actor
                                && owner["node"] == *fingerprint
                                && owner["room"] == *room
                                && owner["peer"] == peer
                        })
                        .cloned()
                        .collect();
                    if owners.len() == 1 {
                        break (actor, owners[0].clone());
                    }
                }
            }
        }
        std::thread::sleep(Duration::from_millis(20));
    };

    // One accepted successor is a persistence obligation across physical teardown.
    // Its first-gate diagnosis is measured separately by the low-fanout U4 spike.
    let successor = scoped("generation-accounting-successor");
    let (ok, out, err) = stage_post_once(&staged.host, Some(name), other_room, &successor);
    assert!(
        ok,
        "APPARATUS: one pre-retirement local post refused: {out}{err}"
    );
    let (ok, out, err) = vox(
        &staged.host,
        &as_node(&["room", "post", room, FX35_GENERATION_PANIC], Some(name)),
        None,
    );
    assert!(
        !ok,
        "APPARATUS: marker did not panic selected actor: {out}{err}"
    );
    let lifecycle = || {
        let (ok, out, err) = vox_plain(&staged.host, &["node", "list"], None);
        assert!(
            ok,
            "APPARATUS: public node lifecycle list failed: {out}{err}"
        );
        let selected: Vec<_> = out
            .lines()
            .filter_map(|line| {
                let mut fields = line.split_whitespace();
                (fields.next() == Some(name)).then(|| fields.next().unwrap_or("").to_owned())
            })
            .collect();
        assert_eq!(
            selected.len(),
            1,
            "APPARATUS: selected node lifecycle line missing/duplicate: {out}"
        );
        selected[0].clone()
    };
    let retired = loop {
        let shown = fx35_synced(&staged.host, Some(FX35_HOSTED[0]));
        let status: serde_json::Value =
            serde_json::from_str(&shown.status).expect("PRODUCT: retiring accounting status JSON");
        let pool = &status["lanes"]["budget"]["flow_state"];
        let old = pool["actors"]
            .as_array()
            .expect("PRODUCT: pool actors")
            .iter()
            .find(|actor| actor["actor"] == old_actor && actor["node"] == *fingerprint);
        if old.is_some_and(|actor| actor["registered"] == false && actor["in_use"] == 1) {
            break status;
        }
        assert_ne!(
            lifecycle(),
            "Locked",
            "PRODUCT: selected node claims physical stop while its held worker has not retired"
        );
        std::thread::sleep(Duration::from_millis(20));
    };
    let pool = &retired["lanes"]["budget"]["flow_state"];
    let actors = pool["actors"].as_array().unwrap();
    let nodes: BTreeSet<_> = actors
        .iter()
        .map(|actor| {
            actor["node"]
                .as_str()
                .expect("PRODUCT: accounting actor omitted node")
        })
        .collect();
    let by_node = pool["by_node"]
        .as_object()
        .expect("PRODUCT: by_node object");
    let occupied = pool["occupied_by_node"]
        .as_object()
        .expect("PRODUCT: occupied_by_node object");
    let sum: u64 = actors
        .iter()
        .map(|actor| {
            actor["in_use"]
                .as_u64()
                .expect("PRODUCT: actor omitted charge")
        })
        .sum();
    let held_matches = pool["running"]
        .as_array()
        .expect("PRODUCT: running owners")
        .iter()
        .filter(|owner| **owner == held_owner)
        .count();
    assert!(nodes.len() == pressure_members.len()
        && by_node.keys().map(String::as_str).collect::<BTreeSet<_>>() == nodes
        && occupied.keys().map(String::as_str).collect::<BTreeSet<_>>() == nodes
        && by_node[fingerprint].as_u64() == Some(1)
        && occupied[fingerprint].as_u64() == Some(1)
        && held_matches == 1 && pool["running"].as_array().unwrap().len() as u64 == sum
        && pool["in_use"] == sum
        && by_node.values().filter_map(serde_json::Value::as_u64).sum::<u64>() == sum
        && pool["occupied"].as_u64() == Some(occupied.values()
            .filter_map(serde_json::Value::as_u64).sum::<u64>())
        && pool["limit"].as_u64() == Some((nodes.len()
            * vox_core::node::history_budget::BOUNDED_SYNC_RUNNING_SLOTS) as u64)
        && pool["retiring_nodes"].as_array().is_some_and(|retiring| retiring.iter()
            .any(|node| node == fingerprint)),
        "PRODUCT: shipped pool omitted the held retiring identity or its exact 2N accounting: {pool}");
    // PROPOSED PUBLIC BINDING: A's physical-lifecycle patch renders existing Detaching state;
    // for this known passphrase-protected saved profile, Locked appears only AFTER receipt.
    // This proposal is NOT executable until that product surface/source binding is accepted.
    // A causal user command, not a lucky snapshot before premature detach: the exact old
    // worker cannot finish while this file remains. This deliberate held-state request is
    // distinct from the ONE fresh unlock after actual teardown; neither command is retried.
    // First observe that this host processed retirement. Pool unregister precedes its
    // watcher. The old product's ellipsis is transitional staging ONLY, never completion or
    // an own-red for missing the new label. Protected Locked while this worker is held is
    // already a truthful user-level premature physical-stop failure.
    loop {
        match lifecycle().as_str() {
            "Ready" => std::thread::sleep(Duration::from_millis(20)),
            "Detaching" | "…" => break,
            "Locked" => panic!(
                "PRODUCT: selected node claims physical stop while its exact worker remains held"
            ),
            other => panic!("APPARATUS: unexpected pre-unlock retirement state {other:?}"),
        }
    }
    let blocked_args = attach::persistent_args(
        &staged.host,
        &["node", "unlock", name, "--passphrase-file", "-"],
        IDENTITY,
    );
    let blocked_args: Vec<&str> = blocked_args.iter().map(String::as_str).collect();
    let (ok, out, err) = vox_plain(&staged.host, &blocked_args, None);
    let shown = fx35_synced(&staged.host, Some(FX35_HOSTED[0]));
    let still: serde_json::Value =
        serde_json::from_str(&shown.status).expect("PRODUCT: held-state unlock status JSON");
    assert!(
        hold.exists()
            && charged_flow_hold_owners(hold).get(&(
                old_actor,
                fingerprint.clone(),
                room.clone(),
                held_owner["peer"].as_str().unwrap().to_owned()
            )) == Some(&1)
            && still["lanes"]["budget"]["flow_state"]["running"]
                .as_array()
                .is_some_and(|owners| owners.contains(&held_owner)),
        "APPARATUS: original real worker was not held through the blocked unlock: {still}"
    );
    let expected = format!("node {name}'s work is still stopping; try again once it has finished");
    assert!(!ok && format!("{out}{err}").contains(&expected),
        "PRODUCT: unlock while exact retired work is still held did not truthfully report StillDetaching: ok={ok}, {out}{err}");
    assert_eq!(
        lifecycle(),
        "Detaching",
        "PRODUCT: held retired node did not truthfully remain Detaching"
    );
    std::fs::remove_file(hold).expect("APPARATUS: release exact retired worker");
    loop {
        match lifecycle().as_str() {
            "Detaching" => std::thread::sleep(Duration::from_millis(20)),
            "Locked" => break,
            other => panic!("PRODUCT: physical teardown reported unexpected lifecycle {other:?}"),
        }
    }
    let shown = fx35_synced(&staged.host, Some(FX35_HOSTED[0]));
    let stopped: serde_json::Value =
        serde_json::from_str(&shown.status).expect("PRODUCT: physical-stop pool status JSON");
    let pool = &stopped["lanes"]["budget"]["flow_state"];
    assert!(
        !pool["actors"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|owner| owner["actor"] == old_actor)
            && pool["by_node"].get(fingerprint).is_none()
            && pool["limit"].as_u64()
                == Some(
                    ((pressure_members.len() - 1)
                        * vox_core::node::history_budget::BOUNDED_SYNC_RUNNING_SLOTS)
                        as u64
                ),
        "PRODUCT: completed physical teardown retained the old accounting owner: {pool}"
    );
    unlock(&staged.host, name); // ONE unlock, only after the real physical receipt.
    loop {
        let shown = fx35_synced(&staged.host, Some(name));
        let status: serde_json::Value =
            serde_json::from_str(&shown.status).expect("PRODUCT: replacement Ready status JSON");
        assert!(
            status["status"] == "Ready" && status["identity"] == *fingerprint,
            "PRODUCT: one post-teardown unlock did not restore the exact identity: {status}"
        );
        let preparing = status["preparing"]
            .as_array()
            .expect("PRODUCT: room preparations array");
        assert!(
            preparing
                .iter()
                .all(|pending| staged.rooms.iter().any(|room| pending["id"] == *room)),
            "APPARATUS: unexpected replacement room preparation: {status}"
        );
        if preparing.is_empty() {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    loop {
        let (ok, out, err) = vox(
            &staged.host,
            &as_node(&["room", "read", room], Some(name)),
            None,
        );
        assert!(
            ok,
            "PRODUCT: post-physical-stop ordinary read refused: {out}{err}"
        );
        if out.contains(&target) {
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    tail.wait_for(&successor, peer_name, true);
    let fresh = scoped("generation-post-physical-stop");
    let (ok, out, err) = stage_post_once(&staged.host, Some(name), other_room, &fresh);
    assert!(
        ok,
        "PRODUCT: one fresh post after physical stop/unlock refused: {out}{err}"
    );
    tail.wait_for(&fresh, peer_name, true);
    println!("[proof] retiring actor {old_actor} stayed in exact 2N accounting; actual worker release and physical stop preceded one fresh unlock/post/read; concurrent same-profile generations and NodeBusy are source-reviewed, not runtime claims");
}

// The original cold delivery population stays unchanged. A pressure sidecar can also supply
// the generation fixture's actual retained Live peer; these readers never join the Archive room.
#[cfg(feature = "optional-proofs")]
const PRESSURE_SIDECARS: [&str; vox_core::node::history_budget::ARCHIVE_JOBS] =
    ["pressure-one", "pressure-two"];

#[cfg(feature = "optional-proofs")]
type PressureMember = (
    std::path::PathBuf,
    Option<&'static str>,
    &'static str,
    String,
);

#[cfg(feature = "optional-proofs")]
struct PressureSidecars {
    members: Vec<PressureMember>,
    unrelated_rooms: BTreeMap<&'static str, String>,
    waiter: PressureMember,
    waiter_room: String,
    waiter_tail_cursor: String,
    waiter_tail_ready: String,
}

/// Apparatus topology, read from the selected shipped node: only Bob can own an external port.
#[cfg(feature = "optional-proofs")]
fn assert_directed_waiter_topology(
    status: &serde_json::Value,
    room: &str,
    isolated: &str,
    waiter: &str,
    bob: &str,
) {
    assert!(
        status["status"] == "Ready" && status["identity"] == waiter,
        "APPARATUS: directed waiter is not the expected Ready identity: {status}"
    );
    let rooms = status["rooms"]
        .as_array()
        .expect("APPARATUS: directed waiter rooms not an array");
    let ids: BTreeSet<_> = rooms.iter().filter_map(|row| row["id"].as_str()).collect();
    assert!(
        room != isolated && rooms.len() == 2 && ids == BTreeSet::from([room, isolated]),
        "APPARATUS: directed waiter must hold only its Bob room and isolated room: {rooms:?}"
    );
    for shown in rooms {
        let members: BTreeSet<_> = shown["members"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|member| member["id"].as_str())
            .collect();
        let expected = if shown["id"] == room {
            BTreeSet::from([waiter, bob])
        } else {
            BTreeSet::from([waiter])
        };
        assert_eq!(
            members, expected,
            "APPARATUS: directed waiter acquired another room peer: {shown}"
        );
        if shown["id"] == room {
            assert!(
                shown["members"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .any(|member| member["id"] == bob && member["trusted"] == true),
                "APPARATUS: directed waiter does not trust its exact Bob source: {shown}"
            );
        }
    }
    assert!(
        status["lanes"]["ports"]
            .as_array()
            .into_iter()
            .flatten()
            .all(|port| port["room"] == room && port["peer"] == bob),
        "APPARATUS: directed waiter has an external port other than its Bob room: {}",
        status["lanes"]
    );
}

#[cfg(feature = "optional-proofs")]
fn stage_pressure_sidecars(staged: &Staged, holder_room: &str, nonce: &str) -> PressureSidecars {
    let (peer_dir, peer_node, peer_name, peer_fp) = &staged.everyone[staged.hosted];
    let waiter_name = *PRESSURE_SIDECARS
        .last()
        .expect("APPARATUS: no directed pressure sidecar");
    let mut members = Vec::new();
    let mut unrelated_rooms = BTreeMap::new();
    let mut waiter = None;
    let mut waiter_room = None;
    let mut waiter_tail_cursor = None;
    let mut waiter_tail_ready = None;
    for name in PRESSURE_SIDECARS {
        let (ok, fp, err) = vox(&staged.host, &["id", "--node", name], None);
        assert!(
            ok,
            "APPARATUS: pressure sidecar {name} identity failed: {fp}{err}"
        );
        let fp = fp.trim().to_owned();
        unlock(&staged.host, name);
        attached_as(&staged.host, "host", Some(name));
        for (dir, node, target, label) in [
            (&staged.host, Some(name), peer_fp.as_str(), *peer_name),
            (peer_dir, *peer_node, fp.as_str(), name),
        ] {
            let (ok, out, err) = vox(
                dir,
                &as_node(&["trust", "add", target, "--name", label], node),
                None,
            );
            assert!(
                ok,
                "APPARATUS: pressure sidecar {name} mutual trust failed: {out}{err}"
            );
        }
        let room = if name == waiter_name {
            let suffix: String = nonce
                .chars()
                .filter(char::is_ascii_alphanumeric)
                .map(|character| character.to_ascii_lowercase())
                .collect();
            assert!(
                !suffix.is_empty(),
                "APPARATUS: directed room nonce has no legal characters"
            );
            let alias = format!("directed-pressure-{suffix}");
            let (ok, out, err) = vox(
                peer_dir,
                &as_node(
                    &["room", "create", "--passphrase-file", "-", "--name", &alias],
                    *peer_node,
                ),
                Some(&format!("{ROOMPASS}\n")),
            );
            assert!(
                ok,
                "APPARATUS: Bob's dedicated pressure room failed: {out}{err}"
            );
            vox_core::node::link::b32_encode(&room_id_as(peer_dir, *peer_node, peer_name, &alias))
        } else {
            holder_room.to_owned()
        };
        let (ok, link, err) = vox(
            peer_dir,
            &as_node(&["room", "link", &room], *peer_node),
            None,
        );
        assert!(
            ok,
            "APPARATUS: pressure sidecar room link failed: {link}{err}"
        );
        let link = link
            .lines()
            .find(|line| line.starts_with("vox://"))
            .unwrap_or(link.trim());
        let (ok, out, err) = vox(
            &staged.host,
            &as_node(
                &["room", "join", "--passphrase-file", "-", link],
                Some(name),
            ),
            Some(&format!("{ROOMPASS}\n")),
        );
        assert!(
            ok,
            "APPARATUS: pressure sidecar {name} join failed: {out}{err}"
        );
        let own_name = format!("{name}-isolated");
        let (ok, out, err) = vox(
            &staged.host,
            &as_node(
                &[
                    "room",
                    "create",
                    "--passphrase-file",
                    "-",
                    "--name",
                    &own_name,
                ],
                Some(name),
            ),
            Some(&format!("{ROOMPASS}\n")),
        );
        assert!(ok, "APPARATUS: {name}'s unrelated room failed: {out}{err}");
        let own_room = vox_core::node::link::b32_encode(&room_id_as(
            &staged.host,
            Some(name),
            name,
            &own_name,
        ));
        unrelated_rooms.insert(name, own_room.clone());
        let source_ready = format!("{name}-source-ready-{nonce}");
        let reader_ready = format!("{name}-reader-ready-{nonce}");
        stage_post(peer_dir, *peer_node, peer_name, &room, &source_ready);
        // Save a readable arrival BEFORE the later own baseline append. A tail resumed from
        // this exact hash can prove it subscribed by replaying that later baseline, without
        // another post while the full pool is held.
        let source_cursor = loop {
            let (ok, out, err) = vox(
                &staged.host,
                &as_node(&["room", "read", &room, "--json"], Some(name)),
                None,
            );
            assert!(
                ok,
                "APPARATUS: {name}'s baseline JSON read refused: {out}{err}"
            );
            let rows: Vec<serde_json::Value> = out
                .lines()
                .filter(|line| !line.trim().is_empty())
                .map(|line| {
                    serde_json::from_str(line).unwrap_or_else(|error| {
                        panic!("APPARATUS: sidecar baseline row was not JSON ({error}): {line}")
                    })
                })
                .collect();
            if let Some(hash) = rows
                .iter()
                .find(|row| {
                    row["schema"] == "vox.room.row/1"
                        && row["room"] == room
                        && row["author"] == *peer_fp
                        && row["text"] == source_ready
                        && row["owed"] == false
                })
                .and_then(|row| row["entry_hash"].as_str())
            {
                break hash.to_owned();
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        stage_post(&staged.host, Some(name), name, &room, &reader_ready);
        loop {
            let (ok, out, err) = vox(
                &staged.host,
                &as_node(&["room", "read", &room], Some(name)),
                None,
            );
            assert!(
                ok,
                "APPARATUS: {name}'s pressure readiness read refused: {out}{err}"
            );
            let (peer_ok, peer_out, peer_err) = vox(
                peer_dir,
                &as_node(&["room", "read", &room], *peer_node),
                None,
            );
            assert!(
                peer_ok,
                "APPARATUS: source's sidecar readiness read refused: {peer_out}{peer_err}"
            );
            if out.contains(&source_ready)
                && out.contains(&reader_ready)
                && peer_out.contains(&reader_ready)
            {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let member = (staged.host.clone(), Some(name), name, fp.clone());
        if name == waiter_name {
            let shown = fx35_synced(&staged.host, Some(name));
            let status: serde_json::Value = serde_json::from_str(&shown.status)
                .expect("APPARATUS: directed waiter status was not JSON");
            assert_directed_waiter_topology(&status, &room, &own_room, &fp, peer_fp);
            let (ok, out, err) = vox(&staged.host, &["node", "lock", name], None);
            assert!(
                ok,
                "APPARATUS: could not lock baselined directed waiter: {out}{err}"
            );
            eprintln!("[proof] directed waiter baselined and locked: node={name} room={room} peer={peer_fp} isolated={own_room}");
            waiter = Some(member.clone());
            waiter_room = Some(room);
            waiter_tail_cursor = Some(source_cursor);
            waiter_tail_ready = Some(reader_ready);
        }
        members.push(member);
    }
    PressureSidecars {
        members,
        unrelated_rooms,
        waiter: waiter.expect("APPARATUS: directed waiter was not staged"),
        waiter_room: waiter_room.expect("APPARATUS: directed waiter room was not staged"),
        waiter_tail_cursor: waiter_tail_cursor.expect("APPARATUS: directed tail cursor missing"),
        waiter_tail_ready: waiter_tail_ready.expect("APPARATUS: directed tail readiness missing"),
    }
}

#[cfg(feature = "optional-proofs")]
#[derive(Clone)]
struct PressureContinuation {
    name: &'static str,
    observed: Instant,
    order: u64,
    identity: serde_json::Value,
    root: String,
}

#[cfg(feature = "optional-proofs")]
fn pressure_continuation(
    status: &serde_json::Value,
    name: &'static str,
    node: &str,
    room: &str,
    peer: &str,
) -> Option<PressureContinuation> {
    let admission = status["lanes"]["bounded"]["admissions"]
        .as_array()?
        .iter()
        .find(|entry| entry["gate"] == "pool" && entry["room"] == room && entry["peer"] == peer)?;
    let order = admission["wait_order"]
        .as_u64()
        .expect("PRODUCT: PoolFull admission omitted order");
    let identity = status["lanes"]["budget"]["flow_state"]["waiting"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|entry| entry["order"] == order)
        .expect("PRODUCT: actor's PoolFull admission has no exact daemon continuation")
        .clone();
    assert_eq!(
        identity["node"], node,
        "PRODUCT: PoolFull continuation names another identity"
    );
    assert_eq!(
        identity["room"], room,
        "PRODUCT: PoolFull continuation names another room"
    );
    assert_eq!(
        identity["peer"], peer,
        "PRODUCT: PoolFull continuation names another peer"
    );
    for field in ["actor", "request", "instance"] {
        assert!(
            !identity[field].is_null(),
            "PRODUCT: PoolFull continuation omitted {field}"
        );
    }
    let retained = status["lanes"]["bounded"]["ready"]
        .as_array()
        .into_iter()
        .flatten()
        .chain(
            status["lanes"]["bounded"]["deferred"]
                .as_array()
                .into_iter()
                .flatten(),
        )
        .find(|flow| {
            flow["archive"] == false
                && ["actor", "request", "instance", "room", "peer"]
                    .iter()
                    .all(|field| flow[*field] == identity[*field])
        })
        .expect("PRODUCT: PoolFull discarded its exact foreground Flow instead of retaining it");
    Some(PressureContinuation {
        name,
        observed: Instant::now(),
        order,
        identity,
        root: retained["root"]
            .as_str()
            .expect("PRODUCT: retained Flow omitted root")
            .to_owned(),
    })
}

#[cfg(feature = "optional-proofs")]
fn assert_pressure_identity(record: &serde_json::Value, owner: &PressureContinuation) {
    for field in ["actor", "node", "request", "instance", "room", "peer"] {
        assert_eq!(
            record[field], owner.identity[field],
            "PRODUCT: release continuation {} changed its exact {field}",
            owner.order
        );
    }
}

/// **More than eight hosted nodes read each other, and the flow-state pool holds no port**
/// (ADR-038 FX-35; #986): [`FX35_HOSTED`] on one daemon and bob on another, two rooms, trust in every
/// direction, one post each. Every member MUST eventually read every other; only the apparatus
/// watchdog bounds the run, never the product verdict. Then `vox status --json` on every node
/// MUST show `lanes.budget.flow_state` with
/// `by_node` holding one member per node its daemon hosts, the asked node's member equal to its
/// ports with `round_running` and `in_use` the sum; and every port's last start in the contract's
/// words ([`start_words`]). Its limit is exactly the shared source constants'
/// `running slots × active-or-retiring identities`, not a copied count, so it is never full in the
/// production segment. A feature-gated apparatus file then temporarily selects that same
/// source-defined floor to reach the otherwise impossible retained path: PoolFull requires
/// `occupied == limit`; an unrelated hosted-identity registration enlarges the limit but does
/// not grant work; and, after a real charge release, another hosted node observes the exact
/// granted-but-unconsumed continuation included in `promised` and `occupied`.
///
/// Measured before the fix (main, 2026-10-20, four runs of five): the four hosted nodes' parked
/// hinted flows held all sixteen flow states, the inventory round that would have let them
/// resume could never start, and the four nodes read nobody's post in 300 s while the peer read
/// everyone; or a post was refused for 60 s while the room applied its last change.
///
/// Mutants, one per claim: `Flow::park` keeping its charge turns convergence PRODUCT red;
/// reporting PoolFull from `in_use` while a grant is promised turns the exact `occupied == limit`
/// assertion red; omitting promises from `occupied` turns the granted-but-unconsumed snapshot
/// PRODUCT-red; restoring `Pool::resize`'s handoff makes unrelated registration grant the exact
/// retained continuation and turns that assertion PRODUCT-red;
/// The pressure phase retains the actual selected foreground continuation; it does not claim
/// to manufacture a separate `RequiredOwner` dependency. Required/hint/Archive variants share
/// the reviewed Flow ownership path; the release mutant falsifies the independent U2 claim.
/// `scratchpad/mutant_fx35_release_wake.py` removes the synchronous actor handoff after granting
/// the earliest exact continuation; one shipped status snapshot then reports the same release
/// order `granted: true` and `handed_off: false`, immediately PRODUCT red before the already-
/// attached tail is consulted; dropping archive ownership turns the exact shipped archive
/// request's structural ownership assertion red; omitting the held retiring identity from
/// `Pool::resize` makes the actual distinct-identity 2N accounting assertion PRODUCT-red;
/// the ordinary first-gate diagnosis is covered by the separate low-fanout U4 spike.
/// Concurrent same-profile generations and NodeBusy
/// remain source-reviewed; this journey does not claim to run them.
/// removing the retained-room health attribution makes that exact room's shipped diagnosis
/// PRODUCT-red; unrelated-room exclusion requires the separate real-other-member spike.
/// Removing the PoolFull port reason makes the
/// full-pool admission's first-gate assertion PRODUCT-red; removing the
/// post-quiet need re-arm leaves the waiting node short of the named `re-armed` posts.
#[cfg(feature = "optional-proofs")]
#[test]
#[ignore = "two real vox daemons, one hosting more than eight nodes; optional, run it in release"]
fn hosted_nodes_read_each_other_and_the_flow_state_pool_holds_no_port() {
    test_knobs::require(&[
        "VOX_TEST_FOREGROUND_JOBS",
        "VOX_TEST_HOLD_LIVE_JOB_FILE",
        "VOX_TEST_HOLD_CONTROL_JOB_FILE",
        "VOX_TEST_HOLD_ARCHIVE_JOB_FILE",
        "VOX_TEST_HOLD_FLOW_RELEASE_FILE",
        "VOX_TEST_FLOW_STATE_FLOOR_FILE",
        "VOX_TEST_DISABLE_TICK_SCHEDULE",
        "VOX_TEST_PANIC_ON_TEXT",
        "VOX_TEST_FX35_KEEP_CLOSED_POOL_ADMISSION",
    ]);
    watchdog::arm_for_setup(
        u32::try_from(
            QUIET_ROOMS.len() * (FX35_HOSTED.len() + FX35_WAKE_HOSTED.len())
                + vox_core::node::history_budget::ARCHIVE_JOBS
                + PRESSURE_SIDECARS.len(),
        )
        .expect("APPARATUS: join count does not fit the watchdog"),
        u32::try_from(FX35_HOSTED.len() + FX35_WAKE_HOSTED.len() + PRESSURE_SIDECARS.len() + 2)
            .expect("APPARATUS: unlock count does not fit the watchdog"),
    );
    let mut staged = stage_hosted_nodes(&FX35_HOSTED, true, false, true);
    converged(&staged);
    parked_flow_charge_discriminator(&staged);
    let converged_after = staged.posted.elapsed();
    // Attach before pressure. This pool phase observes the source-fenced exact release handoff
    // before consuming the tail's target; status/read/lifecycle commands also stage its owners.
    // Only foreground_release_wakes_without_a_tick forbids CLI requests after its release.
    let holder_room = &staged.rooms[0];
    let nonce = staged
        ._tmp
        .path()
        .file_name()
        .expect("APPARATUS: no staging nonce")
        .to_string_lossy()
        .into_owned();
    let directed = stage_pressure_sidecars(&staged, holder_room, &nonce);
    let waiter = directed.waiter.clone();
    let (waiter_dir, waiter_node, waiter_name, waiter_fp) = &waiter;
    let pressure_room = &directed.waiter_room;
    let mut unrelated_rooms = directed.unrelated_rooms.clone();
    let mut pressure_members = staged.everyone[..staged.hosted].to_vec();
    pressure_members.extend(directed.members.iter().cloned());
    let holder_members: Vec<_> = pressure_members
        .iter()
        .filter(|(_, _, name, _)| name != waiter_name)
        .cloned()
        .collect();
    let (room_reader_dir, room_reader_node, room_reader_name, _) = &staged.everyone[0];
    let holder_room_id = vox_core::node::link::b32_encode(&room_id_as(
        room_reader_dir,
        *room_reader_node,
        room_reader_name,
        holder_room,
    ));
    let (pressure_dir, pressure_node, pressure_name, pressure_peer) =
        &staged.everyone[staged.hosted];
    let pressure_room_id = vox_core::node::link::b32_encode(&room_id_as(
        pressure_dir,
        *pressure_node,
        pressure_name,
        pressure_room,
    ));
    let unrelated_id = vox_core::node::link::b32_encode(&room_id_as(
        room_reader_dir,
        *room_reader_node,
        room_reader_name,
        &staged.rooms[1],
    ));
    for (_, _, name, _) in &staged.everyone[..staged.hosted] {
        unrelated_rooms.insert(*name, unrelated_id.clone());
    }
    let mut pressure_tails: BTreeMap<&str, TailObserver> = holder_members
        .iter()
        .map(|(dir, node, name, _)| (*name, TailObserver::attach(dir, *node, holder_room, None)))
        .collect();
    let ready = format!("pool-release-tails-attached-{nonce}");
    stage_post(
        pressure_dir,
        *pressure_node,
        pressure_name,
        holder_room,
        &ready,
    );
    for (_, _, name, _) in &holder_members {
        pressure_tails
            .get(name)
            .expect("APPARATUS: holder tail disappeared")
            .wait_for(&ready, name, false);
    }
    // Hold two real shipped archive requests at their admitted jobs. The separate proof-only
    // archive barrier is installed before either request, so observing both admissions proves
    // they cannot finish before live pressure reaches the seventeenth reservation. A fresh
    // Content post by the peer then makes one live round eligible on every hosted node. Body
    // size does not choose the lane; these barriers stage running flow-state ownership.
    // The barriers hold already-admitted jobs. Control and Live share one canonical-room selector:
    // a foreground/hint Flow may truthfully choose either lane, and every actual charge must stay
    // held until the one deliberate release. A feature-gated apparatus file temporarily asks
    // the pool to use its own source-defined floor: fourteen foreground plus the daemon's two
    // source-owned archive jobs then reaches the otherwise impossible retained path without a
    // copied count. The ordinary sidecar supplements quiet1 holders; the dedicated sidecar is
    // already baselined with Bob in a separate two-member room and stays locked until the exact
    // held population is captured. It cannot reserve a competing quiet1 port. Removing the file
    // restores actual production identity accounting.
    let resize_probe = "fx35-resize-probe";
    let pool_floor = staged
        .pool_floor
        .as_ref()
        .expect("APPARATUS: flow-state floor path was not staged");
    std::fs::File::create(pool_floor).unwrap_or_else(|error| {
        panic!(
            "APPARATUS: could not create {}: {error}",
            pool_floor.display()
        )
    });
    let (ok, _, err) = vox(&staged.host, &["id", "--node", resize_probe], None);
    assert!(ok, "APPARATUS: could not create resize probe: {err}");
    unlock(&staged.host, resize_probe);
    attached_as(&staged.host, "host", Some(resize_probe));
    let (ok, out, err) = vox(&staged.host, &["node", "lock", resize_probe], None);
    assert!(
        ok,
        "APPARATUS: could not lock resize probe after applying the source-defined pool floor: \
         {out}{err}"
    );
    let floored = fx35_synced(&staged.host, Some(FX35_HOSTED[0]));
    let floored: serde_json::Value = serde_json::from_str(&floored.status)
        .expect("PRODUCT: source-defined pool-floor status was not JSON");
    assert_eq!(
        floored["lanes"]["budget"]["flow_state"]["limit"],
        vox_core::node::history_budget::FLOW_STATE_CAPACITY as u64,
        "APPARATUS: the feature-gated pool floor was not staged: {}",
        floored["lanes"]["budget"]["flow_state"]
    );
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
    let archive = stage_two_archive_jobs(&staged);
    let archive_room = archive.room.clone();
    let hold = staged
        .live_hold
        .as_ref()
        .expect("APPARATUS: flow-state pressure hold path was not staged");
    let pressure_selector = format!("room={holder_room_id}\n");
    let scoped_hold = hold.with_extension("pressure-room");
    std::fs::write(&scoped_hold, pressure_selector.as_bytes()).unwrap_or_else(|error| {
        panic!(
            "APPARATUS: could not write scoped Control/Live hold {}: {error}",
            scoped_hold.display()
        )
    });
    std::fs::rename(&scoped_hold, hold).unwrap_or_else(|error| {
        panic!(
            "APPARATUS: could not publish scoped Control/Live hold {}: {error}",
            hold.display()
        )
    });
    assert_eq!(
        std::fs::read_to_string(hold).expect("APPARATUS: read pressure-room hold selector"),
        pressure_selector,
        "APPARATUS: pressure-room hold selector bytes changed"
    );
    stage_post(
        pressure_dir,
        *pressure_node,
        pressure_name,
        holder_room,
        &format!("pool-pressure-payload-{nonce}"),
    );
    let pressure_target = format!("pool-pressure-landed-{nonce}");
    let mut pressure_target_posted = false;
    let mut pool_full_seen = false;
    let mut live_pool_full: Option<PressureContinuation> = None;
    let mut frozen_running: Option<HeldFlowOwners> = None;
    let mut most_pressure = 0;
    let mut pressure_staged = false;
    let observed = 'pressure: loop {
        let scan = if pressure_target_posted {
            std::slice::from_ref(&waiter)
        } else {
            holder_members.as_slice()
        };
        for (dir, node, name, _) in scan {
            let shown = fx35_synced(dir, *node);
            let v: serde_json::Value = serde_json::from_str(&shown.status).unwrap_or_default();
            let pool = &v["lanes"]["budget"]["flow_state"];
            let in_use = pool["in_use"].as_u64().unwrap_or(0);
            let archives = v["lanes"]["budget"]["archive_nodes"]
                .as_array()
                .map_or(0, Vec::len);
            let bounded = &v["lanes"]["bounded"];
            let full_ports: BTreeSet<(String, String)> = bounded["admissions"]
                .as_array()
                .into_iter()
                .flatten()
                .filter(|admission| admission["gate"] == "pool")
                .filter_map(|admission| {
                    Some((
                        admission["room"].as_str()?.to_owned(),
                        admission["peer"].as_str()?.to_owned(),
                    ))
                })
                .collect();
            if !full_ports.is_empty() {
                assert_eq!(
                    pool["occupied"], pool["limit"],
                    "PRODUCT: {name} refused a legal flow-state reservation as PoolFull while \
                     shipped status reported unoccupied capacity: {}",
                    shown.status
                );
                for (room, peer) in &full_ports {
                    assert!(
                        v["lanes"]["ports"]
                            .as_array()
                            .into_iter()
                            .flatten()
                            .any(|port| {
                                port["room"] == *room
                                    && port["peer"] == *peer
                                    && port["start_reason"] == "flow_state_pool_full"
                            }),
                        "PRODUCT: {name}'s exact pool admission {room}/{peer} did not name the \
                         first failed gate as flow_state_pool_full: {}",
                        shown.status
                    );
                }
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
                    > vox_core::node::history_budget::FLOW_STATE_CAPACITY as u64
                    || !full_ports.is_empty();
            }
            if !pressure_target_posted
                && in_use == vox_core::node::history_budget::FLOW_STATE_CAPACITY as u64
            {
                let Some(held) =
                    all_flow_state_charges_held(&v, hold, archive_hold, Some(&holder_room_id))
                else {
                    most_pressure = most_pressure.max(in_use);
                    continue;
                };
                assert_eq!(
                    pool["promised"], 0,
                    "APPARATUS: a promise preceded the initial exact held snapshot: {pool}"
                );
                assert_eq!(
                    held.values().sum::<usize>(),
                    vox_core::node::history_budget::FLOW_STATE_CAPACITY,
                    "APPARATUS: exact held owners did not fill the floor: {held:?}"
                );
                assert!(
                    !held.keys().any(|(_, node, _, _)| node == waiter_fp)
                        && !pool["actors"]
                            .as_array()
                            .into_iter()
                            .flatten()
                            .any(|actor| actor["node"] == *waiter_fp
                                && actor["registered"] == true),
                    "APPARATUS: locked spare owned capacity before capture: {pool}"
                );
                frozen_running = Some(held);
                eprintln!(
                    "[proof] exact holder population frozen independently of waiter: {}",
                    pool
                );
                unlock(waiter_dir, waiter_name);
                attached_as(waiter_dir, "directed-waiter", *waiter_node);
                // Ready owns the node before its remembered rooms finish reopening. Follow
                // only those exact source-owned public preparations; absence without one is
                // a staging fault, not permission to poll until some desired shape appears.
                let isolated = unrelated_rooms
                    .get(waiter_name)
                    .expect("APPARATUS: waiter isolated room missing");
                let expected = BTreeSet::from([pressure_room_id.as_str(), isolated.as_str()]);
                let shown = loop {
                    let shown = fx35_synced(waiter_dir, *waiter_node);
                    let shown: serde_json::Value = serde_json::from_str(&shown.status)
                        .expect("APPARATUS: reopened directed waiter status was not JSON");
                    assert!(
                        shown["status"] == "Ready" && shown["identity"] == *waiter_fp,
                        "APPARATUS: reopened waiter identity/state changed: {shown}"
                    );
                    let present: BTreeSet<_> = shown["rooms"]
                        .as_array()
                        .expect("APPARATUS: reopened waiter rooms missing")
                        .iter()
                        .map(|room| {
                            room["id"]
                                .as_str()
                                .expect("APPARATUS: open room id missing")
                        })
                        .collect();
                    let preparing: BTreeSet<_> = shown["preparing"]
                        .as_array()
                        .expect("APPARATUS: reopened waiter preparing list missing")
                        .iter()
                        .map(|room| {
                            room["id"]
                                .as_str()
                                .expect("APPARATUS: preparing room id missing")
                        })
                        .collect();
                    assert!(present.is_subset(&expected) && preparing.is_subset(&expected)
                        && expected.iter().all(|id| present.contains(id) || preparing.contains(id)),
                        "APPARATUS: expected directed rooms missing without exact preparation, or an extra room appeared: {shown}");
                    if preparing.is_empty() {
                        break shown;
                    }
                    std::thread::sleep(Duration::from_millis(20));
                };
                assert_directed_waiter_topology(
                    &shown,
                    &pressure_room_id,
                    unrelated_rooms
                        .get(waiter_name)
                        .expect("APPARATUS: waiter isolated room missing"),
                    waiter_fp,
                    pressure_peer,
                );
                assert!(shown["lanes"]["bounded"]["running"].as_array().into_iter().flatten()
                    .all(serde_json::Value::is_null),
                    "APPARATUS: reopened waiter already ran while all floor charges were held: {shown}");
                let tail = TailObserver::attach(
                    waiter_dir,
                    *waiter_node,
                    pressure_room,
                    Some(&directed.waiter_tail_cursor),
                );
                tail.wait_for(&directed.waiter_tail_ready, waiter_name, false);
                pressure_tails.insert(*waiter_name, tail);
                // This is the one measurement post. The two-member spare has only Bob's
                // external port, and its tail has actually replayed its saved readiness row.
                stage_post(
                    pressure_dir,
                    *pressure_node,
                    pressure_name,
                    pressure_room,
                    &pressure_target,
                );
                pressure_target_posted = true;
                eprintln!("[proof] directed target posted once after exact held capture: waiter={waiter_name} room={pressure_room_id}");
                continue 'pressure;
            }
            if !pressure_target_posted {
                most_pressure = most_pressure.max(in_use);
                continue;
            }
            assert_directed_waiter_topology(
                &v,
                &pressure_room_id,
                unrelated_rooms
                    .get(waiter_name)
                    .expect("APPARATUS: waiter isolated room missing"),
                waiter_fp,
                pressure_peer,
            );
            let held = all_flow_state_charges_held(&v, hold, archive_hold, Some(&holder_room_id))
                .expect(
                "APPARATUS: held population escaped while waiting for the directed Bob admission",
            );
            assert_eq!(
                frozen_running
                    .as_ref()
                    .expect("APPARATUS: holder snapshot missing"),
                &held,
                "APPARATUS: original held owners changed before directed admission"
            );
            assert_eq!(
                pool["promised"], 0,
                "APPARATUS: a release preceded the directed Bob admission: {pool}"
            );
            let fingerprint = pressure_members
                .iter()
                .find(|(_, _, candidate, _)| candidate == name)
                .expect("APPARATUS: pressure identity disappeared")
                .3
                .as_str();
            if let Some(owner) = pressure_continuation(
                &v,
                name,
                fingerprint,
                &pressure_room_id,
                &staged.everyone[staged.hosted].3,
            ) {
                assert!(
                    room_health_messages(&v, &pressure_room_id)
                        .iter()
                        .any(|message| message.contains("flow-state pool")),
                    "PRODUCT: retained pressure room has no exact flow-state pool health: {}",
                    v["unhealthy"]
                );
                // The own-only isolated room is skipped by StatusReport::diagnose.
                // Its empty messages do not prove unrelated-room pool attribution;
                // that user claim is to be measured by the separate external-member spike.
                assert_eq!(
                    pool["promised"], 0,
                    "APPARATUS: a release promise existed before the controlled release stage: \
                     {pool}"
                );
                assert_eq!(
                    pool["in_use"], pool["limit"],
                    "APPARATUS: the source-defined floor was not held entirely by running rounds: \
                     {pool}"
                );
                let Some(held) =
                    all_flow_state_charges_held(&v, hold, archive_hold, Some(&holder_room_id))
                else {
                    continue;
                };
                assert_eq!(
                    held.values().sum::<usize>(),
                    vox_core::node::history_budget::FLOW_STATE_CAPACITY,
                    "APPARATUS: the exact held owner multiset did not fill the source-defined pool: \
                     {held:?}"
                );
                assert_eq!(
                    frozen_running
                        .as_ref()
                        .expect("APPARATUS: pre-target held owner multiset was not captured"),
                    &held,
                    "APPARATUS: a charged owner changed after the one target publication"
                );
                eprintln!(
                    "[proof] exact foreground PoolFull owner={} root={} identity={}",
                    owner.name, owner.root, owner.identity
                );
                live_pool_full = Some(owner);
                most_pressure = most_pressure.max(in_use);
                break 'pressure most_pressure;
            }
            most_pressure = most_pressure.max(in_use);
        }
        if most_pressure > vox_core::node::history_budget::FLOW_STATE_CAPACITY as u64 {
            break most_pressure;
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    // A real connection close is an eligibility edge, not something the periodic scheduler may
    // notice later. Stop the exact peer behind the retained foreground Flow, wait until shipped
    // status says that member is disconnected, and require both actor admission and daemon pool
    // continuation to be gone in the same observation. Reconnection does not remove an
    // earlier local gate: a different held Live round can occupy the original node's slot.
    // Stage the later release claims on an ACTUAL currently eligible PoolFull owner instead.
    // This probe does not equate Flow allocation ids across intervening completion/supersession.
    if let Some(disconnected_owner) = live_pool_full.clone() {
        let owner = disconnected_owner.name;
        let disconnected_order = disconnected_owner.order;
        let disconnected_peer = disconnected_owner.identity["peer"]
            .as_str()
            .expect("PRODUCT: no exact peer")
            .to_owned();
        let (owner_dir, owner_node, _, _) = pressure_members
            .iter()
            .find(|(_, _, candidate, _)| *candidate == owner)
            .expect("APPARATUS: PoolFull owner disappeared before disconnect");
        staged
            .peer_daemon
            .take()
            .expect("APPARATUS: peer daemon disappeared before disconnect")
            .stop();
        while member_connected_as(owner_dir, *owner_node, pressure_room, &disconnected_peer)
            != Some(false)
        {
            std::thread::yield_now();
        }
        let disconnected = fx35_synced(owner_dir, *owner_node);
        let disconnected_status: serde_json::Value = serde_json::from_str(&disconnected.status)
            .expect("PRODUCT: disconnected PoolFull status was not JSON");
        let retained_by_actor = disconnected_status["lanes"]["bounded"]["admissions"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|admission| admission["wait_order"] == disconnected_order);
        let retained_by_pool = disconnected_status["lanes"]["budget"]["flow_state"]["waiting"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|continuation| continuation["order"] == disconnected_order);
        eprintln!(
            "[proof] FX-35 exact retained port disconnected: owner={owner} peer={disconnected_peer} order={disconnected_order}"
        );
        assert!(
            !retained_by_actor && !retained_by_pool,
            "PRODUCT [FX35 disconnected-pool-admission]: shipped status says peer \
             {disconnected_peer} is disconnected but still retains flow-state continuation \
             {disconnected_order}: {}",
            disconnected.status
        );

        let peer_root = &staged.everyone[staged.hosted].0;
        staged.peer_daemon = Some(daemon_env(
            peer_root,
            "peer-after-pool-disconnect",
            &[("VOX_TEST_DISABLE_TICK_SCHEDULE", "1")],
        ));
        attached_as(peer_root, "peer-after-pool-disconnect", None);
        while member_connected_as(owner_dir, *owner_node, pressure_room, &disconnected_peer)
            != Some(true)
        {
            std::thread::yield_now();
        }
        eprintln!(
            "[proof] FX-35 peer reconnected: original_owner={owner} peer={disconnected_peer}; selecting an actual eligible release owner"
        );
        live_pool_full = 'restaged: loop {
            for (dir, node, name, _) in std::slice::from_ref(&waiter) {
                let shown = fx35_synced(dir, *node);
                let status: serde_json::Value = serde_json::from_str(&shown.status)
                    .expect("PRODUCT: reconnected PoolFull status was not JSON");
                assert_directed_waiter_topology(
                    &status,
                    &pressure_room_id,
                    unrelated_rooms
                        .get(waiter_name)
                        .expect("APPARATUS: waiter isolated room missing"),
                    waiter_fp,
                    pressure_peer,
                );
                let still_held =
                    all_flow_state_charges_held(&status, hold, archive_hold, Some(&holder_room_id))
                        .expect(
                            "APPARATUS: a holder escaped before the directed reconnect admission",
                        );
                assert_eq!(
                    frozen_running
                        .as_ref()
                        .expect("APPARATUS: original holder snapshot missing"),
                    &still_held,
                    "APPARATUS: held owners changed before directed reconnect binding"
                );
                let fp = pressure_members
                    .iter()
                    .find(|(_, _, candidate, _)| candidate == name)
                    .expect("APPARATUS: reconnect identity disappeared")
                    .3
                    .as_str();
                if pressure_continuation(&status, name, fp, &pressure_room_id, &disconnected_peer)
                    .is_some()
                {
                    let pool = &status["lanes"]["budget"]["flow_state"];
                    assert_eq!(pool["occupied"], pool["limit"],
                        "PRODUCT: reconnected owner's actual PoolFull admission reports free capacity: {pool}");
                    assert!(status["lanes"]["ports"].as_array().into_iter().flatten().any(|port| {
                        port["room"] == pressure_room_id && port["peer"] == disconnected_peer
                            && port["start_reason"] == "flow_state_pool_full"
                    }), "PRODUCT: reconnected owner's exact PoolFull admission names another first gate: {}", status["lanes"]);
                    // The directed actor still has only Bob as a peer; rebind its current
                    // continuation after reconnect, without equating pre-disconnect Flow ids.
                    // Do not credit an old readable target as a future release consequence.
                    // A cached read stages user-visible absence, never absence of stored bytes.
                    let (ok, out, err) = vox(
                        dir,
                        &as_node(&["room", "read", pressure_room, "--json"], *node),
                        None,
                    );
                    assert!(
                        ok,
                        "APPARATUS: cannot establish {name}'s release-target absence: {out}{err}"
                    );
                    let rows: Vec<serde_json::Value> = out.lines()
                        .filter(|line| !line.trim().is_empty())
                        .map(|line| serde_json::from_str(line).unwrap_or_else(|error| {
                            panic!("APPARATUS: release-target absence read is not JSON ({error}): {line}")
                        })).collect();
                    assert!(
                        rows.iter().all(|row| row["schema"] == "vox.room.row/1"
                            && row["room"] == pressure_room_id
                            && row["entry_hash"].is_string()
                            && row["author"].is_string()
                            && row["text"].is_string()
                            && row["owed"].is_boolean()),
                        "APPARATUS: release-target absence read has invalid row shape: {out}"
                    );
                    assert!(!rows.iter().any(|row| row["author"] == disconnected_peer
                        && row["text"] == pressure_target && row["owed"] == false),
                        "APPARATUS: {name} already reads the pressure target before the selected release stage; no fresh post or changed head was issued: {out}");
                    // The read can process normal metadata/actor work. Bind ONE final status
                    // AFTER it, rather than requiring an earlier allocation/token to survive it.
                    let final_shown = fx35_synced(dir, *node);
                    let final_status: serde_json::Value = serde_json::from_str(&final_shown.status)
                        .expect("PRODUCT: final reconnected PoolFull status was not JSON");
                    let reconnected = pressure_continuation(&final_status, name, fp,
                        &pressure_room_id, &disconnected_peer).unwrap_or_else(|| {
                        panic!("APPARATUS: selected release ownership changed while establishing target absence; no new post or restaging retry was issued: {}", final_shown.status)
                    });
                    assert_ne!(
                        reconnected.order, disconnected_order,
                        "PRODUCT: reconnect reused the cancelled exact pool continuation order"
                    );
                    assert_eq!(reconnected.identity["granted"], false,
                        "APPARATUS: selected release continuation already had a grant before resize staging: {}", final_shown.status);
                    let final_pool = &final_status["lanes"]["budget"]["flow_state"];
                    assert_eq!(final_pool["occupied"], final_pool["limit"],
                        "PRODUCT: final selected PoolFull admission reports free capacity: {final_pool}");
                    assert_eq!(
                        final_pool["promised"], 0,
                        "APPARATUS: a real release preceded final owner binding: {final_pool}"
                    );
                    let final_running = all_flow_state_charges_held(
                        &final_status,
                        hold,
                        archive_hold,
                        Some(&holder_room_id),
                    )
                    .expect(
                        "APPARATUS: a running charge escaped its exact proof barrier before final \
                         owner binding",
                    );
                    assert_eq!(
                        frozen_running
                            .as_ref()
                            .expect("APPARATUS: initial held owner multiset was not captured"),
                        &final_running,
                        "APPARATUS: a running charge changed before final release-owner binding"
                    );
                    assert!(
                        final_status["lanes"]["ports"]
                            .as_array()
                            .into_iter()
                            .flatten()
                            .any(|port| {
                                port["room"] == pressure_room_id
                                    && port["peer"] == disconnected_peer
                                    && port["start_reason"] == "flow_state_pool_full"
                            }),
                        "PRODUCT: final selected PoolFull admission names another first gate: {}",
                        final_status["lanes"]
                    );
                    eprintln!("[proof] FX-35 actual release owner bound: owner={} root={} order={} identity={}",
                        reconnected.name, reconnected.root, reconnected.order, reconnected.identity);
                    break 'restaged Some(reconnected);
                }
            }
            std::thread::yield_now();
        };
    }
    // The exact pressure-room health assertion is complete. Unrelated-room exclusion
    // requires the focused external-member spike. While the exact
    // source-defined pool is still full and every charge is held, atomically widen the SAME
    // Control/Live barrier. After dynamic resize, fresh work in another room may reserve newly
    // exposed capacity; it must not finish and impersonate the later deliberate release.
    if live_pool_full.is_some() {
        let all_rooms_hold = hold.with_extension("all-rooms");
        std::fs::write(&all_rooms_hold, b"all\n").unwrap_or_else(|error| {
            panic!(
                "APPARATUS: could not write all-room Control/Live hold {}: {error}",
                all_rooms_hold.display()
            )
        });
        std::fs::rename(&all_rooms_hold, hold).unwrap_or_else(|error| {
            panic!(
                "APPARATUS: could not widen Control/Live hold {}: {error}",
                hold.display()
            )
        });
        assert_eq!(
            std::fs::read_to_string(hold).expect("APPARATUS: read all-room hold selector"),
            "all\n",
            "APPARATUS: all-room Control/Live hold bytes changed"
        );
    }
    if let Some(retained_owner) = &live_pool_full {
        let owner = &retained_owner.name;
        let wait_order = &retained_owner.order;
        let release_hold = staged
            .release_hold
            .as_ref()
            .expect("APPARATUS: flow-release hold path was not staged");
        std::fs::File::create(release_hold).unwrap_or_else(|error| {
            panic!(
                "APPARATUS: could not create {}: {error}",
                release_hold.display()
            )
        });
        std::fs::remove_file(pool_floor).unwrap_or_else(|error| {
            panic!(
                "APPARATUS: could not restore the dynamic pool at {}: {error}",
                pool_floor.display()
            )
        });
        // Registering an unrelated hosted identity changes only the pool's accounting limit.
        // It is not a running-round release and therefore cannot grant this retained Flow.
        unlock(&staged.host, resize_probe);
        attached_as(&staged.host, "host", Some(resize_probe));
        // This roomless actor cannot own a release continuation of its own. A pressure actor could
        // receive another grant and block inside the proof release barrier before answering Status.
        let (resized, resized_running) = loop {
            let shown = fx35_synced(&staged.host, Some(resize_probe));
            let status: serde_json::Value = serde_json::from_str(&shown.status)
                .expect("PRODUCT: post-resize status was not JSON");
            if let Some(held) = all_flow_state_charges_held(&status, hold, archive_hold, None) {
                break (status, held);
            }
            std::thread::yield_now();
        };
        let retained = resized["lanes"]["budget"]["flow_state"]["waiting"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|continuation| continuation["order"] == *wait_order)
            .unwrap_or_else(|| {
                panic!(
                    "PRODUCT: unrelated hosted-identity registration consumed or lost retained \
                     continuation {wait_order}: {}",
                    resized["lanes"]
                )
            });
        assert_pressure_identity(retained, retained_owner);
        assert_eq!(
            retained["granted"], false,
            "PRODUCT: unrelated hosted-identity registration granted retained continuation \
             {wait_order} without a running-round charge release: {}",
            resized["lanes"]
        );
        let resized_pool = &resized["lanes"]["budget"]["flow_state"];
        assert_eq!(
            resized_pool["promised"], 0,
            "PRODUCT: resize exposed a release promise without any running-round release: \
             {resized_pool}"
        );
        let frozen = frozen_running
            .as_ref()
            .expect("APPARATUS: initial held owner multiset was not captured");
        assert!(
            frozen
                .iter()
                .all(|(owner, count)| resized_running.get(owner).is_some_and(|now| now >= count)),
            "APPARATUS: an original held flow-state owner disappeared during resize"
        );
        let newly_held = resized_running
            .iter()
            .any(|(owner, count)| *count > frozen.get(owner).copied().unwrap_or(0));
        assert!(
            resized_pool["occupied"]
                .as_u64()
                .zip(resized_pool["limit"].as_u64())
                .is_some_and(|(occupied, limit)| occupied < limit)
                || newly_held,
            "PRODUCT: the unrelated registration neither exposed unused capacity nor admitted \
             new marker-held work while retained continuation {wait_order} stayed ungranted: \
             {resized_pool}"
        );
        eprintln!("[proof] FX-35 resize assertions completed: owner={owner} order={wait_order} remained ungranted");
    }
    std::fs::remove_file(hold)
        .unwrap_or_else(|error| panic!("APPARATUS: could not release {}: {error}", hold.display()));
    std::fs::remove_file(archive_hold).unwrap_or_else(|error| {
        panic!(
            "APPARATUS: could not release {}: {error}",
            archive_hold.display()
        )
    });
    eprintln!(
        "[proof] FX-35 Control/Live and Archive hold files removed; awaiting the exact release grant"
    );
    if pool_full_seen {
        let retained_owner = live_pool_full
            .expect("PRODUCT: PoolFull lost the selected exact foreground continuation");
        let name = retained_owner.name;
        let observed_at = retained_owner.observed;
        let wait_order = retained_owner.order;
        let peer = retained_owner.identity["peer"]
            .as_str()
            .expect("PRODUCT: no retained peer");
        let (dir, node, _, _) = pressure_members
            .iter()
            .find(|(_, _, candidate, _)| *candidate == name)
            .expect("APPARATUS: PoolFull owner disappeared from staged nodes");
        loop {
            let promised = fx35_synced(&staged.host, Some(resize_probe));
            let promised: serde_json::Value = serde_json::from_str(&promised.status)
                .expect("PRODUCT: granted-but-unconsumed status was not JSON");
            let pool = &promised["lanes"]["budget"]["flow_state"];
            let exact = pool["waiting"]
                .as_array()
                .into_iter()
                .flatten()
                .find(|continuation| continuation["order"] == wait_order);
            if let Some(exact) = exact.filter(|continuation| continuation["granted"] == true) {
                assert_pressure_identity(exact, &retained_owner);
                assert!(
                    pool["promised"].as_u64().is_some_and(|count| count > 0)
                        && pool["occupied"].as_u64()
                            == pool["in_use"]
                                .as_u64()
                                .zip(pool["promised"].as_u64())
                                .map(|(in_use, promised)| in_use + promised),
                    "PRODUCT: another hosted node could see exact release grant {wait_order}, \
                     but status did not include it in promised and occupied capacity: {pool}"
                );
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let release_hold = staged
            .release_hold
            .as_ref()
            .expect("APPARATUS: flow-release hold path disappeared");
        std::fs::remove_file(release_hold).unwrap_or_else(|error| {
            panic!(
                "APPARATUS: could not release {}: {error}",
                release_hold.display()
            )
        });
        observe_flow_release_handoff(dir, *node, name, wait_order, &pressure_room_id, peer);
        eprintln!("[proof] FX-35 exact handoff observed: owner={name} order={wait_order}");
        pressure_tails
            .get(name)
            .expect("APPARATUS: PoolFull node lost its pre-attached observer")
            .wait_for_after(&pressure_target, name, true, Some(observed_at));
        eprintln!("[proof] FX-35 selected user target observed in its preattached tail: owner={name} order={wait_order} target={pressure_target:?}");
        let (ok, out, err) = vox(&staged.host, &["node", "lock", resize_probe], None);
        assert!(
            ok,
            "APPARATUS: could not lock unrelated resize probe: {out}{err}"
        );
    }
    drop(pressure_tails);
    // Initial convergence already proves every original reader/author/room observation. This
    // pressure room intentionally has only Bob and the spare: its exact preattached tail above
    // is the release-delivery claim; nonmembers must not be asked to read its target.
    // The forced old-connection retirement must publish the exact durable result already reached,
    // or leave the exact saved request truthfully Paused. Only Paused receives one shipped Resume.
    // Under the orphan mutant the old Pending/running state has no physical owner, so the
    // structural verdict below turns red before Status or Resume can prepare replacement work.
    for (dir, node, name, fingerprint) in
        &staged.everyone[..vox_core::node::history_budget::ARCHIVE_JOBS]
    {
        let accepted = archive
            .owners
            .get(*name)
            .unwrap_or_else(|| panic!("APPARATUS: {name}'s accepted archive owner was not saved"));
        let mut disconnect_failure: Option<String> = None;
        loop {
            let shown = fx35_synced(dir, *node);
            let status: serde_json::Value =
                serde_json::from_str(&shown.status).unwrap_or_else(|error| {
                    panic!(
                        "PRODUCT: {name}'s status was not JSON while its archive request ran: \
                         {error}: {}",
                        shown.status
                    )
                });
            let history = &status["lanes"]["history"];
            // The daemon status above only observes ownership. Before an explicit History Status
            // or Resume can prepare replacement work, count the exact queued Dispatch as well as
            // bounded owners: a same-port live round may legitimately delay taking that Dispatch.
            let owner = &history["owner"];
            let accepted_room = vox_core::node::link::b32_encode(&accepted.room);
            let queued_dispatch = history["ready"] == true
                && owner["room"].as_str() == Some(accepted_room.as_str())
                && owner["instance"].as_str() == Some(accepted.instance.as_str())
                && owner["request"].as_str() == Some(accepted.request.as_str())
                && owner["peer"].as_str() == Some(staged.everyone[staged.hosted].3.as_str());
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
                history["running"] != true
                    || queued_dispatch
                    || running
                    || retained_archive
                    || admission,
                "PRODUCT: {name}'s shipped archive request remains running, but no exact queued \
                 history dispatch, archive round, retained archive flow, or archive admission \
                 owns its next step (node charge {charged} cannot stand in for \
                 archive ownership): {}",
                shown.status
            );
            if matches!(history["phase"].as_str(), Some("Complete" | "More")) {
                let (ok, out, err) = vox(
                    dir,
                    &as_node(
                        &[
                            "room",
                            "read",
                            &archive_room,
                            "--history",
                            "status",
                            "--history-instance",
                            &accepted.instance,
                            "--json",
                        ],
                        *node,
                    ),
                    None,
                );
                assert!(
                    ok,
                    "PRODUCT: {name}'s durable archive result could not be observed: {out}{err}"
                );
                let completed: HistoryDemandReply =
                    serde_json::from_str(&out).unwrap_or_else(|error| {
                        panic!(
                            "PRODUCT: {name}'s durable archive result was not JSON ({error}): {out}"
                        )
                    });
                assert!(
                    completed.schema == "vox.room.history/1"
                        && completed.status.room == accepted.room
                        && completed.instance == accepted.instance
                        && completed.request.as_deref() == Some(accepted.request.as_str())
                        && (completed.status.author == accepted.author
                            || completed.status.author.is_none())
                        && completed.status.head == accepted.head
                        && matches!(
                            completed.status.phase,
                            vox_core::node::api::HistoryDemandPhase::Complete
                                | vox_core::node::api::HistoryDemandPhase::More
                        ),
                    "PRODUCT: {name}'s durable terminal archive result did not retain the accepted \
                     room/request/instance/head: {out}"
                );
                break;
            }
            if history["phase"] == "Paused" {
                assert!(
                    disconnect_failure.is_none(),
                    "PRODUCT: {name}'s exact archive request paused again after its one explicit \
                     Resume; first failure was {:?}, current status is {history}",
                    disconnect_failure
                );
                // Paused has no physical owner by design. Identify its exact durable operation
                // only after the no-orphan assertion above, then resume it once as a person does.
                let (ok, out, err) = vox(
                    dir,
                    &as_node(
                        &[
                            "room",
                            "read",
                            &archive_room,
                            "--history",
                            "status",
                            "--history-instance",
                            &accepted.instance,
                            "--json",
                        ],
                        *node,
                    ),
                    None,
                );
                assert!(
                    ok,
                    "PRODUCT: {name}'s paused exact archive request could not be observed: \
                     {out}{err}"
                );
                let paused: HistoryDemandReply =
                    serde_json::from_str(&out).unwrap_or_else(|error| {
                        panic!(
                            "PRODUCT: {name}'s paused archive status was not JSON ({error}): {out}"
                        )
                    });
                assert!(
                    paused.schema == "vox.room.history/1"
                        && paused.status.room == accepted.room
                        && paused.instance == accepted.instance
                        && paused.request.as_deref() == Some(accepted.request.as_str())
                        && paused.status.author == accepted.author
                        && paused.status.head == accepted.head
                        && matches!(
                            paused.status.phase,
                            vox_core::node::api::HistoryDemandPhase::Paused
                        )
                        && !paused.status.detail.is_empty(),
                    "PRODUCT: {name}'s forced disconnect did not leave the exact accepted \
                     request/instance/author/head Paused with its truthful failure: {out}"
                );
                eprintln!(
                    "[proof] FX-35 archive request paused after forced disconnect: \
                     owner={name} request={} detail={:?}",
                    accepted.request, paused.status.detail
                );
                let failure = paused.status.detail.clone();
                let (ok, out, err) = vox(
                    dir,
                    &as_node(
                        &[
                            "room",
                            "read",
                            &archive_room,
                            "--history",
                            "resume",
                            "--history-instance",
                            &accepted.instance,
                            "--history-request",
                            &accepted.request,
                            "--json",
                        ],
                        *node,
                    ),
                    None,
                );
                assert!(
                    ok,
                    "PRODUCT: {name}'s one exact shipped Resume was refused after the forced \
                     disconnect: {out}{err}"
                );
                let resumed: HistoryDemandReply =
                    serde_json::from_str(&out).unwrap_or_else(|error| {
                        panic!(
                            "PRODUCT: {name}'s exact Resume response was not JSON ({error}): {out}"
                        )
                    });
                assert!(
                    resumed.schema == "vox.room.history/1"
                        && resumed.status.room == accepted.room
                        && resumed.instance == accepted.instance
                        && resumed.request.as_deref() == Some(accepted.request.as_str())
                        && matches!(
                            resumed.status.phase,
                            vox_core::node::api::HistoryDemandPhase::Preparing
                                | vox_core::node::api::HistoryDemandPhase::Pending
                        ),
                    "PRODUCT: {name}'s one Resume did not retain the accepted request/instance \
                     that owns its bounded interval: {out}"
                );
                disconnect_failure = Some(failure);
                continue;
            }
            if matches!(
                history["phase"].as_str(),
                Some("Unavailable" | "Cancelled" | "Busy")
            ) {
                panic!(
                    "PRODUCT: {name}'s exact shipped archive request ended without its quantum \
                     after pool pressure: {history}"
                );
            }
            std::thread::sleep(Duration::from_millis(200));
        }
    }
    generation_accounting_keeps_actor_incarnations_exact(&staged, &pressure_members, &archive_room);
    // The product's account of the pool, now that everyone has read everyone.
    let hosted_fps: BTreeSet<&str> = pressure_members
        .iter()
        .map(|(_, _, _, fp)| fp.as_str())
        .collect();
    let mut most = 0u64;
    let mut limit: Option<u64> = None;
    let mut broken: Vec<String> = Vec::new();
    for (dir, node, name, fp) in pressure_members
        .iter()
        .chain(staged.everyone[staged.hosted..].iter())
    {
        let shown = fx35_synced(dir, *node);
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
                let promised = pool["promised"].as_u64().unwrap_or(u64::MAX);
                let occupied = pool["occupied"].as_u64().unwrap_or(u64::MAX);
                let by_node = pool["by_node"].as_object();
                let occupied_by_node = pool["occupied_by_node"].as_object();
                let keys: BTreeSet<&str> = by_node
                    .map(|m| m.keys().map(String::as_str).collect())
                    .unwrap_or_default();
                let sum: u64 = by_node
                    .map(|m| m.values().filter_map(serde_json::Value::as_u64).sum())
                    .unwrap_or(0);
                let occupied_sum: u64 = occupied_by_node
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
                        && round["request"].as_str().is_some()
                        && round["instance"].as_str().is_some()
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
                    || sum != in_use
                    || occupied != in_use.saturating_add(promised)
                    || occupied_sum != occupied
                    || occupied_by_node
                        .map(|values| values.keys().map(String::as_str).collect::<BTreeSet<_>>())
                        .unwrap_or_default()
                        != expected
                    || running.len() as u64 != in_use
                    || !running_exact
                    || retiring_said != retiring_expected
                {
                    broken.push(format!(
                        "{name}: flow-state generations do not account exactly for in_use \
                         {in_use} and occupied {occupied} (by_node {}, occupied_by_node {}, \
                         actors {}, running {}, retiring_nodes {})",
                        pool["by_node"],
                        pool["occupied_by_node"],
                        pool["actors"],
                        pool["running"],
                        pool["retiring_nodes"]
                    ));
                }
                if mine != Some(running_here) {
                    broken.push(format!(
                        "{name}: by_node says {mine:?} for this node but {running_here} of its \
                         ports have a round running"
                    ));
                }
                let expected_limit = (vox_core::node::history_budget::BOUNDED_SYNC_RUNNING_SLOTS
                    * keys.len()) as u64;
                if l != expected_limit || occupied > l {
                    broken.push(format!(
                        "{name}: the pool allows {l}, not exactly {expected_limit}, flow states \
                         for {} hosted nodes; {in_use} in use and {occupied} occupied",
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
    let staged = stage_hosted_nodes(&FX35_WAKE_HOSTED, true, true, true);
    let (bob_dir, bob_node, bob_name, bob_id) = staged
        .everyone
        .last()
        .expect("APPARATUS: strict foreground donor");
    // Each network edge crosses daemon budgets. A same-host Inventory server can
    // otherwise hold FG1 awaiting HAVE that its sibling needs FG1 to construct.
    for (index, (dir, node, name, id)) in staged.everyone[..staged.hosted].iter().enumerate() {
        let room = &staged.rooms[index];
        loop {
            let shown = fx35_synced(dir, *node);
            let value: serde_json::Value = serde_json::from_str(&shown.status)
                .expect("APPARATUS: strict foreground topology JSON");
            let rooms = value["rooms"]
                .as_array()
                .expect("APPARATUS: strict foreground rooms");
            assert_eq!(
                rooms.len(),
                1,
                "APPARATUS: {name} must have one Bob-only room: {value}"
            );
            assert_eq!(
                rooms[0]["id"], *room,
                "APPARATUS: {name}'s own room changed"
            );
            let members: BTreeSet<_> = rooms[0]["members"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|member| member["id"].as_str())
                .collect();
            let pair: BTreeSet<_> = [id.as_str(), bob_id.as_str()].into_iter().collect();
            assert_eq!(
                members, pair,
                "APPARATUS: strict foreground reader has a same-host sibling edge: {value}"
            );
            let (ok, out, err) = vox(dir, &as_node(&["room", "read", room], *node), None);
            assert!(
                ok,
                "APPARATUS: {name}'s strict foreground baseline refused: {out}{err}"
            );
            let (bob_ok, bob_out, bob_err) =
                vox(bob_dir, &as_node(&["room", "read", room], *bob_node), None);
            assert!(
                bob_ok,
                "APPARATUS: Bob's strict foreground baseline refused: {bob_out}{bob_err}"
            );
            if out.contains(&format!("{bob_name} is here"))
                && bob_out.contains(&format!("{name} is here"))
            {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
    // Complete every local tail-ready append before holding FG1. An own append
    // while a hinted Live admission waits may legally prepend a Control announcement.
    let mut tails: BTreeMap<&str, TailObserver> = staged.everyone[..staged.hosted]
        .iter()
        .enumerate()
        .map(|(index, (dir, node, name, _))| {
            (
                *name,
                TailObserver::attach(dir, *node, &staged.rooms[index], None),
            )
        })
        .collect();
    for (index, (dir, node, name, _)) in staged.everyone[..staged.hosted].iter().enumerate() {
        let ready = format!("tail-attached-for-{name}");
        stage_post(dir, *node, name, &staged.rooms[index], &ready);
        tails
            .get(name)
            .expect("APPARATUS: strict foreground tail")
            .wait_for(&ready, name, false);
    }
    loop {
        let mut busy = Vec::new();
        for (dir, node, name, _) in &staged.everyone[..staged.hosted] {
            let shown = fx35_synced(dir, *node);
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
                    .filter_map(|key| bounded[key].as_array().map(|rows| rows.len() as u64))
                    .sum::<u64>()
                + u64::from(!bounded["cleanup"].is_null());
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
        std::thread::sleep(Duration::from_millis(20));
    }

    let hold = staged
        .live_hold
        .as_ref()
        .expect("APPARATUS: exact-admission hold path was not staged");
    std::fs::File::create(hold)
        .unwrap_or_else(|e| panic!("APPARATUS: could not create {}: {e}", hold.display()));
    // A Bob post in each independent room creates real receiving Live work on
    // both hosted contenders; local posts alone would only owe Bob an announcement.
    for (index, (_, _, name, _)) in staged.everyone[..staged.hosted].iter().enumerate() {
        let text = format!("{name} re-armed");
        stage_post(bob_dir, *bob_node, bob_name, &staged.rooms[index], &text);
    }
    // A peer's incoming HAVE can itself wait for FG1 before publishing any new
    // head. Observe the actual held receiver, then make ONE ordinary local append
    // on the OTHER reader so its outgoing Control producer is owed independently.
    let held_index = loop {
        let owners = charged_flow_hold_owners(hold);
        let mut selected = None;
        if owners.values().sum::<usize>() == 1 {
            let ((actor, id, room, peer), _) = owners
                .iter()
                .next()
                .expect("APPARATUS: one held Live owner");
            let index = staged.everyone[..staged.hosted]
                .iter()
                .position(|(_, _, _, node)| node == id)
                .expect("APPARATUS: strict foreground held an unstaged node");
            assert_eq!(
                *room, staged.rooms[index],
                "APPARATUS: held reader room changed"
            );
            assert_eq!(peer, bob_id, "APPARATUS: held reader peer changed");
            let (dir, node, _, _) = &staged.everyone[index];
            let shown = fx35_synced(dir, *node);
            let value: serde_json::Value =
                serde_json::from_str(&shown.status).expect("APPARATUS: held Live status JSON");
            let real = value["lanes"]["bounded"]["running"]
                .as_array()
                .into_iter()
                .flatten()
                .any(|round| {
                    round["actor"] == *actor
                        && round["room"] == *room
                        && round["peer"] == *bob_id
                        && round["archive"] == false
                        && round["lane"] == "live"
                        && round["finished"] == false
                });
            if real
                && value["lanes"]["budget"]["foreground"] == 1
                && charged_flow_hold_owners(hold) == owners
            {
                selected = Some(index);
            }
        }
        if let Some(index) = selected {
            break index;
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let waiting_index = (0..staged.hosted)
        .find(|index| *index != held_index)
        .expect("APPARATUS: strict foreground needs the other reader");
    let (waiting_dir, waiting_node, waiting_name, waiting_id) = &staged.everyone[waiting_index];
    let room = &staged.rooms[waiting_index];
    let stimulus = format!("foreground-control-stimulus-for-{waiting_name}");
    let (ok, out, err) = stage_post_once(waiting_dir, *waiting_node, room, &stimulus);
    assert!(
        ok,
        "APPARATUS: sole local Control stimulus was refused: {out}{err}"
    );
    eprintln!("[proof] strict foreground Live held; other reader {waiting_name}'s sole Control stimulus accepted");

    let witnesses = || {
        let fault = std::path::PathBuf::from(format!("{}.foreground-fault", hold.display()));
        assert!(
            !fault.exists(),
            "APPARATUS: foreground witness failed: {:?}",
            std::fs::read_to_string(&fault)
        );
        let prefix = format!(
            "{}.foreground-wait.",
            hold.file_name()
                .expect("APPARATUS: foreground hold basename")
                .to_string_lossy()
        );
        std::fs::read_dir(hold.parent().expect("APPARATUS: foreground hold parent"))
            .expect("APPARATUS: foreground witness directory")
            .filter_map(|entry| {
                let path = entry.expect("APPARATUS: foreground witness entry").path();
                if !path
                    .file_name()
                    .is_some_and(|name| name.to_string_lossy().starts_with(&prefix))
                {
                    return None;
                }
                let bytes = match std::fs::read(&path) {
                    Ok(bytes) => bytes,
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => return None,
                    Err(error) => panic!("APPARATUS: foreground witness read: {error}"),
                };
                let value: serde_json::Value = serde_json::from_slice(&bytes)
                    .expect("APPARATUS: atomically published foreground witness JSON");
                assert!(
                    value["schema"] == "vox.proof.foreground-wait/1"
                        && value["lane"] == "large_control"
                        && value["parent_job"].as_u64().is_some()
                        && value["ticket"].as_u64().is_some(),
                    "APPARATUS: foreground witness schema changed: {value}"
                );
                let expected_path = std::path::PathBuf::from(format!(
                    "{}.foreground-wait.{}.{}.{}",
                    hold.display(),
                    value["actor"].as_u64().expect("APPARATUS: witness actor"),
                    value["parent_job"].as_u64().expect("APPARATUS: parent job"),
                    value["ticket"].as_u64().expect("APPARATUS: witness ticket")
                ));
                assert_eq!(
                    path, expected_path,
                    "APPARATUS: foreground witness filename changed parent/ticket binding"
                );
                Some((path, bytes, value))
            })
            .collect::<Vec<_>>()
    };
    let current_control =
        |status: &serde_json::Value, witness: &serde_json::Value, id: &str, room: &str| {
            witness["node"] == id
                && witness["room"] == room
                && witness["peer"] == *bob_id
                && status["lanes"]["budget"]["flow_state"]["actors"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .any(|actor| {
                        actor["actor"] == witness["actor"]
                            && actor["node"] == id
                            && actor["registered"] == true
                    })
                && status["lanes"]["bounded"]["running"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .any(|round| {
                        round["archive"] == false
                            && round["lane"] == "control"
                            && round["finished"] == false
                            && ["actor", "room", "peer", "request", "instance", "token"]
                                .into_iter()
                                .all(|field| round[field] == witness[field])
                    })
        };
    let exact_running = |status: &serde_json::Value, witness: &serde_json::Value| {
        let held = charged_flow_hold_owners(hold);
        if held.values().sum::<usize>() != 1 {
            return false;
        }
        if !held.keys().all(|(actor, node, _, _)| {
            status["lanes"]["budget"]["flow_state"]["actors"]
                .as_array()
                .into_iter()
                .flatten()
                .any(|owner| {
                    owner["actor"] == *actor
                        && owner["node"] == *node
                        && owner["registered"] == true
                })
        }) {
            return false;
        }
        let mut expected = held;
        *expected
            .entry((
                witness["actor"].as_u64().expect("APPARATUS: witness actor"),
                witness["node"]
                    .as_str()
                    .expect("APPARATUS: witness node")
                    .to_owned(),
                witness["room"]
                    .as_str()
                    .expect("APPARATUS: witness room")
                    .to_owned(),
                witness["peer"]
                    .as_str()
                    .expect("APPARATUS: witness peer")
                    .to_owned(),
            ))
            .or_insert(0) += 1;
        running_flow_owners(status) == expected
            && status["lanes"]["budget"]["flow_state"]["in_use"] == 2
            && status["lanes"]["budget"]["foreground"] == 1
            && status["lanes"]["budget"]["foreground_jobs"] == 1
    };
    loop {
        let shown = fx35_synced(waiting_dir, *waiting_node);
        let value: serde_json::Value =
            serde_json::from_str(&shown.status).expect("APPARATUS: foreground waiter status JSON");
        if witnesses().iter().any(|(_, _, witness)| {
            current_control(&value, witness, waiting_id, room) && exact_running(&value, witness)
        }) {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }

    // Create one remote result the retained waiter can reveal. It must still be absent before
    // release. The read and the tail subscription may schedule while capacity is held; neither
    // can be the event that starts the waiter after capacity changes.
    let target = format!("release-event-target-for-{waiting_name}");
    stage_post(bob_dir, *bob_node, bob_name, room, &target);
    let (ok, before, err) = vox(
        waiting_dir,
        &as_node(&["room", "read", room], *waiting_node),
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

    let tail = tails
        .remove(*waiting_name)
        .expect("APPARATUS: selected strict foreground tail disappeared");
    // Bind only after every preparatory command. This is a real queued LargeControl
    // promotion owned by this exact running Control round, not an actor Live FIFO claim.
    let shown = fx35_synced(waiting_dir, *waiting_node);
    let value: serde_json::Value =
        serde_json::from_str(&shown.status).expect("APPARATUS: final foreground waiter JSON");
    let id = waiting_id;
    let (path, bytes, witness) = witnesses().into_iter()
        .find(|(_, _, witness)| current_control(&value, witness, id, room)
            && exact_running(&value, witness))
        .unwrap_or_else(|| panic!("APPARATUS: exact foreground promotion/held Live owner changed during target staging: {value}"));
    assert_eq!(
        std::fs::read(&path).expect("APPARATUS: final current promotion witness"),
        bytes,
        "APPARATUS: actual queued promotion ended/changed before capacity release"
    );
    eprintln!(
        "[proof] strict foreground actual queued promotion bound for {waiting_name}: {witness}"
    );
    let released = Instant::now();
    std::fs::remove_file(hold)
        .unwrap_or_else(|e| panic!("APPARATUS: could not release {}: {e}", hold.display()));
    // No status, read, post, or other actor request occurs after this point. The retained lane's
    // exact capacity-release notification is the only product event that can expose `target` to
    // the already-running shipped tail while periodic scheduling is disabled.
    tail.wait_for_after(&target, waiting_name, true, Some(released));
    assert!(!std::path::Path::new(&format!("{}.foreground-fault", hold.display())).exists(),
        "APPARATUS: foreground witness cleanup failed; user outcome is not credited by this apparatus");
    loop {
        let (ok, out, err) = vox(
            waiting_dir,
            &as_node(&["room", "read", room], *waiting_node),
            None,
        );
        assert!(
            ok,
            "PRODUCT: {waiting_name}'s shipped read refused while judging re-armed ports: \
             {out}{err}"
        );
        if out.contains(&format!("{waiting_name} re-armed")) {
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    for (index, (dir, node, name, _)) in staged.everyone[..staged.hosted].iter().enumerate() {
        loop {
            let (ok, out, err) = vox(
                dir,
                &as_node(&["room", "read", &staged.rooms[index]], *node),
                None,
            );
            assert!(
                ok,
                "PRODUCT: {name}'s own Bob-room read refused after release: {out}{err}"
            );
            if out.contains(&format!("{name} re-armed")) {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
    drop(tail);
    drop(tails);
}

/// **A quiet room costs nothing, writes nothing and says when it last synced** (ADR-038 FX-15,
/// FX-16, FX-29; #979, #980, #996, #1021): alice and bob, each on a daemon of their own, read
/// each other once. Carol joins,
/// then goes offline; alice's consent must therefore travel as a key-package in her public feed.
/// While Bob is offline, Alice and Carol each append more than the production history-page bound.
/// On return he is hostile-sent Carol's private package body once: he must reject it before
/// persistence, cross the authenticated header, and durably acknowledge both authors' exact
/// tails across a restart. Over [`IDLE`] seconds nobody posts, no lane becomes partial merely
/// because Bob correctly holds only that package's public header, and each profile completes no
/// more sync rounds than the periodic
/// request allows (one per [`SYNC_INTERVAL_SECS`](vox_core::node::syncstream::SYNC_INTERVAL_SECS)
/// plus the follow-up each may raise), and `vox status --json` names a last completed sync for
/// the room and for the member. With Alice offline, Carol completes a sync with Bob but cannot
/// read Alice's tail; once the actual package source returns she reads it and all three members
/// still exchange visible posts. Measured before #996's role-aware settlement: the package's
/// header-only position remained a missing body on Bob, whose periodic inventory probe ended
/// partial forever. Across the quiet window, every exact shipped lane must complete at least one
/// periodic round, every completed round must be empty, no lane may fetch, serve or re-decline
/// history, and Alice's, Bob's and offline Carol's complete `store.redb` bytes and mtimes must be
/// unchanged. The artifact is the user's storage verdict; no private database field substitutes.
/// The same journey then admits a member trusted before the posts only after every holder has
/// visibly pruned one body. Its exact durable refusal must survive a transport reconnect and its
/// own daemon restart; a trust removal/regrant and a leave/rejoin must invalidate the old
/// authorization and room/member lifetimes; and Bob's successor must be read while shipped
/// status names the exact refusal re-armed. Those waits are bounded by completed lane cycles,
/// never an elapsed PRODUCT deadline.
///
/// Mutants: the own-head hint offered to every peer on every tick again (`offer_own_head`
/// ignoring who acknowledged) turns the round-count claim red; undoing role-aware settlement for
/// the non-recipient package turns the exact held-through assertion red; restoring direct
/// inventory credit turns the pre-release no-credit assertion red when Bob echoes Alice's merely
/// committed head; granting body credit persists the hostile ciphertext and turns the exact
/// pre-persistence refusal assertion red; moving the archive cursor
/// below the role-only header before its effect makes the interrupted request finish with debt;
/// skipping the already-settled callback or rejecting its terminal replay strands the resumed
/// request; dropping bounded continuation stalls the exact older-row assertion; each mutation
/// has its own script and PRODUCT red. The lane's completion no longer recording the sync
/// (`note_lane_sync` removed) turns the last-sync claim red. The isolated
/// `held-inventory-write` mutant commits an unchanged inventory slice without changing the lane
/// counters and turns only the complete-store artifact assertion red. Removing the indexed
/// refusal write makes the post-disconnect reconnect cycle re-decline; omitting indexed
/// reconstruction makes the first flow released after the requester-start barrier re-decline;
/// labeling the refusal with the callback's current grant instead of the Flow's captured grant,
/// or dropping the authorization comparison, makes the transaction-barrier cycle decline without
/// the shipped lane first reporting the stale old Flow. Retaining the departed room/member
/// refusal suppresses the rejoined lifetime's decline; treating a changed head as the old
/// decision prevents the successor's read/re-armed assertion. Resetting a settled Content
/// header's original first-seen time when its body arrives later exposes an already-expired row
/// after a younger shipped witness has disappeared. `drop-resume-owed` removes only the replacement
/// owner after an archive Flow becomes authorization-stale while an earlier Control waiter owns
/// admission; the exact shipped `lanes.history.owner` assertion turns red. Each mutant reaches its
/// own exact terminal PRODUCT red.
#[cfg(feature = "optional-proofs")]
#[test]
#[ignore = "an idle minute on two real vox daemons; optional, run it in release"]
fn a_quiet_room_costs_no_rounds_and_says_when_it_last_synced() {
    test_knobs::require(&[
        "VOX_TEST_HOLD_PACKAGES_FILE",
        "VOX_TEST_SERVE_NONRECIPIENT_HISTORY_BODY_FILE",
        "VOX_TEST_HOLD_ROLE_HEADER_SETTLEMENT_FILE",
        "VOX_TEST_HISTORY_BODY_DURABLE_FILE",
        "VOX_TEST_HOLD_CONTROL_JOB_FILE",
        "VOX_TEST_HOLD_HISTORY_DECLINE_FILE",
        "VOX_TEST_FOREGROUND_JOBS",
        "VOX_TEST_CONTROL_JOBS",
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
    let settlement_hold = root.join("hold-role-header-settlement");
    let settlement_hold_path = settlement_hold
        .to_str()
        .expect("APPARATUS: a UTF-8 role-settlement hold path")
        .to_owned();
    let settlement_engaged =
        std::path::PathBuf::from(format!("{}.engaged", settlement_hold.display()));
    let control_hold = root.join("hold-archive-resume-control-owner");
    let control_hold_path = control_hold
        .to_str()
        .expect("APPARATUS: a UTF-8 Control-owner hold path")
        .to_owned();
    let body_durable = root.join("history-body-durable");
    let body_durable_path = body_durable
        .to_str()
        .expect("APPARATUS: a UTF-8 durable-body marker path")
        .to_owned();
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
    // boundary. Stop Carol first and observe the exact member disconnected in shipped status.
    // Alice then appends the boundary row locally and trusts Carol. A new failure generation on
    // Carol's exact full-fingerprint sync lane proves the direct attempt actually failed; the
    // following exact two-position log/feed advance proves that failure selected the
    // package-plus-consent path.
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
    // The actor's monotonic member-reach serial is the causal baseline. Any attempt already in
    // flight because the boundary post raised a port has a serial at or below this one and cannot
    // masquerade as the reach synchronously started by the trust command.
    let reach_before = offline_fallback_observation(&alice, &room, &fps[2]).serial;
    let (ok, _, err) = vox(&alice, &["trust", "add", &fps[2], "--name", "carol"], None);
    assert!(
        ok,
        "PRODUCT: alice's `vox trust add` of carol failed: {err}"
    );
    // Alice had no direct connection at the decision and Carol's process remains stopped. The
    // shipped snapshot must now show either the exact asked-for attempt or its exact fallback
    // result. Once the attempt disappears, absence of that result is structurally a PRODUCT red;
    // only an attempt still owned by the network may run until the external apparatus deadman.
    let (fallback_attempt, package_seq, consent_seq) = loop {
        let observation = offline_fallback_observation(&alice, &room, &fps[2]);
        assert!(
            observation.serial > reach_before,
            "PRODUCT: `vox trust add` returned without starting Carol's exact member-delivery \
             reach: serial remained {reach_before}"
        );
        if let Some((attempt, package_seq, consent_seq)) = observation
            .fallback
            .filter(|(attempt, _, _)| *attempt > reach_before)
        {
            break (attempt, package_seq, consent_seq);
        }
        assert!(
            observation
                .active
                .iter()
                .any(|attempt| *attempt > reach_before),
            "PRODUCT: Carol's asked-for member reach completed but shipped status records no \
             package/consent fallback result after serial {reach_before}"
        );
        std::thread::yield_now();
    };
    assert_eq!(
        package_seq,
        Some(before_package_through.saturating_add(1)),
        "PRODUCT: failed member reach {fallback_attempt} did not append Carol's exact key package \
         at authenticated position {}",
        before_package_through.saturating_add(1)
    );
    assert_eq!(
        consent_seq,
        Some(before_package_through.saturating_add(2)),
        "PRODUCT: failed member reach {fallback_attempt} did not append Carol's exact consent at \
         authenticated position {}",
        before_package_through.saturating_add(2)
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
    let carol_bob_sync_before = member_last_sync(&carol, &room, &fps[1]);
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

    // Turn Alice into a hostile authenticated server for exactly the first body frame of the
    // package addressed to Carol. The server renames this marker only after sending that frame.
    // Bob must reject it before staging/persistence, then retry the header-only role-complete
    // entry and causally finish both authors' bounded suffixes.
    std::fs::write(&hostile, b"")
        .unwrap_or_else(|e| panic!("APPARATUS: could not create {}: {e}", hostile.display()));
    std::fs::write(&settlement_hold, b"").unwrap_or_else(|e| {
        panic!(
            "APPARATUS: could not create {}: {e}",
            settlement_hold.display()
        )
    });
    let hostile_engaged = std::path::PathBuf::from(format!("{}.engaged", hostile.display()));
    let bob_settlement_knob = [
        (
            "VOX_TEST_HOLD_ROLE_HEADER_SETTLEMENT_FILE",
            settlement_hold_path.as_str(),
        ),
        (
            "VOX_TEST_HISTORY_BODY_DURABLE_FILE",
            body_durable_path.as_str(),
        ),
        ("VOX_TEST_FOREGROUND_JOBS", "1"),
        ("VOX_TEST_CONTROL_JOBS", "1"),
        ("VOX_TEST_HOLD_CONTROL_JOB_FILE", control_hold_path.as_str()),
    ];
    let bob_after_gap = daemon_env(&bob, "bob-after-gap", &bob_settlement_knob);
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
    let hostile_deadline = Instant::now() + READY_WITHIN;
    while !hostile_engaged.is_file() {
        assert!(
            Instant::now() < hostile_deadline,
            "APPARATUS: Alice did not send the deliberately hostile non-recipient package body \
             within {READY_WITHIN:?}; the privacy boundary was not exercised\nalice said: {}",
            said(&alice, "alice")
        );
        std::thread::sleep(Duration::from_millis(200));
    }
    let hostile_hash = std::fs::read(&hostile_engaged).unwrap_or_else(|e| {
        panic!(
            "APPARATUS: could not read the exact hostile entry from {}: {e}",
            hostile_engaged.display()
        )
    });
    assert_eq!(
        hostile_hash.len(),
        32,
        "APPARATUS: {} did not name one exact authenticated entry",
        hostile_engaged.display()
    );
    while !settlement_engaged.is_file() {
        assert_ne!(
            std::fs::read(&body_durable).ok().as_deref(),
            Some(hostile_hash.as_slice()),
            "PRODUCT [FX29 private-body-refusal]: Bob durably stored Carol's exact private body \
             instead of refusing it before persistence"
        );
        // The suite watchdog is the APPARATUS deadman if neither causal outcome arrives. This
        // sleep only paces observation; elapsed wall time is not a PRODUCT verdict.
        std::thread::sleep(Duration::from_millis(200));
    }
    let held_status = history_status(&bob, &room);
    assert!(
        held_status.0 != "complete" && held_status.1 != 0,
        "PRODUCT: before Carol's role-only header was semantically settled, Bob reported the \
         archive request complete with no remaining debt: {held_status:?}"
    );
    let bob_held_before_receipt =
        member_held_through_state(&alice, &room, &fps[1]).unwrap_or_else(|| {
            panic!(
                "PRODUCT: while Bob's role-complete receipt path was held, Alice's shipped \
                 status did not name Bob with a null or numeric held_through receipt"
            )
        });
    assert_ne!(
        bob_held_before_receipt,
        Some(marker_through),
        "PRODUCT: while Bob's role-complete receipt path was held before settlement, Alice's \
         shipped status credited Bob through her exact current feed position {marker_through}; \
         his echoed inventory scalar was treated as a catch-up receipt (reported \
         {bob_held_before_receipt:?})"
    );
    // Make the exact archive Flow authorization-stale while Control admission is genuinely busy.
    // Its own Control job is still held at role settlement. Bob's trust of Carol is a real keyring
    // generation change; Carol's real post then queues an older Control waiter behind that held
    // job. Once the archive Flow returns stale, FIFO admission gives Carol the released job and
    // holds it, so the archive replacement must remain visibly owned as `resume_owed` with its
    // exact request/ticket/wake. The isolated mutant drops only `owe_resume`; after the exact stale
    // lane terminal and held Control owner, this assertion turns PRODUCT red rather than waiting.
    let archive_request = history_observation(&bob, &room)
        .request
        .unwrap_or_else(|| panic!("PRODUCT: the held archive request exposed no exact request id"));
    let (ok, held_owner_status, err) = vox(&bob, &["status", "--json"], None);
    assert!(
        ok,
        "PRODUCT: Bob's shipped status failed while identifying the held archive owner: {err}"
    );
    let held_owner_status: serde_json::Value = serde_json::from_str(&held_owner_status)
        .unwrap_or_else(|error| {
            panic!(
                "PRODUCT: Bob's shipped status was not JSON while identifying the held archive \
                 owner: {error}: {held_owner_status}"
            )
        });
    let held_owner = &held_owner_status["lanes"]["history"]["owner"];
    let archive_instance = held_owner["instance"]
        .as_str()
        .filter(|instance| instance.len() == 32)
        .unwrap_or_else(|| {
            panic!(
                "PRODUCT: Bob's held archive owner exposed no exact incarnation: \
                 {held_owner_status}"
            )
        })
        .to_owned();
    assert!(
        held_owner["room"] == room && held_owner["request"] == archive_request,
        "PRODUCT: Bob's held archive owner did not identify the exact room/request before \
         authorization changed: {held_owner_status}"
    );
    let control_pressure_daemon = {
        std::fs::File::create(&control_hold).unwrap_or_else(|error| {
            panic!("APPARATUS: could not arm the real Control owner: {error}")
        });
        let stale_before = exact_lane(
            &bob,
            &room,
            &fps[0],
            "before the held archive authorization changed",
        );
        let (ok, out, err) = vox(&bob, &["trust", "add", &fps[2], "--name", "carol"], None);
        assert!(
            ok,
            "PRODUCT: Bob's shipped trust of Carol was refused while staging the archive authorization change: {out}{err}"
        );
        let pressure = daemon_env(&carol, "carol-control-pressure", &knob);
        attached(&carol, "carol-control-pressure");
        wait_room_open(&carol, &room, "carol-control-pressure");
        let control_post = "carol's real Control-pressure successor";
        let (ok, out, err) = vox(&carol, &["room", "post", &room, control_post], None);
        assert!(
            ok,
            "PRODUCT: Carol's Control-pressure post was refused: {out}{err}"
        );
        loop {
            let (ok, status, err) = vox(&bob, &["status", "--json"], None);
            assert!(
                ok,
                "APPARATUS: Bob's shipped status failed while staging the queued Control owner: {err}"
            );
            let value: serde_json::Value = serde_json::from_str(&status).unwrap_or_else(|error| {
                panic!("PRODUCT: Bob's shipped status was not JSON while staging Control pressure: {error}: {status}")
            });
            let queued = value["lanes"]["bounded"]["admissions"]
                .as_array()
                .into_iter()
                .flatten()
                .any(|owner| {
                    owner["room"].as_str() == Some(room.as_str())
                        && owner["peer"].as_str() == Some(fps[2].as_str())
                        && owner["lane"].as_str() == Some("control")
                });
            if queued {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        println!(
            "[proof] FX-29 archive authorization-stale Control-busy apparatus staged: room {room}, peer {}, request {archive_request}",
            fps[0]
        );
        std::fs::remove_file(&settlement_engaged).unwrap_or_else(|error| {
            panic!("APPARATUS: could not release the exact stale archive Flow: {error}")
        });
        loop {
            let stale = exact_lane(
                &bob,
                &room,
                &fps[0],
                "after the held archive authorization changed",
            )
            .since(stale_before);
            if stale.stale > 0 {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        loop {
            let held =
                charged_flow_hold_entries(&control_hold)
                    .into_iter()
                    .any(|(_, _, marker)| {
                        std::fs::read_to_string(marker).is_ok_and(|identity| {
                            identity.lines().any(|line| line == format!("room={room}"))
                                && identity
                                    .lines()
                                    .any(|line| line == format!("peer={}", fps[2]))
                        })
                    });
            if held {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let (ok, status, err) = vox(&bob, &["status", "--json"], None);
        assert!(
            ok,
            "PRODUCT: Bob's shipped status failed after the exact stale archive terminal: {err}"
        );
        let value: serde_json::Value = serde_json::from_str(&status).unwrap_or_else(|error| {
            panic!("PRODUCT: Bob's shipped status was not JSON after the stale archive terminal: {error}: {status}")
        });
        let owner = &value["lanes"]["history"]["owner"];
        assert!(
            owner["stage"] == "resume_owed"
                && owner["room"] == room
                && owner["request"] == archive_request
                && owner["instance"].as_str() == Some(archive_instance.as_str())
                && owner["ticket"].as_u64().is_some()
                && owner["wake"] == true
                && value["lanes"]["budget"]["control"] == 1,
            "PRODUCT [FX29 archive-resume-owner]: after the exact archive Flow became authorization-stale and Carol's earlier real Control work owned the sole admission, shipped status did not retain Bob's exact room/request/incarnation FIFO ticket and wake as `resume_owed`: {status}"
        );
        pressure
    };

    // Stop at the exact durable boundary, then resume through the shipped command. The product
    // now has an exact retained replacement owner. The held real Control worker deliberately
    // prevents a clean actor stop, so kill this scratch daemon by its owned process handle and
    // remove only its scratch apparatus.
    drop(bob_after_gap);
    let _ = std::fs::remove_file(&control_hold);
    for (_, _, marker) in charged_flow_hold_entries(&control_hold) {
        let _ = std::fs::remove_file(marker);
    }
    control_pressure_daemon.stop();
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
        assert_history_owned(&bob, &room, &fps[0], 0, 1);
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
    // ---- the room is quiet: acknowledgements settle, then the rounds are counted ----------
    let before = [synced(&alice), synced(&bob)];
    let before_lanes = [lane_why(&before[0].2), lane_why(&before[1].2)];
    let before_exact = [quiet_lanes(&before[0].2), quiet_lanes(&before[1].2)];
    let quiet_profiles = [
        ("alice", alice.as_path()),
        ("bob", bob.as_path()),
        ("carol", carol.as_path()),
    ];
    // No store is touched by the proof process between these two reads. Commands before and
    // after the interval supply user-visible lane verdicts; the quiet storage verdict is the
    // complete artifact itself at its two edges.
    let stores_before = store_artifacts(&quiet_profiles);
    let counted = Instant::now();
    std::thread::sleep(IDLE);
    let stores_after = store_artifacts(&quiet_profiles);
    let after = [synced(&alice), synced(&bob)];
    let after_lanes = [lane_why(&after[0].2), lane_why(&after[1].2)];
    let after_exact = [quiet_lanes(&after[0].2), quiet_lanes(&after[1].2)];
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
    let wrote: Vec<String> = stores_before
        .iter()
        .filter_map(|(name, before)| {
            let after = stores_after.get(name).unwrap_or_else(|| {
                panic!("APPARATUS: {name}'s store disappeared from the second snapshot")
            });
            (before.bytes != after.bytes || before.modified != after.modified).then(|| {
                format!(
                    "{name}: bytes changed {} ({} -> {} bytes), mtime changed {} ({:?} -> {:?}), store {}",
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
    assert!(
        wrote.is_empty(),
        "PRODUCT: sync rounds that brought nothing wrote to the nodes' complete store artifacts \
         (ADR-038 FX-29, #1021): {}",
        wrote.join("; ")
    );
    let mut missing_lanes = Vec::new();
    let mut lanes_that_did_not_run = Vec::new();
    let mut nonempty_lanes = Vec::new();
    let mut repeated_history = Vec::new();
    for (index, name) in ["alice", "bob"].into_iter().enumerate() {
        if before_exact[index].is_empty() || after_exact[index].is_empty() {
            missing_lanes.push(format!(
                "{name}: before {:?}, after {:?}",
                before_exact[index].keys().collect::<Vec<_>>(),
                after_exact[index].keys().collect::<Vec<_>>()
            ));
        }
        let before_keys = before_exact[index].keys().cloned().collect::<BTreeSet<_>>();
        let after_keys = after_exact[index].keys().cloned().collect::<BTreeSet<_>>();
        if before_keys != after_keys {
            missing_lanes.push(format!(
                "{name}: exact lane keys changed: before-only {:?}, after-only {:?}",
                before_keys.difference(&after_keys).collect::<Vec<_>>(),
                after_keys.difference(&before_keys).collect::<Vec<_>>()
            ));
        }
        for (lane, now) in &after_exact[index] {
            let Some(was) = before_exact[index].get(lane) else {
                missing_lanes.push(format!("{name}: lane {lane:?} appeared only after quiet"));
                continue;
            };
            let grown = now.since(*was);
            if grown.completed == 0 {
                lanes_that_did_not_run.push(format!("{name} {lane:?}: {grown:?}"));
            }
            if grown.completed != grown.empty {
                nonempty_lanes.push(format!("{name} {lane:?}: {grown:?}"));
            }
            if grown.history_fetched != 0
                || grown.history_served != 0
                || grown.history_declined != 0
            {
                repeated_history.push(format!("{name} {lane:?}: {grown:?}"));
            }
        }
    }
    assert!(
        missing_lanes.is_empty(),
        "PRODUCT: `vox status --json` did not expose the same exact quiet room/peer lanes at \
         both artifact edges (ADR-038 FX-29, #1021): {missing_lanes:?}"
    );
    assert!(
        lanes_that_did_not_run.is_empty(),
        "PRODUCT: a quiet lane completed no periodic round, so no-write could be a stopped \
         scheduler rather than correct empty sync (ADR-038 FX-29, #1021): \
         {lanes_that_did_not_run:?}"
    );
    assert!(
        nonempty_lanes.is_empty(),
        "PRODUCT: shipped status says completed quiet rounds brought something new instead of \
         ending empty (ADR-038 FX-29, #1021): {nonempty_lanes:?}"
    );
    assert!(
        repeated_history.is_empty(),
        "PRODUCT: `vox status --json` says quiet lanes fetched, served or re-declined repeated \
         history (ADR-038 FX-29, #1021): {repeated_history:?}"
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
    let partial = [0usize, 1].map(|i| {
        after_lanes[i]
            .partial
            .saturating_sub(before_lanes[i].partial)
    });
    assert_eq!(
        partial,
        [0, 0],
        "PRODUCT: a quiet peer treated carol's private key-package body as owed after holding its \
         authenticated header: partial syncs over {idled:?} were alice {}, bob {}\n\
         alice's lane before: {}; after: {}\n\
         bob's lane before: {}; after: {}",
        partial[0],
        partial[1],
        before_lanes[0],
        after_lanes[0],
        before_lanes[1],
        after_lanes[1]
    );

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
    let bob_only_deadline = Instant::now() + READY_WITHIN;
    while member_last_sync(&carol, &room, &fps[1]) <= carol_bob_sync_before {
        assert!(
            Instant::now() < bob_only_deadline,
            "PRODUCT: Carol did not complete a sync with reachable Bob within \
             {READY_WITHIN:?} while Alice was offline\ncarol said: {}\nbob said: {}",
            said(&carol, "carol-from-bob"),
            said(&bob, "bob-after-restart")
        );
        std::thread::sleep(Duration::from_millis(200));
    }
    assert!(
        member_held_through(&carol, &room, &fps[1]) == Some(carol_tail_through),
        "PRODUCT: after both authors exceeded the bounded continuation page and Carol completed \
         a sync with restarted Bob, his receipt did not preserve her exact feed position \
         {carol_tail_through}\ncarol said: {}\nbob said: {}",
        said(&carol, "carol-from-bob"),
        said(&bob, "bob-after-restart")
    );
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
    prove_declined_refusal_lifecycle(
        &alice,
        &bob,
        &carol,
        &late,
        &room,
        &link,
        &fps,
        bob_after_restart,
        carol_from_bob_daemon,
    );
}

/// Continue the quiet-room journey through the durable refusal's actual user lifecycle. `late`
/// was mutually trusted with every author before any room post. Alice and Bob visibly prune one
/// Bob body while its only retaining source is offline, so late settles its authenticated header
/// and records a real missing-body decision. A later local post visibly aging out proves that
/// header's sealed retention origin is already expired. Carol then returns with the body while a
/// proof-only sweep hold preserves the exact post-refill observation: the old body must not become
/// visible merely because its bytes arrived later. No forged frame or database inspection stands
/// in for the shipped product.
///
/// Every wait below is fenced by exact terminal lane cycles. The process-wide proof watchdog is
/// only an external APPARATUS deadman for a lane that makes no observable progress at all.
#[cfg(feature = "optional-proofs")]
#[allow(clippy::too_many_arguments)]
fn prove_declined_refusal_lifecycle(
    alice: &Path,
    bob: &Path,
    carol: &Path,
    late: &Path,
    room: &str,
    link: &str,
    fps: &[String],
    bob_daemon: Daemon,
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
    let declined = await_lane_claim(
        late,
        room,
        &fps[1],
        QuietLane::default(),
        "late member's first missing-body decision",
        |grown| grown.history_declined > 0,
    );
    assert!(
        !reads(late, room, pruned),
        "PRODUCT: the late member read Bob's body after every shipped holder had pruned it; \
         status named its missing-body decision as {declined:?}"
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

    // A transport reconnect does not change the peer, author, authorization or room lifetime.
    // Its first completed exact lane cycle must therefore be empty and must not decide again.
    bob_daemon.stop();
    while member_connected(late, room, &fps[1]) != Some(false) {
        std::thread::yield_now();
    }
    // The baseline is deliberately after shipped status reports the disconnect. A completion
    // from the old connection therefore cannot satisfy the reconnect claim.
    let reconnect_before = exact_lane(late, room, &fps[1], "after Bob disconnected");
    let bob_daemon = daemon(bob, "bob-refusal-reconnected");
    attached(bob, "bob-refusal-reconnected");
    let reconnect = await_lane_claim(
        late,
        room,
        &fps[1],
        reconnect_before,
        "unchanged inventory after Bob reconnects",
        |grown| grown.completed > 0,
    );
    assert!(
        reconnect.completed == reconnect.empty
            && reconnect.history_fetched == 0
            && reconnect.history_declined == 0
            && reconnect.history_rearmed == 0,
        "PRODUCT: reconnecting Bob made the late member retry or forget an unchanged durable \
         refusal instead of completing empty: {reconnect:?}"
    );

    // Reconstruct the requester from disk. The first exact lane completion after restart is the
    // durable observation: an in-memory suppression cannot survive this edge.
    late_daemon.stop();
    let restart_hold = late.join("hold-refusal-restart-control");
    let decline_hold = late.join("hold-refusal-generation-write");
    std::fs::File::create(&restart_hold).unwrap_or_else(|error| {
        panic!("APPARATUS: could not arm the requester-restart flow barrier: {error}")
    });
    let restart_hold_text = restart_hold.to_string_lossy().into_owned();
    let decline_hold_text = decline_hold.to_string_lossy().into_owned();
    let late_daemon = daemon_env(
        late,
        "late-refusal-restarted",
        &[
            ("VOX_TEST_HOLD_CONTROL_JOB_FILE", restart_hold_text.as_str()),
            (
                "VOX_TEST_HOLD_HISTORY_DECLINE_FILE",
                decline_hold_text.as_str(),
            ),
        ],
    );
    attached(late, "late-refusal-restarted");
    wait_room_open(late, room, "late-refusal-restarted");
    wait_exact_bounded_running(
        late,
        room,
        &fps[1],
        &restart_hold,
        "requester restart barrier",
    );
    let restart_before = exact_lane(late, room, &fps[1], "after late's restart");
    std::fs::remove_file(&restart_hold).unwrap_or_else(|error| {
        panic!("APPARATUS: could not release the requester-restart flow barrier: {error}")
    });
    let restarted = await_lane_claim(
        late,
        room,
        &fps[1],
        restart_before,
        "unchanged inventory after the requester's restart",
        |grown| grown.completed > 0,
    );
    assert!(
        restarted.completed == restarted.empty
            && restarted.history_fetched == 0
            && restarted.history_declined == 0
            && restarted.history_rearmed == 0,
        "PRODUCT: after the requester's daemon restart, its first Bob lane retried or forgot the \
         durable refusal instead of completing empty: {restarted:?}"
    );

    // Stage a distinct unavailable Bob head, then hold the real refusal write after its Flow has
    // captured the old grant. The trust edit below therefore races an actually in-flight stale
    // Flow, rather than merely hoping a periodic round overlaps two sequential commands.
    let stale_body = "bob body whose refusal races an authorization generation";
    std::fs::File::create(&decline_hold).unwrap_or_else(|error| {
        panic!("APPARATUS: could not arm the stale-refusal durability barrier: {error}")
    });
    let (ok, out, err) = vox(bob, &["room", "post", room, stale_body], None);
    assert!(
        ok,
        "PRODUCT: Bob's stale-generation staging post was refused: {out}{err}"
    );
    while [alice, bob, carol]
        .iter()
        .any(|holder| reads(holder, room, stale_body))
    {
        std::thread::yield_now();
    }
    let decline_entered = std::path::PathBuf::from(format!("{}.entered", decline_hold.display()));
    while !decline_entered.exists() {
        std::thread::yield_now();
    }
    let staged = std::fs::read_to_string(&decline_entered).unwrap_or_else(|error| {
        panic!("APPARATUS: could not read the stale-refusal marker: {error}")
    });
    let staged_fields: std::collections::BTreeMap<_, _> = staged
        .split_whitespace()
        .filter_map(|field| field.split_once('='))
        .collect();
    assert!(
        staged_fields.get("peer").copied() == Some(fps[1].as_str())
            && staged_fields.get("author").copied() == Some(fps[1].as_str())
            && staged_fields.get("head").is_some_and(|head| !head.is_empty())
            && staged_fields
                .get("request")
                .is_some_and(|request| request.len() == 32)
            && staged_fields
                .get("captured")
                .is_some_and(|generation| !generation.is_empty()),
        "APPARATUS: the held refusal did not identify Bob's exact author/head/request/captured-generation transaction: {staged}"
    );
    let staged_head = staged_fields["head"].to_owned();
    let staged_request = staged_fields["request"].to_owned();
    let staged_generation = staged_fields["captured"].to_owned();
    let grant_before = exact_lane(late, room, &fps[1], "with Bob's old-grant flow in flight");
    let (ok, out, err) = vox(late, &["trust", "remove", &fps[1]], None);
    assert!(
        ok,
        "PRODUCT: late's shipped trust removal of Bob was refused: {out}{err}"
    );
    let (ok, out, err) = vox(late, &["trust", "add", &fps[1], "--name", "bob"], None);
    assert!(
        ok,
        "PRODUCT: late's shipped fresh trust grant to Bob was refused: {out}{err}"
    );
    std::fs::remove_file(&decline_hold).unwrap_or_else(|error| {
        panic!("APPARATUS: could not release the stale-refusal durability barrier: {error}")
    });
    let regranted = await_exact_refusal_transition(
        late,
        room,
        &fps[1],
        grant_before,
        &fps[1],
        &staged_head,
        &staged_request,
        &staged_generation,
    );
    assert!(
        regranted.stale.request == staged_request
            && regranted.saved.request != staged_request
            && regranted.lane.stale > 0,
        "PRODUCT: the fresh authorization lifecycle did not expose distinct exact stale and successor transactions: {regranted:?}"
    );
    assert!(
        !reads(late, room, stale_body),
        "PRODUCT: changing authorization made a body every holder pruned appear; exact lane \
         outcome {regranted:?}"
    );

    // Leaving deletes the local room, including its refusal namespace. Rejoining the same room
    // is a new local room/member lifetime; its missing-body decision cannot be suppressed by the
    // deleted lifetime's scalar. These are user commands and the visible room list is the fence.
    let room_before = exact_lane(late, room, &fps[1], "before late leaves the room");
    let (ok, out, err) = vox(late, &["room", "leave", room], None);
    assert!(
        ok,
        "PRODUCT: late's shipped room leave was refused: {out}{err}"
    );
    let (ok, listed, err) = vox(late, &["room", "list"], None);
    assert!(ok, "PRODUCT: late's room list failed after leave: {err}");
    assert!(
        !listed.contains(room),
        "PRODUCT: `vox room leave` returned but late's shipped room list still named {room}: \
         {listed}"
    );
    let (ok, out, err) = vox(
        late,
        &["room", "join", "--passphrase-file", "-", link],
        Some(&format!("{ROOMPASS}\n")),
    );
    assert!(
        ok,
        "PRODUCT: late could not rejoin the room after its visible leave: {out}{err}"
    );
    wait_room_open(late, room, "late-refusal-rejoined");
    let reincarnated = await_lane_claim(
        late,
        room,
        &fps[1],
        room_before,
        "the rejoined room/member lifetime",
        |grown| grown.history_declined > 0,
    );
    assert!(
        !reads(late, room, pruned),
        "PRODUCT: the rejoined room exposed Bob's pruned body instead of recording the new \
         lifetime's refusal: {reincarnated:?}"
    );

    // Restore ordinary local retention through the same shipped reload command. Bob's next
    // authenticated head is the author successor that ends the refusal. The exact user-visible
    // post and history_rearmed counter independently prove delivery and invalidation.
    for (name, dir) in [("alice", alice), ("bob", bob), ("carol", carol)] {
        std::fs::write(dir.join("cfg/retention"), "default forever\n").unwrap_or_else(|error| {
            panic!("APPARATUS: could not restore {name}'s local retention: {error}")
        });
        let (ok, out, err) = vox(dir, &["room", "retention", room, "--steps", "7d"], None);
        assert!(
            ok,
            "PRODUCT: {name}'s shipped retention restore was refused: {out}{err}"
        );
    }
    let successor_before = exact_lane(late, room, &fps[1], "before Bob's successor");
    let successor = "bob successor after the exact declined head";
    let (ok, out, err) = vox(bob, &["room", "post", room, successor], None);
    assert!(
        ok,
        "PRODUCT: Bob's successor to the declined inventory head was refused: {out}{err}"
    );
    let successor_lane = await_lane_claim(
        late,
        room,
        &fps[1],
        successor_before,
        "Bob's authenticated successor head",
        |grown| reads(late, room, successor) && grown.history_rearmed > 0,
    );
    assert!(
        successor_lane.history_fetched > 0,
        "PRODUCT: late read Bob's successor but shipped status did not name fetched history on \
         that exact lane: {successor_lane:?}"
    );

    drop(late_daemon);
    drop(bob_daemon);
}

#[cfg(feature = "optional-proofs")]
fn wait_exact_bounded_running(dir: &Path, room: &str, peer: &str, hold: &Path, claim: &str) {
    let room_line = format!("room={room}");
    let peer_line = format!("peer={peer}");
    loop {
        let marker = charged_flow_hold_entries(hold)
            .into_iter()
            .any(|(_, _, path)| {
                std::fs::read_to_string(path).is_ok_and(|identity| {
                    identity.lines().any(|line| line == room_line)
                        && identity.lines().any(|line| line == peer_line)
                })
            });
        let (ok, out, err) = vox(dir, &["status", "--json"], None);
        assert!(ok, "PRODUCT: shipped status failed at {claim}: {err}");
        let value: serde_json::Value = serde_json::from_str(&out).unwrap_or_else(|error| {
            panic!("PRODUCT: shipped status was not JSON at {claim}: {error}: {out}")
        });
        let exact = value["lanes"]["bounded"]["running"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|row| {
                !row.is_null()
                    && row["room"].as_str() == Some(room)
                    && row["peer"].as_str() == Some(peer)
            });
        if marker && exact {
            return;
        }
        std::thread::yield_now();
    }
}

#[cfg(feature = "optional-proofs")]
#[derive(Clone, Debug, PartialEq, Eq)]
struct ExactRefusal {
    peer: String,
    author: String,
    head: String,
    request: String,
    captured_generation: String,
    current_generation: String,
    remembered: bool,
}

#[cfg(feature = "optional-proofs")]
#[derive(Debug)]
struct RefusalTransition {
    stale: ExactRefusal,
    saved: ExactRefusal,
    lane: QuietLane,
}

#[cfg(feature = "optional-proofs")]
fn parse_exact_refusal(row: &serde_json::Value, field: &str, claim: &str) -> Option<ExactRefusal> {
    let refusal = &row[field];
    if refusal.is_null() {
        return None;
    }
    let text = |name: &str| {
        refusal[name]
            .as_str()
            .unwrap_or_else(|| {
                panic!("PRODUCT: shipped {field} omitted {name} at {claim}: {refusal}")
            })
            .to_owned()
    };
    Some(ExactRefusal {
        peer: text("peer"),
        author: text("author"),
        head: text("head"),
        request: text("request"),
        captured_generation: text("captured_generation"),
        current_generation: text("current_generation"),
        remembered: refusal["remembered"].as_bool().unwrap_or_else(|| {
            panic!("PRODUCT: shipped {field} omitted remembered at {claim}: {refusal}")
        }),
    })
}

/// Observe the transaction held by the apparatus through the product's exact status facts. Lane
/// counters are only a causal terminal fence: they cannot satisfy any identity assertion.
#[cfg(feature = "optional-proofs")]
#[allow(clippy::too_many_arguments)]
fn await_exact_refusal_transition(
    dir: &Path,
    room: &str,
    peer: &str,
    before: QuietLane,
    author: &str,
    head: &str,
    request: &str,
    captured_generation: &str,
) -> RefusalTransition {
    loop {
        let (_, _, status) = synced(dir);
        let value: serde_json::Value = serde_json::from_str(&status).unwrap_or_else(|error| {
            panic!(
                "PRODUCT: `vox status --json` was not JSON while observing the exact refusal transaction: {error}: {status}"
            )
        });
        let row = value["sync"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|row| row["room"].as_str() == Some(room) && row["peer"].as_str() == Some(peer))
            .unwrap_or_else(|| {
                panic!(
                    "PRODUCT: shipped status omitted the exact {room}/{peer} refusal lane: {status}"
                )
            });
        let stale = parse_exact_refusal(row, "history_refusal_stale", "authorization change");
        let saved = parse_exact_refusal(row, "history_refusal_saved", "authorization change");
        let now = quiet_lanes(&status)[&(room.to_owned(), peer.to_owned())];
        let grown = now.since(before);

        if let Some(saved) = &saved {
            assert!(
                !(saved.author == author && saved.head == head && saved.request == request),
                "PRODUCT: the held old-generation refusal transaction was saved under the fresh grant instead of being fenced: {saved:?}"
            );
        }
        let Some(stale) = stale.filter(|stale| stale.request == request) else {
            std::thread::yield_now();
            continue;
        };
        assert!(
            stale.peer == peer
                && stale.author == author
                && stale.head == head
                && stale.captured_generation == captured_generation
                && stale.current_generation != stale.captured_generation,
            "PRODUCT: shipped status did not bind the fenced refusal to the held peer/author/head/request and old-to-fresh authorization generations: {stale:?}"
        );
        if let Some(saved) = saved.filter(|saved| {
            saved.peer == peer
                && saved.author == author
                && saved.head == head
                && saved.request != request
        }) {
            assert!(
                saved.captured_generation == stale.current_generation
                    && saved.current_generation == stale.current_generation
                    && saved.remembered,
                "PRODUCT: the successor refusal was not durably saved under the exact fresh generation fenced by the stale transaction: stale={stale:?}, saved={saved:?}"
            );
            assert!(
                grown.stale > 0 && grown.history_rearmed > 0 && grown.history_declined > 0,
                "PRODUCT: exact stale and successor refusal outcomes were visible, but the shipped lane did not account for fencing, re-arm and durable decline: {grown:?}"
            );
            return RefusalTransition {
                stale,
                saved,
                lane: grown,
            };
        }
        assert!(
            grown.completed == 0,
            "PRODUCT: the exact lane completed a successor cycle after fencing {stale:?} without durably saving the exact fresh-generation refusal; lane delta: {grown:?}"
        );
        std::thread::yield_now();
    }
}

#[cfg(feature = "optional-proofs")]
fn exact_lane(dir: &Path, room: &str, peer: &str, when: &str) -> QuietLane {
    let (_, _, status) = synced(dir);
    quiet_lanes(&status)
        .get(&(room.to_owned(), peer.to_owned()))
        .copied()
        .unwrap_or_else(|| {
            panic!(
                "PRODUCT: `vox status --json` omitted the exact {room}/{peer} lane {when}: \
                 {status}"
            )
        })
}

#[cfg(feature = "optional-proofs")]
fn await_lane_claim(
    dir: &Path,
    room: &str,
    peer: &str,
    before: QuietLane,
    claim: &str,
    done: impl Fn(QuietLane) -> bool,
) -> QuietLane {
    loop {
        let now = exact_lane(dir, room, peer, claim);
        // Leaving and rejoining creates a new room actor and may reset its lane counters. Treat
        // that truthful new generation as its own baseline; saturating every field against the
        // retired actor would otherwise hide all of the new lifetime's visible work.
        let grown = if now.completed < before.completed
            || now.history_declined < before.history_declined
            || now.history_rearmed < before.history_rearmed
        {
            now
        } else {
            now.since(before)
        };
        if done(grown) {
            return grown;
        }
        assert!(
            grown.completed < 2,
            "PRODUCT: the exact {room}/{peer} lane completed two terminal cycles without proving \
             {claim}; its shipped counter delta was {grown:?}"
        );
        std::thread::yield_now();
    }
}

/// Rooms staged together so the bounded backfill has both a long author and independent work.
const WORK_ROOMS: usize = 3;
/// Rows Alice seals in each work room before Bob joins it. The fold and package marker holds below
/// make Bob accept these rows before their author's consent and sender key, respectively.
const BEFORE_KEY: usize = vox_core::node::channel::RENDER_BACKFILL_ROWS_PER_TURN + 1;
/// **Rows parked on missing consent/key cost no busy loop and wake from retained facts**
/// (ADR-038 FX-22, #1007): Bob visibly retains Alice's exact rows while both facts are absent.
/// Alice then becomes unavailable before Bob opens the retained logged key package; Bob MUST
/// render every retained row once and in order.
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
    let consent_entered = root.join("incoming-consent-hold.entered");
    let consent_backfill = root.join("consent-backfill");
    let consent_backfill_entered = root.join("consent-backfill.entered");
    let render_hold = root.join("render-hold");
    let alice_fold_path = alice_fold
        .to_str()
        .expect("APPARATUS: a UTF-8 Alice fold path");
    let bob_fold_path = bob_fold.to_str().expect("APPARATUS: a UTF-8 Bob fold path");

    let (ok, alice_fp, err) = vox(&alice, &["id"], None);
    assert!(ok, "PRODUCT: Alice's `vox id` failed: {err}");
    let (ok, bob_fp, err) = vox(&bob, &["id"], None);
    assert!(ok, "PRODUCT: Bob's `vox id` failed: {err}");
    for (dir, fp, name) in [(&bob, alice_fp.trim(), "alice")] {
        let (ok, out, err) = vox(dir, &["trust", "add", fp, "--name", name], None);
        assert!(ok, "PRODUCT: `vox trust add {name}` failed: {out}{err}");
    }
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
            (
                "VOX_TEST_CONSENT_BACKFILL_FILE",
                consent_backfill
                    .to_str()
                    .expect("APPARATUS: consent backfill path"),
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
    // A room member is the actual precondition for Alice's trust decision; aggregate
    // per-node log counts describe different collections and cannot establish it.
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
    let mut backfill_scope = room_id(&alice, "alice", &room).to_vec();
    backfill_scope.extend_from_slice(
        &vox_core::node::link::b32_decode(alice_fp.trim(), "Alice fingerprint")
            .unwrap_or_else(|error| panic!("APPARATUS: malformed Alice fingerprint: {error}")),
    );
    std::fs::write(&consent_backfill, &backfill_scope)
        .unwrap_or_else(|error| panic!("APPARATUS: cannot arm consent backfill evidence: {error}"));
    std::fs::write(&consent_hold, &consent_scope)
        .unwrap_or_else(|error| panic!("APPARATUS: cannot arm incoming consent hold: {error}"));
    let before_consent = room_hashes(&alice, "alice", &room);
    std::fs::remove_file(&alice_fold)
        .unwrap_or_else(|error| panic!("APPARATUS: could not release Alice's fold: {error}"));
    let (ok, out, err) = vox(
        &alice,
        &[
            "trust",
            "add",
            bob_fp.trim(),
            "--name",
            "bob",
            "--history",
            "full",
        ],
        None,
    );
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
    assert_eq!(
        trust_detail(&bob, "bob", &room, "alice"),
        "you trust it, but it has not trusted you: it cannot read you",
        "APPARATUS: Bob's consent fold did not hold after the key arrived"
    );
    wait_for_held_rows(&bob, &room, &hashes, "consent-fold");
    assert!(
        with_key.received_key_generations >= 1,
        "APPARATUS: key-before-consent was not staged: {with_key:?}"
    );
    while !consent_backfill_entered.exists() {
        assert_eq!(
            trust_detail(&bob, "bob", &room, "alice"),
            "you trust it, but it has not trusted you: it cannot read you",
            "APPARATUS: consent arrived before the keyed backfill attempt"
        );
        std::thread::yield_now();
    }
    assert_eq!(
        std::fs::read(&consent_backfill_entered)
            .unwrap_or_else(|error| panic!("APPARATUS: cannot read backfill evidence: {error}")),
        backfill_scope,
        "APPARATUS: keyed backfill evidence names another room or author"
    );
    // The actual product read, not the marker, determines whether consent prevented disclosure.
    wait_for_held_rows(&bob, &room, &hashes, "keyed-backfill-before-consent");
    std::fs::write(&render_hold, b"")
        .unwrap_or_else(|error| panic!("APPARATUS: cannot arm render hold: {error}"));

    // The real signed consent must reach the held publication, then be durably accepted
    // while rendering remains held. Stop Alice before Bob renders or restarts.
    while !consent_entered.exists() {
        assert_eq!(
            trust_detail(&bob, "bob", &room, "alice"),
            "you trust it, but it has not trusted you: it cannot read you",
            "APPARATUS: Alice's consent reached Bob before the exact consent hold engaged"
        );
        std::thread::yield_now();
    }
    let entered = std::fs::read_to_string(&consent_entered)
        .unwrap_or_else(|error| panic!("APPARATUS: cannot read held consent: {error}"));
    let (scope, hash) = entered
        .rsplit_once(' ')
        .unwrap_or_else(|| panic!("APPARATUS: malformed held-consent evidence: {entered}"));
    assert_eq!(
        scope, consent_scope,
        "APPARATUS: held consent belongs to a different room or peer"
    );
    assert!(
        !before_consent.iter().any(|old| old == hash)
            && room_hashes(&alice, "alice", &room)
                .iter()
                .any(|current| current == hash),
        "APPARATUS: held consent is not a newly published Alice row: {entered}"
    );
    assert_eq!(
        trust_detail(&bob, "bob", &room, "alice"),
        "you trust it, but it has not trusted you: it cannot read you",
        "APPARATUS: another publication path delivered Alice's consent before release"
    );
    assert!(
        room_status(&bob, "bob", &room).received_key_generations >= 1,
        "APPARATUS: sender key disappeared before the held-consent boundary"
    );
    wait_for_held_rows(&bob, &room, &hashes, "consent-held-exact");
    std::fs::remove_file(&consent_hold)
        .unwrap_or_else(|error| panic!("APPARATUS: cannot release incoming consent: {error}"));
    std::fs::remove_file(&bob_fold)
        .unwrap_or_else(|error| panic!("APPARATUS: could not release Bob's fold: {error}"));
    wait_trust_detail(&bob, "bob", &room, "alice", "you trust each other");
    // The render hold is apparatus, not proof that every rendering path is held. Establish
    // the exact user-visible precondition again after consent and before either daemon stops.
    assert_held_rows_at_boundary(&bob, &room, &hashes, "post-consent restart boundary");
    alice_daemon.stop();
    bob_daemon.stop();
    // Verify the boundary survived shutdown: keep the hold armed while Bob returns alone.
    let bob_held_restart = daemon_env(
        &bob,
        "bob-consent-last-held-restart",
        &[(
            "VOX_TEST_HOLD_RENDER_FILE",
            render_hold.to_str().expect("APPARATUS: render hold path"),
        )],
    );
    attached(&bob, "bob-consent-last-held-restart");
    wait_trust_detail(&bob, "bob", &room, "alice", "you trust each other");
    assert_held_rows_at_boundary(&bob, &room, &hashes, "held Bob-only restart");
    // Restart is the real causal wake after removing the apparatus hold; no clock or polling
    // assumption is used as a product state transition.
    bob_held_restart.stop();
    std::fs::remove_file(&render_hold)
        .unwrap_or_else(|error| panic!("APPARATUS: cannot release render hold: {error}"));
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
        "VOX_TEST_CONSENT_BACKFILL_FILE",
        "VOX_TEST_HOLD_PACKAGES_FILE",
        "VOX_TEST_HOLD_RENDER_FILE",
        TEST_EXPIRING_ADMIN_ENV,
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
        let (ok, _, err) = vox(dir, &["trust", "add", fp, "--name", name], None);
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
    let fold_knob = [
        ("VOX_TEST_FOLD_HOLD_FILE", fold_hold_path.as_str()),
        (TEST_EXPIRING_ADMIN_ENV, "1"),
    ];
    let carol_fold_knob = [("VOX_TEST_FOLD_HOLD_FILE", carol_fold_hold_path.as_str())];
    let package_knob = [
        ("VOX_TEST_HOLD_PACKAGES_FILE", package_hold_path.as_str()),
        ("VOX_TEST_HOLD_RENDER_FILE", render_hold_path.as_str()),
    ];
    let alice_daemon = daemon_env(&alice, "alice", &fold_knob);
    let mut carol_daemon = daemon_env(&carol, "carol", &carol_fold_knob);
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
    // Alice's continuation of more than one production page, so eventual exact visibility from
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

    // Alice and Carol have not trusted Bob, so neither can consent or release a key to him.
    // Bob nevertheless accepts their existing LogDb prefixes. The product itself says that
    // the prefix is present, no sender key is held, Alice has not consented, and none of the named
    // content is readable: those are the APPARATUS preconditions for the late-render verdict.
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
        // Each author must have observed Bob as a member before the trust decision.
        for (author, name) in [(&alice, "alice"), (&carol, "carol")] {
            wait_room_status(
                author,
                name,
                room,
                false,
                "author never listed Bob as a room member",
                |status| status.members.iter().any(|member| member == &fps[1]),
            );
        }
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

    // Stage one same-name action while the fold is still held and prove the command appended one
    // exact authenticated room-order object. Command success alone is not the precondition: a
    // mutant that returns success without the append has no new hash and fails here.
    for room in &rooms {
        let before = room_hashes(&alice, "alice", room);
        let appended = rename_hash(&alice, "alice", room, room);
        assert!(
            !before.contains(&appended) && room_hashes(&alice, "alice", room).contains(&appended),
            "PRODUCT: Alice's successful same-name rename named entry {appended}, but that exact \
             authenticated row was not newly present in room {room}"
        );
    }

    // Bob is offline. Each author grants his existing room membership; Bob's own doctor
    // must report mutual trust once he restarts and receives their actual consent.
    std::fs::remove_file(&fold_hold)
        .unwrap_or_else(|error| panic!("APPARATUS: could not release the fold hold: {error}"));
    let (ok, out, err) = vox(
        &alice,
        &[
            "trust",
            "add",
            &fps[1],
            "--name",
            "bob",
            "--history",
            "full",
        ],
        None,
    );
    assert!(
        ok,
        "PRODUCT: Alice could not grant Bob full history: {out}{err}"
    );
    // Marker removal is apparatus, not a product wake. A second authenticated same-name action is
    // the causal event that resumes Alice's released fold.
    for room in &rooms {
        let causal = rename_hash(&alice, "alice", room, room);
        assert!(
            room_hashes(&alice, "alice", room).contains(&causal),
            "PRODUCT: Alice's causal same-name rename named {causal}, but the exact \
             authenticated row was absent after the fold hold was released in room {room}"
        );
    }
    for room in &rooms {
        wait_local_trust(&alice, "alice", room, "bob");
    }
    std::fs::remove_file(&carol_fold_hold)
        .unwrap_or_else(|error| panic!("APPARATUS: could not release Carol's fold hold: {error}"));
    // A real restart resumes the saved governance work after the apparatus hold is removed.
    carol_daemon.stop();
    carol_daemon = daemon_env(&carol, "carol-fold-restarted", &carol_fold_knob);
    attached(&carol, "carol-fold-restarted");
    let (ok, out, err) = vox(
        &carol,
        &[
            "trust",
            "add",
            &fps[1],
            "--name",
            "bob",
            "--history",
            "full",
        ],
        None,
    );
    assert!(
        ok,
        "PRODUCT: Carol could not grant Bob full history: {out}{err}"
    );
    // The real trust command above changes Carol's policy; her room projection may still be
    // completing after restart. Observe her local trust rather than requiring admin authority.
    for room in &rooms {
        wait_local_trust(&carol, "carol", room, "bob");
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

    // Alice now stops, so removing the package marker cannot be confused with a fresh direct key
    // delivery. Once Bob's status says the key landed from his retained log, one exact paged
    // observation proves all rows accepted before key and consent were rendered exactly once and
    // in order.
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
    // Restart is a real causal wake for saved render work after the hold changes.
    bob_daemon.stop();
    bob_daemon = daemon_env(&bob, "bob-fair-turn-restarted", &package_knob);
    attached(&bob, "bob-fair-turn-restarted");

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
        readable_say_body(competing[0]),
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
                    && readable_say_body(row).is_some()
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
    bob_daemon.stop();
    bob_daemon = daemon_env(&bob, "bob-continuation-restarted", &package_knob);
    attached(&bob, "bob-continuation-restarted");

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

    // `trust add` completes only after applying that trust revision and retrying retained logged
    // packages. Both exact authors' generations are already held and both sources are offline, so
    // Alice's retained package presents an unchanged SKDM. The shipped status work observation is
    // causal and exact: no new projection revision and no render continuation may appear. This
    // replaces an aggregate CPU sample that could pass without observing the duplicate at all.
    let duplicate_before = room_status(&bob, "bob", &rooms[0]);
    assert!(
        !duplicate_before.render_backfill_pending,
        "PRODUCT: room {} still reported render backfill before the unchanged key replay: \
         {duplicate_before:?}",
        rooms[0]
    );
    std::fs::write(&render_hold, b"")
        .unwrap_or_else(|error| panic!("APPARATUS: could not engage render hold: {error}"));
    let (ok, out, err) = vox(&bob, &["trust", "add", &fps[0], "--name", "alice"], None);
    assert!(
        ok,
        "PRODUCT: Bob's idempotent `vox trust add alice` could not replay the retained key \
         package: {out}{err}"
    );
    let duplicate_after = room_status(&bob, "bob", &rooms[0]);
    assert_eq!(
        duplicate_after.governance_revision, duplicate_before.governance_revision,
        "PRODUCT: an unchanged retained sender key revised room {}'s governance projection: \
         before {duplicate_before:?}, after {duplicate_after:?}",
        rooms[0]
    );
    assert_eq!(
        duplicate_after.received_key_generations, duplicate_before.received_key_generations,
        "PRODUCT: an unchanged retained sender key changed room {}'s held generations: before \
         {duplicate_before:?}, after {duplicate_after:?}",
        rooms[0]
    );
    assert!(
        !duplicate_after.render_backfill_pending,
        "PRODUCT: an unchanged retained sender key requeued already-rendered history in room {}: \
         before {duplicate_before:?}, after {duplicate_after:?} (ADR-038 FX-22, #1007)",
        rooms[0]
    );
    std::fs::remove_file(&render_hold)
        .unwrap_or_else(|error| panic!("APPARATUS: could not release render hold: {error}"));
    let mut alice_restarted = daemon_env(&alice, "alice", &fold_knob);
    attached(&alice, "alice");

    // Remove Carol through the shipped trust command and wait for Alice's resulting governance
    // projection and Bob's effective mutual trust before the same-value and restart checks.
    let isolation_before = room_status(&alice, "alice", &rooms[0]);
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
    let isolation_revision = isolation_before
        .governance_revision
        .checked_add(2)
        .expect("PRODUCT: Alice's governance revision overflowed while isolating Bob's grant");
    let isolation_settled = wait_room_status(
        &alice,
        "alice",
        &rooms[0],
        false,
        "Carol's removal did not publish its reset and the one Bob-only regrant, or Alice did \
         not finish Bob's resulting key delivery",
        |status| {
            status.governance_revision >= isolation_revision
                && !status
                    .key_delivery_pending
                    .iter()
                    .any(|member| member == &fps[1])
        },
    );
    assert_eq!(
        isolation_settled.governance_revision, isolation_revision,
        "PRODUCT: removing Carol from the three-member trusted-reader set did not publish exactly \
         the one reset and one Bob-only regrant in quiet room {}: before {isolation_before:?}, \
         settled {isolation_settled:?}",
        rooms[0]
    );
    wait_governance_current(
        &alice,
        "alice",
        &rooms[0],
        "Carol's removal and the resulting Bob-only regrant never completed their bounded fold",
    );
    wait_trust_detail(&bob, "bob", &rooms[0], "alice", "you trust each other");

    // A same-value authenticated action exists in the immutable room order but is not a new
    // canonical meaning. Wait on an authority-dependent shipped page so the equal revision below
    // is observed after the exact row was folded, not before asynchronous work began.
    let semantic_before = room_status(&alice, "alice", &rooms[0]);
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
    let semantic_after = room_status(&alice, "alice", &rooms[0]);
    assert_eq!(
        semantic_after.governance_revision, semantic_before.governance_revision,
        "PRODUCT: an authenticated same-name rename revised room {} despite leaving its canonical \
         meaning unchanged: before {semantic_before:?}, after {semantic_after:?}",
        rooms[0]
    );

    // The message and mutual trust must remain available across Bob's restart while both
    // source authors are offline. This checks the user's restart outcome without inferring
    // control-record types or arrival order from the room-order hash list.
    assert_eq!(
        trust_detail(&bob, "bob", &rooms[0], "alice"),
        "you trust each other",
        "APPARATUS: mutual trust was not established before Bob's restart"
    );
    alice_restarted.stop();
    bob_daemon.stop();
    bob_daemon = daemon_env(&bob, "bob-after-source-restart", &package_knob);
    attached(&bob, "bob-after-source-restart");
    wait_governance_current(
        &bob,
        "bob",
        &rooms[0],
        "Bob's governance projection did not settle after restart",
    );
    assert_eq!(
        trust_detail(&bob, "bob", &rooms[0], "alice"),
        "you trust each other",
        "PRODUCT: Bob lost mutual trust after restarting with Alice offline"
    );
    let expected_before: Vec<String> = (0..BEFORE_KEY)
        .map(|row| format!("alice before key room 1 row {row}"))
        .collect();
    assert_exact_read_rows(
        &bob,
        "bob",
        &rooms[0],
        &late_hashes[0],
        &expected_before,
        "Bob restarted with both sources unavailable",
    );
    alice_restarted = daemon_env(&alice, "alice-after-source-restart", &fold_knob);
    attached(&alice, "alice-after-source-restart");
    // Keep both shipped daemons alive for the remaining user journey.
    let _running_after_restart = (&alice_restarted, &bob_daemon);

    // Bob and Carol are offline for this expiry observation. Wait for Alice's existing
    // governance work before granting the short-lived certificate; this does not establish
    // the exact expiry instant or an autonomous wake.
    bob_daemon.stop();
    wait_governance_current(
        &alice,
        "alice",
        &rooms[0],
        "pre-expiry governance did not settle",
    );
    let authority_before = room_status(&alice, "alice", &rooms[0]);
    let (ok, out, err) = vox(&alice, &["room", "admin", "add", &rooms[0], &fps[1]], None);
    assert!(
        ok,
        "PRODUCT: Alice's `vox room admin add` was refused: {out}{err}"
    );
    wait_admin_membership(&alice, "alice", &rooms[0], &fps[1], true);
    let authority_active = wait_room_status(
        &alice,
        "alice",
        &rooms[0],
        false,
        "the effective administrator certificate did not publish a semantic revision",
        |status| status.governance_revision > authority_before.governance_revision,
    );
    assert_eq!(
        authority_active.governance_revision,
        authority_before.governance_revision + 1,
        "PRODUCT: one effective administrator certificate did not publish exactly one semantic \
         governance revision in room {}: before {authority_before:?}, active {authority_active:?}",
        rooms[0]
    );
    // The published roster is the observed expiry boundary. If room entries change between
    // observations, another fact could explain a revision; that run did not stage expiry alone.
    let expiry_order_before = room_hashes(&alice, "alice", &rooms[0]);
    wait_admin_membership(&alice, "alice", &rooms[0], &fps[1], false);
    wait_governance_current(
        &alice,
        "alice",
        &rooms[0],
        "post-expiry governance did not settle",
    );
    let expiry_order_after = room_hashes(&alice, "alice", &rooms[0]);
    assert_eq!(expiry_order_after, expiry_order_before,
        "APPARATUS: room entries changed during the expiry-only observation; the semantic revision cannot be attributed solely to expiry");
    let authority_expired = room_status(&alice, "alice", &rooms[0]);
    assert_eq!(
        authority_expired.governance_revision,
        authority_active.governance_revision + 1,
        "PRODUCT: expiry of one effective administrator certificate did not publish exactly one \
         semantic governance revision in quiet room {}: active {authority_active:?}, expired \
         {authority_expired:?}",
        rooms[0]
    );

    // Bob returns for the separate real revocation observation.
    let _bob_after_expiry = daemon_env(&bob, "bob-after-expiry", &package_knob);
    attached(&bob, "bob-after-expiry");

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
        "you trust it, but it has not trusted you: it cannot read you",
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
/// Rounds a lane may run in the window beyond the ones its live posts and periodic requests
/// account for (ADR-038 FX-15, #996): the join's own rounds (the new port's first exchange, the
/// new connection's, the member record's), the room's generation advancing as bob's rows land,
/// and bob's few own heads (his join's entries). None of them scales with the minute.
const ROUNDS_SLACK: u64 = 10;

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
/// **And the serving lane runs no round without a need `vox status` names** (ADR-038 FX-15;
/// #996). As the minute closes, alice's lane toward bob is read from her `vox status --json`:
/// its `reasons` MUST add up to `completed`, and her own rounds (every reason but `served`,
/// bob's requests she answered) MUST be at most the periodic requests in the window plus two
/// per live post (one announcement, one acknowledgement probe) plus [`ROUNDS_SLACK`]. Measured
/// 2026-10-20 in this staging on two shipped daemons: her lane completed 1,296 rounds in 81 s,
/// of which 1,257 were requests she answered for bob's catch-up (about six per row he fetched)
/// and 39 her own; the 953 "rounds" the issue counted were such requests, which the status
/// now names as `served`.
///
/// Mutants: a round counted without its reason turns the reasons claim red; the lane never
/// recording a peer's acknowledgement (bob's word on alice's feed not noted, so `held_through`
/// stays unknown and the settlement tick offers her head to him every second: FX-15's measured
/// cause) turns the own-round bound red on its own number.
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
    let joined_at = Instant::now();
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
    // The lanes' rounds and why each ran, read as the minute closes (ADR-038 FX-15, #996).
    let worked = joined_at.elapsed();
    let (_, alice_status, _) = vox(&alice, &["status", "--json"], None);
    let (_, bob_status, _) = vox(&bob, &["status", "--json"], None);
    let alice_lane = lane_why(&alice_status);
    let bob_lane = lane_why(&bob_status);
    println!(
        "[proof] over {worked:?} since bob's join, alice's lane toward bob: {alice_lane}; bob's \
         toward alice: {bob_lane}"
    );
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

    // ---- the serving lane ran no round without a need the status names (ADR-038 FX-15, #996) --
    let periodic_rounds = worked.as_secs() / vox_core::node::syncstream::SYNC_INTERVAL_SECS + 1;
    let live_posts = LIVE_POSTS as u64;
    assert!(
        alice_lane.reasons_total() == alice_lane.completed,
        "PRODUCT: alice's `vox status` does not name why every round of her lane ran (ADR-038 \
         FX-15, #996): the reasons add up to {} of {} completed; her lane: {alice_lane}",
        alice_lane.reasons_total(),
        alice_lane.completed
    );
    let own = alice_lane
        .completed
        .saturating_sub(alice_lane.reason("served"));
    assert!(
        own <= periodic_rounds + 2 * live_posts + ROUNDS_SLACK,
        "PRODUCT: alice's lane toward a member catching up ran {own} rounds of her own over \
         {worked:?} (ADR-038 FX-15, #996); one announcement and one acknowledgement probe per \
         live post ({live_posts}), the periodic requests ({periodic_rounds}) and {ROUNDS_SLACK} \
         more is every need the status names; her lane: {alice_lane}; bob asked for \
         {pages_asked} pages\nalice's daemon said: {}",
        said(&alice, "alice")
    );
}

/// What a node's lanes did, summed over its peers, from `vox status --json`: the completed
/// rounds and why each ran (ADR-038 FX-15, #996), the partial and failed ones, and each lane's
/// last failure in its own words.
struct LaneWhy {
    completed: u64,
    partial: u64,
    failed: u64,
    last_failure: Vec<String>,
    reasons: std::collections::BTreeMap<String, u64>,
}

/// One exact lane's shipped counters that distinguish a genuinely empty quiet round from
/// repeated history work. The product publishes these per room and peer; summing them would let
/// one busy lane hide behind another, so the FX-29 verdict compares each lane independently.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[cfg(feature = "optional-proofs")]
struct QuietLane {
    completed: u64,
    empty: u64,
    history_fetched: u64,
    history_served: u64,
    history_declined: u64,
    history_offered: u64,
    history_rearmed: u64,
    stale: u64,
}

#[cfg(feature = "optional-proofs")]
impl QuietLane {
    fn since(self, before: Self) -> Self {
        Self {
            completed: self.completed.saturating_sub(before.completed),
            empty: self.empty.saturating_sub(before.empty),
            history_fetched: self.history_fetched.saturating_sub(before.history_fetched),
            history_served: self.history_served.saturating_sub(before.history_served),
            history_declined: self
                .history_declined
                .saturating_sub(before.history_declined),
            history_offered: self.history_offered.saturating_sub(before.history_offered),
            history_rearmed: self.history_rearmed.saturating_sub(before.history_rearmed),
            stale: self.stale.saturating_sub(before.stale),
        }
    }
}

/// The exact room/peer lanes in one shipped status document, with every FX-29 field required.
#[cfg(feature = "optional-proofs")]
fn quiet_lanes(status: &str) -> BTreeMap<(String, String), QuietLane> {
    let value: serde_json::Value = serde_json::from_str(status).unwrap_or_else(|error| {
        panic!("PRODUCT: `vox status --json` was not JSON for the quiet-lane verdict: {error}: {status}")
    });
    value["sync"]
        .as_array()
        .unwrap_or_else(|| panic!("PRODUCT: `vox status --json` omitted its sync lanes: {status}"))
        .iter()
        .map(|lane| {
            let text = |field: &str| {
                lane[field]
                    .as_str()
                    .unwrap_or_else(|| {
                        panic!("PRODUCT: a shipped sync lane omitted {field}: {lane}")
                    })
                    .to_owned()
            };
            let count = |field: &str| {
                lane[field].as_u64().unwrap_or_else(|| {
                    panic!("PRODUCT: a shipped sync lane omitted counter {field}: {lane}")
                })
            };
            (
                (text("room"), text("peer")),
                QuietLane {
                    completed: count("completed"),
                    empty: count("empty"),
                    history_fetched: count("history_fetched"),
                    history_served: count("history_served"),
                    history_declined: count("history_declined"),
                    history_offered: count("history_offered"),
                    history_rearmed: count("history_rearmed"),
                    stale: count("stale"),
                },
            )
        })
        .collect()
}

/// What a person can observe of a node's complete store artifact at one quiet-window edge.
/// Bytes catch any durable mutation; mtime independently catches a write that happened to
/// reproduce the same bytes. No private redb field decides this verdict.
#[cfg(feature = "optional-proofs")]
struct StoreArtifact {
    path: std::path::PathBuf,
    bytes: Vec<u8>,
    modified: std::time::SystemTime,
}

#[cfg(feature = "optional-proofs")]
fn store_artifacts(profiles: &[(&str, &Path)]) -> BTreeMap<String, StoreArtifact> {
    profiles
        .iter()
        .map(|(name, root)| {
            let nodes = root.join("nodes");
            let mut stores: Vec<_> = std::fs::read_dir(&nodes)
                .unwrap_or_else(|error| {
                    panic!("APPARATUS: could not list {}: {error}", nodes.display())
                })
                .flatten()
                .map(|entry| entry.path().join("store.redb"))
                .filter(|path| path.is_file())
                .collect();
            assert_eq!(
                stores.len(),
                1,
                "APPARATUS: {name}'s scratch profile does not contain exactly one shipped node store: {stores:?}"
            );
            let path = stores.remove(0);
            let bytes = std::fs::read(&path).unwrap_or_else(|error| {
                panic!("APPARATUS: could not snapshot {}: {error}", path.display())
            });
            let modified = std::fs::metadata(&path)
                .and_then(|metadata| metadata.modified())
                .unwrap_or_else(|error| {
                    panic!(
                        "APPARATUS: could not read {}'s modification time: {error}",
                        path.display()
                    )
                });
            (
                (*name).to_owned(),
                StoreArtifact {
                    path,
                    bytes,
                    modified,
                },
            )
        })
        .collect()
}

impl LaneWhy {
    fn reason(&self, name: &str) -> u64 {
        self.reasons.get(name).copied().unwrap_or(0)
    }
    fn reasons_total(&self) -> u64 {
        self.reasons.values().sum()
    }
}

impl std::fmt::Display for LaneWhy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "completed {} (why: {}) partial {} failed {} last_failure {:?}",
            self.completed,
            self.reasons
                .iter()
                .map(|(name, n)| format!("{name} {n}"))
                .collect::<Vec<_>>()
                .join(", "),
            self.partial,
            self.failed,
            self.last_failure
        )
    }
}

fn lane_why(status: &str) -> LaneWhy {
    let v: serde_json::Value = serde_json::from_str(status)
        .unwrap_or_else(|e| panic!("APPARATUS: `vox status --json` is not JSON: {e}: {status}"));
    let lanes = v["sync"]
        .as_array()
        .unwrap_or_else(|| panic!("APPARATUS: `vox status --json` has no `sync` lanes: {status}"));
    let mut out = LaneWhy {
        completed: 0,
        partial: 0,
        failed: 0,
        last_failure: Vec::new(),
        reasons: std::collections::BTreeMap::new(),
    };
    for lane in lanes {
        out.completed += lane["completed"].as_u64().unwrap_or(0);
        out.partial += lane["partial"].as_u64().unwrap_or(0);
        out.failed += lane["failed"].as_u64().unwrap_or(0);
        if let Some(why) = lane["reasons"].as_object() {
            for (name, n) in why {
                *out.reasons.entry(name.clone()).or_insert(0) += n.as_u64().unwrap_or(0);
            }
        }
        if let Some(f) = lane["last_failure"].as_str() {
            out.last_failure.push(f.to_owned());
        }
    }
    out
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

struct OfflineFallbackObservation {
    serial: u64,
    active: Vec<u64>,
    fallback: Option<(u64, Option<u64>, Option<u64>)>,
}

/// One shipped snapshot of the exact member-delivery reach and its store-and-forward result.
/// The actor publishes both under `lanes`, so a removed failure callback becomes a PRODUCT red
/// (the attempt vanished without a result) rather than an external-watchdog diagnosis.
fn offline_fallback_observation(
    dir: &Path,
    room: &str,
    member: &str,
) -> OfflineFallbackObservation {
    let (ok, out, err) = vox(dir, &["status", "--json"], None);
    assert!(
        ok,
        "PRODUCT: `vox status --json` refused while observing offline delivery: {out}{err}"
    );
    let value: serde_json::Value = serde_json::from_str(&out).unwrap_or_else(|error| {
        panic!("PRODUCT: offline-delivery status was malformed JSON ({error}): {out}")
    });
    let lanes = &value["lanes"];
    let serial = lanes["member_reach_serial"].as_u64().unwrap_or_else(|| {
        panic!("PRODUCT: shipped status omitted the member-reach serial: {out}")
    });
    let active = lanes["member_reaches"]
        .as_array()
        .unwrap_or_else(|| panic!("PRODUCT: shipped status omitted exact member reaches: {out}"))
        .iter()
        .filter(|row| {
            row["room"]
                .as_str()
                .is_some_and(|candidate| candidate.starts_with(room))
                && row["peer"].as_str() == Some(member)
                && row["asked"].as_bool() == Some(true)
        })
        .filter_map(|row| row["attempt"].as_u64())
        .collect();
    let fallback = lanes["offline_fallbacks"]
        .as_array()
        .unwrap_or_else(|| {
            panic!("PRODUCT: shipped status omitted exact offline fallback results: {out}")
        })
        .iter()
        .find(|row| {
            row["source_room"]
                .as_str()
                .is_some_and(|candidate| candidate.starts_with(room))
                && row["room"]
                    .as_str()
                    .is_some_and(|candidate| candidate.starts_with(room))
                && row["peer"].as_str() == Some(member)
                && row["asked"].as_bool() == Some(true)
        })
        .and_then(|row| {
            Some((
                row["attempt"].as_u64()?,
                row["package_seq"].as_u64(),
                row["consent_seq"].as_u64(),
            ))
        });
    OfflineFallbackObservation {
        serial,
        active,
        fallback,
    }
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
        .find(|row| row["id"].as_str() == Some(member))?["holds_through"]
        .as_u64()
}

/// The last completed sync this profile reports for one exact room member. `None` is also the
/// honest result before that pair has completed a session.
fn member_last_sync(dir: &Path, room: &str, member: &str) -> Option<u64> {
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
        .find(|row| row["id"].as_str() == Some(member))?["last_sync_ms"]
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

/// Completed sync rounds per peer, from `vox status --json`'s lanes; an unreadable or malformed
/// shipped answer is a product red, never a zero that reads as quiet.
fn completed_rounds(dir: &Path) -> std::collections::BTreeMap<String, u64> {
    let (ok, out, err) = vox(dir, &["status", "--json"], None);
    assert!(
        ok,
        "PRODUCT: `vox status --json` failed while counting rounds: {err}"
    );
    let v: serde_json::Value = serde_json::from_str(&out)
        .unwrap_or_else(|e| panic!("PRODUCT: `vox status --json` is not JSON: {e}: {out}"));
    let lanes = v["sync"]
        .as_array()
        .unwrap_or_else(|| panic!("PRODUCT: `vox status --json` has no `sync` lanes: {out}"));
    let mut rounds = std::collections::BTreeMap::new();
    for lane in lanes {
        let peer = lane["peer"]
            .as_str()
            .unwrap_or_else(|| panic!("PRODUCT: a status lane names no peer: {lane}"))
            .to_owned();
        let completed = lane["completed"]
            .as_u64()
            .unwrap_or_else(|| panic!("PRODUCT: a status lane counts no completed rounds: {lane}"));
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
            assert_history_owned(&bob, &room, &fps[0], now, posts);
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
