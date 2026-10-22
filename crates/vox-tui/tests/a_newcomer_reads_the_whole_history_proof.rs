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
);

#[path = "support/test_knobs.rs"]
mod test_knobs;
#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/attach.rs"]
mod attach;

#[path = "support/typed.rs"]
mod typed;

#[cfg(feature = "optional-proofs")]
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
fn attached_as(dir: &Path, tag: &str, node: Option<&str>) -> String {
    let deadline = Instant::now() + Duration::from_secs(90);
    let mut last = String::new();
    while Instant::now() < deadline {
        let (ok, out, err) = vox(dir, &as_node(&["room", "list"], node), None);
        if ok {
            return out;
        }
        last = err;
        std::thread::sleep(Duration::from_millis(200));
    }
    panic!(
        "APPARATUS: {tag}'s daemon never answered `vox room list` in 90 s: {last}\nits stderr: {}",
        said(dir, tag)
    );
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
        std::thread::yield_now();
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
        history["owner"]["room"]
            .as_str()
            .is_some_and(|candidate| candidate.starts_with(room))
            && history["owner"]["peer"].as_str() == Some(peer)
            && history["owner"]["request"].as_str().is_some()
            && history["owner"]["instance"].as_str().is_some()
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
    _peer_daemon: Daemon,
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
    _tmp: tempfile::TempDir,
}

/// Retry only the shipped room's explicit transient "still being applied" refusal. Every other
/// refusal is the exact staging fault; only the proof's external APPARATUS deadman can stop a
/// still-progressing retry sequence.
fn stage_post(dir: &Path, node: Option<&str>, name: &str, room: &str, text: &str) -> Duration {
    let asked = Instant::now();
    loop {
        let (ok, out, err) = stage_post_once(dir, node, room, text, false);
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

fn stage_large_post(
    dir: &Path,
    node: Option<&str>,
    name: &str,
    room: &str,
    text: &str,
) -> Duration {
    let asked = Instant::now();
    loop {
        let (ok, out, err) = stage_post_once(dir, node, room, text, true);
        if ok {
            return asked.elapsed();
        }
        let busy = err.contains("still being applied") || out.contains("still being applied");
        assert!(
            busy,
            "APPARATUS: {name}'s large staging post in {room} was refused before the measured \
             moment: {out}{err}"
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
    stdin: bool,
) -> (bool, String, String) {
    let mut args = vec!["room", "post", room, if stdin { "-" } else { text }];
    if let Some(node) = node {
        args.extend(["--node", node]);
    }
    vox(dir, &args, stdin.then_some(text))
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
            return room;
        }
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
    // The rooms: the first hosted node makes each, and every other node joins by its link.
    let maker = Some(hosted[0]);
    let mut rooms = Vec::with_capacity(QUIET_ROOMS.len());
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
    }
    // One post each in each room, and every node reads every other's within BOUND. A post the
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
        _host_daemon: host_daemon,
        _peer_daemon: peer_daemon,
        host,
        everyone,
        rooms,
        posted,
        waited,
        hosted: hosted.len(),
        live_hold,
        archive_hold,
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
/// means a parked flow retained one. Observe the structural quiet edge so the park mutant has its
/// own PRODUCT discriminator, independent of the pool-derived port projection and of elapsed
/// time.
#[cfg(feature = "optional-proofs")]
fn parked_flow_charge_discriminator(staged: &Staged) {
    loop {
        let mut active = Vec::new();
        let mut retained_control = Vec::new();
        for (dir, node, name, fingerprint) in &staged.everyone {
            let shown = fx35_synced(dir, *node);
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
        if active.is_empty() && retained_control.is_empty() {
            return;
        }
        if active.is_empty() {
            panic!(
                "PRODUCT: bounded controllers have no running worker, but parked flows retain \
                 admitted \
                 Control jobs: {retained_control:?}"
            );
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// The gates a start attempt can end at, in the order the daemon tests them (ADR-038 FX-35).
const START_REASONS: [&str; 6] = [
    "room_busy",
    "archive_budget_busy",
    "control_budget_busy",
    "live_lane_busy",
    "no_outbound_slot",
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
                    panic!("PRODUCT: {who}'s shipped room tail failed: {error}")
                }
                Err(error) if product => panic!(
                    "PRODUCT: {who}'s already-running shipped room tail ended without showing \
                     {target:?} from the exact release edge: {error}"
                ),
                Ok((_, Err(error))) => {
                    panic!("APPARATUS: {who}'s staging room tail failed: {error}")
                }
                Err(error) => panic!(
                    "APPARATUS: {who}'s staging room tail ended without showing {target:?}: \
                     {error}"
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
    loop {
        let shown = fx35_synced(&staged.host, Some(FX35_HOSTED[0]));
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

    let refused = loop {
        let replacement = fx35_synced(&staged.host, Some(running_name));
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
                            && port["start_reason"] == "flow_state_pool_full"
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
        let by_node = pool["by_node"]
            .as_object()
            .expect("PRODUCT: generation-accounting status omitted by_node");
        let expected_limit = vox_core::node::history_budget::FLOW_STATE_CAPACITY
            .max(vox_core::node::history_budget::BOUNDED_SYNC_RUNNING_SLOTS * staged.hosted)
            as u64;
        let actor_sum: u64 = pool["actors"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|actor| actor["in_use"].as_u64())
            .sum();
        let running_count = pool["running"].as_array().map_or(0, Vec::len) as u64;
        if old.is_some() && new.is_some() && running_old && running_new {
            let exact_refusal = exact_refusal.unwrap_or_else(|| {
                panic!(
                    "PRODUCT: the retired and replacement actor each own one running source slot, \
                     but shipped status names no exact room/peer/root/lane `node_slots` waiter for \
                     the third eligible Flow: {}",
                    replacement["lanes"]
                )
            });
            assert!(
                generations.len() == 2
                    && retiring
                    && by_node.len() == staged.hosted
                    && by_node
                        .get(&running_fingerprint)
                        .and_then(serde_json::Value::as_u64)
                        == Some(2)
                    && pool["in_use"].as_u64() == Some(actor_sum)
                    && running_count == actor_sum
                    && pool["in_use"]
                        .as_u64()
                        .zip(pool["limit"].as_u64())
                        .is_some_and(|(in_use, limit)| in_use < limit)
                    && pool["limit"] == expected_limit,
                "PRODUCT: `vox status --json` did not aggregate the retired and replacement \
                 actor into the same two node slots, or did not account its exact waiter: {}",
                pool
            );
            break exact_refusal;
        }
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
            std::thread::sleep(Duration::from_millis(200));
        }
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
/// `scratchpad/mutant_fx35_release_wake.py` drops both exact release wakes; the already-attached
/// shipped tail and retained exact admission then expose the missing causal release while periodic
/// scheduling is disabled and no post-release request can stand in for it; dropping archive
/// ownership turns the exact shipped archive request's structural ownership assertion red;
/// `scratchpad/mutant_fx35_node_release.py` drops the charged worker's pool, lane and completion
/// release notifications, so the exact room/peer/root/lane NodeBusy admission remains visible
/// but its already-attached tail turns PRODUCT red without a command that could schedule it;
/// giving a replacement generation two new node slots instead of sharing the retired actor's
/// source-owned pair prevents the exact NodeBusy verdict and makes the generation assertion
/// PRODUCT-red (and returning PoolFull names that separate PRODUCT defect); removing the
/// post-quiet need re-arm leaves the waiting node short of the named `re-armed` posts.
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
    let staged = stage_hosted_nodes(&FX35_HOSTED, true, false, true);
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
    let (pressure_dir, pressure_node, pressure_name, _) = &staged.everyone[staged.hosted];
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
    let observed = 'pressure: loop {
        for (dir, node, name, _) in &staged.everyone[..staged.hosted] {
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
                    > vox_core::node::history_budget::FLOW_STATE_CAPACITY as u64
                    || !full_ports.is_empty();
            }
            for flow in bounded["ready"]
                .as_array()
                .into_iter()
                .flatten()
                .chain(bounded["admissions"].as_array().into_iter().flatten())
                .filter(|flow| {
                    flow["room"]
                        .as_str()
                        .zip(flow["peer"].as_str())
                        .is_some_and(|(room, peer)| {
                            full_ports.contains(&(room.to_owned(), peer.to_owned()))
                        })
                })
            {
                required_pool_full_seen |= flow["root"] == "required";
                if flow["room"] == *pressure_room && required_pool_full_seen {
                    live_pool_full = Some((*name, Instant::now()));
                    most_pressure = most_pressure.max(in_use);
                    break 'pressure most_pressure;
                }
            }
            most_pressure = most_pressure.max(in_use);
        }
        if most_pressure > vox_core::node::history_budget::FLOW_STATE_CAPACITY as u64 {
            break most_pressure;
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
        std::thread::sleep(Duration::from_millis(200));
    }
    // The two consumed archive dispatches must also finish. Under the undersized mutant, this
    // observes the full-pool branch retain and retry exact archive work before the invariant red
    // is judged; a lost dispatch fails here on the shipped request's own status.
    for (dir, node, name, fingerprint) in
        &staged.everyone[..vox_core::node::history_budget::ARCHIVE_JOBS]
    {
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
                let expected_limit = vox_core::node::history_budget::FLOW_STATE_CAPACITY
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
    let staged = stage_hosted_nodes(&FX35_WAKE_HOSTED, true, true, true);
    converged(&staged);
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
    let room = &staged.rooms[0];
    for (dir, node, name, _) in &staged.everyone[..staged.hosted] {
        let text = format!("{name} re-armed");
        stage_post(dir, *node, name, room, &text);
    }
    let (waiting_dir, waiting_node, waiting_name, parked) = loop {
        let mut found = None;
        let mut running = 0u64;
        for (dir, node, name, _) in &staged.everyone[..staged.hosted] {
            let shown = fx35_synced(dir, *node);
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
        let _ = has_waiter;
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
    loop {
        match lines_rx.recv() {
            Ok(Ok(line)) if line.contains(&ready) => break,
            Ok(Ok(_)) => {}
            Ok(Err(error)) => {
                panic!("APPARATUS: release-observer tail could not read stdout: {error}")
            }
            Err(error) => panic!(
                "APPARATUS: release-observer tail ended without its pre-release ready marker: \
                 {error}"
            ),
        }
    }

    // Bind the decisive release to the same exact admission observed before any staging command.
    // This status request may schedule ports, but the held foreground job still owns capacity;
    // the original admission (same token, gate, room, peer, root and lane) must remain parked.
    let shown = fx35_synced(&waiting_dir, waiting_node);
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
    loop {
        match lines_rx.recv() {
            Ok(Ok(line)) if line.contains(&target) => break,
            Ok(Ok(_)) => {}
            Ok(Err(error)) => panic!(
                "PRODUCT: {waiting_name}'s shipped room tail failed after foreground release: {error}"
            ),
            Err(error) => panic!(
                "PRODUCT: {waiting_name}'s shipped tail ended without the retained target after \
                 exact foreground release while periodic scheduling was disabled: {error}; \
                 admission {parked}"
            ),
        }
    }
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
        std::thread::sleep(Duration::from_millis(200));
    }
    let _ = tail.kill();
    let _ = tail.wait();
    let _ = reader.join();
}

/// **A quiet room costs nothing and says when it last synced** (ADR-038 FX-15, FX-16; #979,
/// #980, #996): alice and bob, each on a daemon of their own, read each other once. Carol joins,
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
/// partial forever.
///
/// Mutants: the own-head hint offered to every peer on every tick again (`offer_own_head`
/// ignoring who acknowledged) turns the round-count claim red; undoing role-aware settlement for
/// the non-recipient package turns the exact held-through assertion red; restoring direct
/// inventory credit turns the pre-release no-credit assertion red when Bob echoes Alice's merely
/// committed head; granting body credit persists the hostile
/// ciphertext and turns the Bob-only privacy assertion red; moving the archive cursor
/// below the role-only header before its effect makes the interrupted request finish with debt;
/// skipping the already-settled callback or rejecting its terminal replay strands the resumed
/// request; dropping bounded continuation stalls the exact older-row assertion; each mutation
/// has its own script and PRODUCT red. The lane's completion no longer recording the sync
/// (`note_lane_sync` removed) turns the last-sync claim red.
#[cfg(feature = "optional-proofs")]
#[test]
#[ignore = "an idle minute on two real vox daemons; optional, run it in release"]
fn a_quiet_room_costs_no_rounds_and_says_when_it_last_synced() {
    test_knobs::require(&[
        "VOX_TEST_HOLD_PACKAGES_FILE",
        "VOX_TEST_SERVE_NONRECIPIENT_HISTORY_BODY_FILE",
        "VOX_TEST_HOLD_ROLE_HEADER_SETTLEMENT_FILE",
        "VOX_TEST_HISTORY_BODY_DURABLE_FILE",
    ]);
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap_or_else(|e| panic!("APPARATUS: no temp dir: {e}"));
    let root = tmp.path();
    let alice = root.join("alice");
    let bob = root.join("bob");
    let carol = root.join("carol");
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
    for (dir, fp, name) in [
        (&alice, &fps[1], "bob"),
        (&bob, &fps[0], "alice"),
        (&carol, &fps[0], "alice"),
        (&carol, &fps[1], "bob"),
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
    let body_durable = root.join("history-body-durable");
    let body_durable_path = body_durable
        .to_str()
        .expect("APPARATUS: a UTF-8 durable-body marker path")
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
    let bob_daemon = daemon(&bob, "bob");
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
    let settlement_deadline = Instant::now() + READY_WITHIN;
    while !settlement_engaged.is_file()
        && std::fs::read(&body_durable).ok().as_deref() != Some(hostile_hash.as_slice())
    {
        assert!(
            Instant::now() < settlement_deadline,
            "APPARATUS: Bob neither durably parked Carol's role-only header nor durably stored the \
             exact hostile body within {READY_WITHIN:?}; the interruption was not staged\n\
             bob said: {}",
            said(&bob, "bob-after-gap")
        );
        std::thread::sleep(Duration::from_millis(200));
    }
    let refused_body = settlement_engaged.is_file();
    if refused_body {
        let held_status = history_status(&bob, &room);
        assert!(
            held_status.0 != "complete" && held_status.1 != 0,
            "PRODUCT: before Carol's role-only header was semantically settled, Bob reported the \
             archive request complete with no remaining debt: {held_status:?}"
        );
    } else {
        assert_eq!(
            std::fs::read(&body_durable).ok().as_deref(),
            Some(hostile_hash.as_slice()),
            "APPARATUS: Bob's receiver marker did not match Alice's exact hostile entry"
        );
    }
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
    // Stop at the exact durable boundary, then resume through the shipped command. The healthy
    // product parked the refused body at its header; the grant-credit mutant parked the exact
    // forbidden body after append. Either restart must continue this request rather than invent an
    // older cursor or a false terminal state.
    bob_after_gap.stop();
    let interruption = if refused_body {
        &settlement_engaged
    } else {
        &body_durable
    };
    std::fs::remove_file(interruption).unwrap_or_else(|e| {
        panic!(
            "APPARATUS: could not release {} after Bob stopped: {e}",
            interruption.display()
        )
    });
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
    let crossed_deadline = Instant::now() + READY_WITHIN;
    while member_held_through(&alice, &room, &fps[1]) != Some(marker_through) {
        assert!(
            Instant::now() < crossed_deadline,
            "PRODUCT: within {READY_WITHIN:?}, alice did not report Bob holding her authenticated \
             room feed through {marker_through}; Carol's header-only package did not settle \
             contiguously for Bob's role\n\
             bob's daemon said: {}",
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
    // ---- the room is quiet: acknowledgements settle, then the rounds are counted ----------
    let before = [synced(&alice), synced(&bob)];
    let before_lanes = [lane_why(&before[0].2), lane_why(&before[1].2)];
    let counted = Instant::now();
    std::thread::sleep(IDLE);
    let after = [synced(&alice), synced(&bob)];
    let after_lanes = [lane_why(&after[0].2), lane_why(&after[1].2)];
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
    let _bob_after_restart = daemon(&bob, "bob-after-restart");
    attached(&bob, "bob-after-restart");
    wait_room_open(&bob, &room, "bob-after-restart");
    let restart_deadline = Instant::now() + READY_WITHIN;
    while member_holds_through(&bob, &room, &fps[0]) != Some(marker_through)
        || member_holds_through(&bob, &room, &fps[2]) != Some(carol_tail_through)
    {
        assert!(
            Instant::now() < restart_deadline,
            "PRODUCT: restarted Bob's `vox status --json` did not restore the exact authenticated \
             contiguous feed heads for Alice through {marker_through} and Carol through \
             {carol_tail_through} within {READY_WITHIN:?}\nbob said: {}",
            said(&bob, "bob-after-restart")
        );
        std::thread::sleep(Duration::from_millis(200));
    }

    // Alice now goes offline. Release Carol's package hold only after Carol and Bob are running,
    // then wait for a completed Carol↔Bob sync (not elapsed silence). If Bob persisted the hostile
    // ciphertext, he can serve it and Carol will show Alice's tail. The correct product completed
    // that sync but has only the authenticated package header, so her shipped read remains absent.
    alice_daemon.stop();
    let _carol_daemon = daemon_env(&carol, "carol-from-bob", &knob);
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
    // oldest live-window row. In the grant-credit mutant, the forbidden body crosses that request
    // and schedules a separate package-maintenance turn. The hold keeps its shipped pending bit
    // observable until the proof releases it, so the privacy read cannot win an actor-scheduling
    // race. The healthy product has only the role-complete header and schedules no such turn.
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

    if !refused_body {
        let staged_deadline = Instant::now() + READY_WITHIN;
        while key_packages_pending(&carol, &room) != Some(true) {
            assert!(
                Instant::now() < staged_deadline,
                "APPARATUS: Bob's exact durably stored hostile package did not reach Carol's \
                 shipped key-packages-pending state within {READY_WITHIN:?} after her explicit \
                 Alice-history request; the grant-credit privacy precondition was not staged\n\
                 carol said: {}\nbob said: {}",
                said(&carol, "carol-from-bob"),
                said(&bob, "bob-after-restart")
            );
            std::thread::yield_now();
        }
    }
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
    watchdog::arm();
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
