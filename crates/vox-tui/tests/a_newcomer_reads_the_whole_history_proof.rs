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
    let file = |kind: &str| {
        let at = dir.join(format!("daemon-{tag}.{kind}"));
        std::fs::File::create(&at)
            .unwrap_or_else(|e| panic!("APPARATUS: could not create {}: {e}", at.display()))
    };
    let mut cmd = Command::new(VOX);
    cmd.args(["daemon", "--listen", "127.0.0.1:0"])
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
fn attached(dir: &Path, _tag: &str) -> String {
    const APPARATUS_ATTACH_RETRY_PACE: Duration = Duration::from_millis(200);
    loop {
        let (ok, out, err) = vox(dir, &["room", "list"], None);
        if ok {
            return out;
        }
        let _ = err;
        std::thread::sleep(APPARATUS_ATTACH_RETRY_PACE);
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

/// Wait until the exact rows Alice posted are visibly present in Bob's paged log, while none has
/// text he can read. That is the user-visible evidence that those rows were accepted before their
/// missing prerequisite; counts alone could be satisfied by Bob's own join records.
fn wait_for_held_rows(dir: &Path, room: &str, expected_hashes: &[String], hold: &str) {
    loop {
        let rows = room_rows(dir, room);
        let staged: Vec<&serde_json::Value> = rows
            .iter()
            .filter(|row| {
                row["entry_hash"]
                    .as_str()
                    .is_some_and(|hash| expected_hashes.iter().any(|expected| expected == hash))
            })
            .collect();
        if staged.len() < expected_hashes.len() {
            std::thread::sleep(Duration::from_millis(100));
            continue;
        }
        let actual_hashes: Vec<&str> = staged
            .iter()
            .filter_map(|row| row["entry_hash"].as_str())
            .collect();
        assert_eq!(
            actual_hashes, expected_hashes,
            "APPARATUS: the exact late rows were not staged once each in source order while the \
             {hold} hold was engaged in room {room}; all rows: {rows:?}"
        );
        assert!(
            staged.iter().all(|row| row["text"].as_str().is_none()),
            "PRODUCT: an exact late row was readable while the {hold} hold proved its required \
             consent/key fact absent \
             in room {room}; staged rows: {staged:?}"
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
                    .then(|| (hash.to_owned(), row["text"].as_str().map(str::to_owned)))
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
                        .then(|| (hash.to_owned(), row["text"].as_str().map(str::to_owned)))
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

#[derive(Clone, Copy, Debug)]
struct RoomStatus {
    log_entries: u64,
    received_key_generations: u64,
    governance_revision: u64,
    render_backfill_pending: bool,
}

/// What the shipped status command says about one room. Refused or malformed output is a product
/// red even while the proof is arranging its deliberate holds: it is still the shipped command's
/// user-visible answer.
fn room_status(dir: &Path, reader: &str, room: &str) -> RoomStatus {
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
                 {out}"
            )
        });
    RoomStatus {
        log_entries: row["log_entries"].as_u64().unwrap_or_else(|| {
            panic!("PRODUCT: {reader}'s room status has no numeric `log_entries`: {row}")
        }),
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
    }
}

fn room_id(dir: &Path, reader: &str, room: &str) -> vox_core::hash::Digest32 {
    let (ok, out, err) = vox(dir, &["status", "--json"], None);
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
            rooms
                .iter()
                .find(|row| row["id"].as_str().is_some_and(|id| id.starts_with(room)))
        })
        .and_then(|row| row["id"].as_str())
        .unwrap_or_else(|| panic!("PRODUCT: {reader}'s status omitted room {room}: {out}"));
    vox_core::node::link::b32_decode(id, "status room id").unwrap_or_else(|error| {
        panic!("PRODUCT: {reader}'s status named a malformed room id: {error}")
    })
}

/// Exact authenticated room-order hashes exposed by the shipped diagnostic command.
fn room_hashes(dir: &Path, reader: &str, room: &str) -> Vec<String> {
    let (ok, out, err) = vox(dir, &["room", "read", room, "--hashes"], None);
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
    _claim: &str,
    ready: impl Fn(RoomStatus) -> bool,
) -> RoomStatus {
    loop {
        let status = room_status(dir, reader, room);
        assert!(
            !key_must_stay_held || status.received_key_generations == 0,
            "APPARATUS: {reader} accepted a sender key in room {room} while the package hold \
             marker still existed: {status:?}"
        );
        if ready(status) {
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

/// Rooms staged together so the bounded backfill has both a long author and independent work.
const WORK_ROOMS: usize = 3;
/// Rows Alice seals in each work room before Bob joins it. The fold and package marker holds below
/// make Bob accept these rows before their author's consent and sender key, respectively.
const BEFORE_KEY: usize = 4 * vox_core::node::channel::RENDER_BACKFILL_ROWS_PER_TURN + 1;
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
    let alice_fold_path = alice_fold
        .to_str()
        .expect("APPARATUS: a UTF-8 Alice fold path");
    let bob_fold_path = bob_fold.to_str().expect("APPARATUS: a UTF-8 Bob fold path");

    let (ok, alice_fp, err) = vox(&alice, &["id"], None);
    assert!(ok, "PRODUCT: Alice's `vox id` failed: {err}");
    let (ok, bob_fp, err) = vox(&bob, &["id"], None);
    assert!(ok, "PRODUCT: Bob's `vox id` failed: {err}");
    for (dir, fp, name) in [
        (&alice, bob_fp.trim(), "bob"),
        (&bob, alice_fp.trim(), "alice"),
    ] {
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
        &[("VOX_TEST_FOLD_HOLD_FILE", bob_fold_path)],
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
    wait_room_status(
        &bob,
        "bob",
        &room,
        true,
        "Bob never reported the consent-last room while its package was held",
        |_| true,
    );
    assert_eq!(
        trust_detail(&bob, "bob", &room, "alice"),
        "you trust it, but it has not trusted you: it cannot read you",
        "APPARATUS: consent was not held before the key-before-consent ordering"
    );
    wait_for_held_rows(&bob, &room, &hashes, "author-governance");
    // Take Bob's count after the paged observation, so its read record is also inside the causal
    // boundary Alice must accept before her fold is released.
    let bob_log = room_status(&bob, "bob", &room).log_entries;
    wait_room_status(
        &alice,
        "alice",
        &room,
        false,
        "Alice never retained Bob's causal join/read boundary",
        |status| status.log_entries >= bob_log,
    );

    std::fs::write(&bob_fold, b"")
        .unwrap_or_else(|error| panic!("APPARATUS: could not engage Bob's fold: {error}"));
    std::fs::remove_file(&alice_fold)
        .unwrap_or_else(|error| panic!("APPARATUS: could not release Alice's fold: {error}"));
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

    // Both source and reader stop while the exact rows, key and as-yet-unfolded consent are
    // retained. Only Bob returns; successful reprojection therefore cannot be a refetch.
    alice_daemon.stop();
    bob_daemon.stop();
    std::fs::remove_file(&bob_fold)
        .unwrap_or_else(|error| panic!("APPARATUS: could not release Bob's fold: {error}"));
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
        "VOX_TEST_HOLD_PACKAGES_FILE",
        "VOX_TEST_HOLD_RENDER_FILE",
        vox_core::node::channel::TEST_EXPIRING_ADMIN_ENV,
        "VOX_TEST_HOLD_GOVERNANCE_SWEEP_AFTER_FILE",
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
        (&alice, &fps[1], "bob"),
        (&alice, &fps[2], "carol"),
        (&bob, &fps[0], "alice"),
        (&bob, &fps[2], "carol"),
        (&carol, &fps[0], "alice"),
        (&carol, &fps[1], "bob"),
    ] {
        let (ok, _, err) = vox(dir, &["trust", "add", fp, "--name", name], None);
        assert!(ok, "PRODUCT: `vox trust add` of {name} failed: {err}");
    }
    let fold_hold = root.join("fx22-fold-hold");
    let carol_fold_hold = root.join("fx22-carol-fold-hold");
    let package_hold = root.join("fx22-package-hold");
    let render_hold = root.join("fx22-render-hold");
    let render_hold_ready = root.join("fx22-render-hold.ready");
    let render_hold_engaged = root.join("fx22-render-hold.engaged");
    let render_hold_replacement = root.join("fx22-render-hold-replacement");
    let sweep_hold = root.join("fx22-sweep-hold");
    let sweep_engaged = root.join("fx22-sweep-hold.engaged");
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
    let sweep_hold_path = sweep_hold
        .to_str()
        .expect("APPARATUS: a UTF-8 governance-sweep hold path")
        .to_owned();
    let fold_knob = [
        ("VOX_TEST_FOLD_HOLD_FILE", fold_hold_path.as_str()),
        (vox_core::node::channel::TEST_EXPIRING_ADMIN_ENV, "1"),
        (
            "VOX_TEST_HOLD_GOVERNANCE_SWEEP_AFTER_FILE",
            sweep_hold_path.as_str(),
        ),
    ];
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

    // Alice may accept Bob's admission but cannot fold it, so she cannot consent or release her
    // key. Bob nevertheless accepts Alice's existing LogDb prefix. The product itself says that
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
        let held_trust = trust_detail(&bob, "bob", room, "alice");
        assert_eq!(
            held_trust, "you trust it, but it has not trusted you: it cannot read you",
            "APPARATUS: Alice's governance fold was not visibly held after Bob accepted her \
             existing LogDb prefix in room {room}"
        );
        wait_for_held_rows(&bob, room, &late_hashes[i], "governance-fold");
        assert_eq!(
            trust_detail(&bob, "bob", room, "carol"),
            "you trust it, but it has not trusted you: it cannot read you",
            "APPARATUS: Carol's governance fold was not visibly held in room {room}"
        );
        wait_for_held_rows(&bob, room, &competing_hashes[i], "Carol-governance-fold");
        // Alice has durably accepted Bob's join-side rows before he goes offline; only her held
        // governance fold keeps the release from being issued. Take Bob's count after the paged
        // observation above, so any read record it made is before this causal sync boundary too.
        let bob_log = room_status(&bob, "bob", room).log_entries;
        wait_room_status(
            &alice,
            "alice",
            room,
            false,
            "Alice never retained Bob's causal join/read boundary",
            |status| status.log_entries >= bob_log,
        );
    }

    // The exact held rows and missing product facts above are the staging evidence. CPU and
    // elapsed time are not verdicts for this claim: the causal consent/key events below must
    // either make those same hashes readable or leave structural render work unfinished.
    bob_before_key.stop();

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

    // With Bob offline, release the two authors separately. The exact ordered interval around
    // Alice's release identifies grant1 itself: after subtracting the one causal same-name rename,
    // exactly one newly appended authenticated object remains. Releasing Carol afterwards keeps
    // her consent from being misidentified as Alice's grant.
    let grant1_baselines: Vec<Vec<String>> = rooms
        .iter()
        .map(|room| room_hashes(&alice, "alice", room))
        .collect();
    std::fs::remove_file(&fold_hold)
        .unwrap_or_else(|error| panic!("APPARATUS: could not release the fold hold: {error}"));
    // Marker removal is apparatus, not a product wake. A second authenticated same-name action is
    // the causal event that resumes Alice's released fold.
    let mut alice_causal_renames = Vec::with_capacity(rooms.len());
    for room in &rooms {
        let causal = rename_hash(&alice, "alice", room, room);
        assert!(
            room_hashes(&alice, "alice", room).contains(&causal),
            "PRODUCT: Alice's causal same-name rename named {causal}, but the exact \
             authenticated row was absent after the fold hold was released in room {room}"
        );
        alice_causal_renames.push(causal);
    }
    for room in &rooms {
        wait_trust_detail(&alice, "alice", room, "bob", "you trust each other");
    }
    let mut grant1_hashes = Vec::with_capacity(rooms.len());
    for (index, room) in rooms.iter().enumerate() {
        let after = room_hashes(&alice, "alice", room);
        let appended: Vec<_> = after
            .iter()
            .filter(|hash| {
                !grant1_baselines[index].contains(hash) && **hash != alice_causal_renames[index]
            })
            .cloned()
            .collect();
        assert_eq!(
            appended.len(),
            1,
            "PRODUCT: Alice's released fold did not append exactly one identifiable consent grant1 in room {room}; before {:?}; causal rename {}; after {after:?}; candidates {appended:?}",
            grant1_baselines[index],
            alice_causal_renames[index]
        );
        grant1_hashes.push(appended[0].clone());
    }

    std::fs::remove_file(&carol_fold_hold)
        .unwrap_or_else(|error| panic!("APPARATUS: could not release Carol's fold hold: {error}"));
    // Carol's authenticated same-name action is the independent causal wake for her released
    // fold; it cannot add another Alice-authored candidate to the grant1 boundary above.
    for room in &rooms {
        let causal = rename_hash(&carol, "carol", room, room);
        assert!(
            room_hashes(&carol, "carol", room).contains(&causal),
            "PRODUCT: Carol's causal same-name rename named {causal}, but the exact authenticated row was absent after her fold hold was released in room {room}"
        );
        wait_trust_detail(&carol, "carol", room, "bob", "you trust each other");
    }

    // Bob now receives Alice's consent and the sealed package row, but the package marker keeps
    // the shipped daemon from opening it. Doctor says consent is mutual while status still says
    // zero received generations: the second hold is visibly engaged.
    let mut bob_daemon = daemon_env(&bob, "bob", &package_knob);
    attached(&bob, "bob");
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
    let fairness_wake = rename_hash(&bob, "bob", &rooms[0], "fx22-fair-turn");
    assert!(
        room_hashes(&bob, "bob", &rooms[0]).contains(&fairness_wake),
        "PRODUCT: Bob's exact fairness wake {fairness_wake} was absent from room {}",
        rooms[0]
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
        competing[0]["text"].as_str(),
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
                    && row["text"].as_str().is_some()
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
    let continuation_wake = rename_hash(&bob, "bob", &rooms[0], "fx22-fair-turn-resume");
    assert!(
        room_hashes(&bob, "bob", &rooms[0]).contains(&continuation_wake),
        "PRODUCT: Bob's exact continuation wake {continuation_wake} was absent from room {}",
        rooms[0]
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

    // Isolate the repeated-grant claim to Alice and Bob before taking any semantic or room-order
    // baseline. A Presence rotation retries consent for every identity Alice still trusts. If
    // offline Carol remained in that set, her equal regrant could own the next semantic revision
    // or share Bob's row interval, so `reset + 1` and the final row would not identify Bob's
    // grant. Removing Carol is a shipped user action; wait for its real rotation/regrant fold and
    // prove the node-wide trust decision before the quiet two-member sequence begins.
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
        "Carol's removal did not publish its reset and the one Bob-only regrant",
        |status| status.governance_revision >= isolation_revision,
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

    // The original Alice→Bob grant is already user-visible and its sender key is held. Take Bob
    // offline, then drive one source-owned sender-generation bound through the shipped post
    // command. The rotation appends an authenticated Presence reset between the original grant
    // and Alice's automatic, equal grant to every still-trusted reader. Bob's sparse catch-up
    // admits the newest control fact before filling the older reset, which is the reachable
    // grant₁ → reset → identical grant₂ → late-reset order: sequence, not arrival, must win.
    assert_eq!(
        trust_detail(&bob, "bob", &rooms[0], "alice"),
        "you trust each other",
        "APPARATUS: the first Alice→Bob grant was not visibly effective before staging the \
         repeated-grant sequence"
    );
    let rotation_order_before = room_hashes(&alice, "alice", &rooms[0]);
    let grant1_hash = &grant1_hashes[0];
    assert!(
        rotation_order_before.contains(grant1_hash),
        "PRODUCT: Alice's exact consent grant1 {grant1_hash} disappeared before sender rotation: {rotation_order_before:?}"
    );
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
    let after_presence = room_hashes(&alice, "alice", &rooms[0]);
    let reset_candidates: Vec<_> = after_presence
        .iter()
        .filter(|hash| {
            !rotation_order_before.contains(hash) && !rotation_post_hashes.contains(hash)
        })
        .cloned()
        .collect();
    assert_eq!(
        reset_candidates.len(),
        1,
        "PRODUCT: the source-owned sender rotation did not append exactly one identifiable authenticated Presence reset; before {rotation_order_before:?}; posts {rotation_post_hashes:?}; after {after_presence:?}; candidates {reset_candidates:?}"
    );
    let reset_hash = reset_candidates[0].clone();
    let grant1_at = after_presence
        .iter()
        .position(|hash| hash == grant1_hash)
        .expect("PRODUCT: exact grant1 missing after Presence rotation");
    let reset_at = after_presence
        .iter()
        .position(|hash| hash == &reset_hash)
        .expect("PRODUCT: exact Presence reset missing from Alice's order");
    assert!(
        grant1_at < reset_at,
        "PRODUCT: Alice's shipped room order did not place grant1 {grant1_hash} before Presence reset {reset_hash}: {after_presence:?}"
    );
    // Wait until the real Presence rotation has reached the semantic projection, then take the
    // revision baseline. The next equality can therefore measure only the identical grant2.
    wait_governance_current(
        &alice,
        "alice",
        &rooms[0],
        "the source-owned Presence reset never completed its bounded governance fold",
    );
    let semantic_after_reset = room_status(&alice, "alice", &rooms[0]);
    // `trust add` is idempotent as a human decision. With Bob offline its retained release is
    // deliberately asynchronous: the fallback may append its key package before the consent.
    // Therefore command success is not the durability boundary and an immediate row-count delta
    // cannot identify grant₂. The next semantic projection revision is the causal product
    // observation: after the already-folded reset, only the new grant changes canonical meaning.
    let (ok, out, err) = vox(&alice, &["trust", "add", &fps[1], "--name", "bob"], None);
    assert!(
        ok,
        "PRODUCT: Alice's idempotent shipped trust decision did not finish the rotated \
         generation's retained grant while Bob was offline: {out}{err}"
    );
    let grant2_revision = semantic_after_reset
        .governance_revision
        .checked_add(1)
        .expect("PRODUCT: Alice's governance revision overflowed before the repeated grant");
    let (after_grant2, semantic_after_grant2) = loop {
        let status = room_status(&alice, "alice", &rooms[0]);
        assert!(
            status.governance_revision <= grant2_revision,
            "PRODUCT: Alice published more than the one reset→grant semantic transition while \
             Bob was offline in quiet room {}: reset {semantic_after_reset:?}, now {status:?}",
            rooms[0]
        );
        if status.governance_revision == grant2_revision {
            wait_governance_current(
                &alice,
                "alice",
                &rooms[0],
                "the exact reset→grant2 semantic transition never completed its bounded fold",
            );
            let settled = room_status(&alice, "alice", &rooms[0]);
            assert_eq!(
                settled.governance_revision, grant2_revision,
                "PRODUCT: Alice published an extra semantic revision while settling the one \
                 repeated grant in quiet room {}: reset {semantic_after_reset:?}, settled \
                 {settled:?}",
                rooms[0]
            );
            break (room_hashes(&alice, "alice", &rooms[0]), settled);
        }
        std::thread::yield_now();
    };
    let grant2_candidates: Vec<_> = after_grant2
        .iter()
        .filter(|hash| !after_presence.contains(hash))
        .cloned()
        .collect();
    assert!(
        matches!(grant2_candidates.len(), 1 | 2),
        "PRODUCT: at the exact reset→grant2 semantic revision, Alice's offline fallback did not \
         expose its authenticated consent alone or after its one key package; before \
         {after_presence:?}; after {after_grant2:?}; candidates {grant2_candidates:?}"
    );
    // The fallback awaits the optional key-package append before it records consent. Room order
    // is causal, so the final candidate at the exact one-revision boundary uniquely names grant₂
    // whether the already-held package made the delta one row or the fallback made it two.
    let grant2_hash = grant2_candidates
        .last()
        .expect("PRODUCT: reset→grant2 revision advanced without an authenticated room row")
        .clone();
    let ordered_positions: Vec<_> = [grant1_hash, &reset_hash, &grant2_hash]
        .iter()
        .map(|hash| {
            after_grant2
                .iter()
                .position(|entry| entry == *hash)
                .unwrap_or_else(|| panic!("PRODUCT: exact sequence row {hash} missing"))
        })
        .collect();
    assert!(
        ordered_positions[0] < ordered_positions[1]
            && ordered_positions[1] < ordered_positions[2],
        "PRODUCT: Alice's shipped room order did not prove grant1 {grant1_hash} → reset {reset_hash} → identical grant2 {grant2_hash}: positions {ordered_positions:?}; order {after_grant2:?}"
    );
    assert_eq!(
        semantic_after_grant2.governance_revision, grant2_revision,
        "PRODUCT: Alice's newer post-reset grant did not make exactly one required semantic \
         transition, or invented an extra displayed revision: reset {semantic_after_reset:?}, \
         grant2 {semantic_after_grant2:?}"
    );

    bob_daemon = daemon_env(&bob, "bob-repeated-grant", &package_knob);
    attached(&bob, "bob-repeated-grant");
    // Sparse catch-up must first expose the newest grant2 while the older Presence reset is still
    // absent. This is the apparatus boundary that makes the later reset genuinely late rather than
    // merely asserting an eventual set. If reset arrives first, this run did not stage the claim.
    loop {
        let held = room_hashes(&bob, "bob", &rooms[0]);
        if held.contains(&grant2_hash) && !held.contains(&reset_hash) {
            break;
        }
        assert!(
            !held.contains(&reset_hash),
            "APPARATUS: Bob received Presence reset {reset_hash} before the newer grant2 {grant2_hash}, so late-reset arrival was not staged; held order {held:?}"
        );
        std::thread::yield_now();
    }
    loop {
        let held = room_hashes(&bob, "bob", &rooms[0]);
        if [grant1_hash, &reset_hash, &grant2_hash]
            .iter()
            .all(|hash| held.contains(hash))
        {
            let positions: Vec<_> = [grant1_hash, &reset_hash, &grant2_hash]
                .iter()
                .map(|hash| held.iter().position(|entry| entry == *hash).unwrap())
                .collect();
            assert!(
                positions[0] < positions[1] && positions[1] < positions[2],
                "PRODUCT: Bob's shipped order changed the authenticated grant1/reset/grant2 sequence: positions {positions:?}; held {held:?}"
            );
            break;
        }
        std::thread::yield_now();
    }
    wait_governance_current(
        &bob,
        "bob",
        &rooms[0],
        "the equal repeated grant and late reset never completed their bounded governance fold",
    );
    assert_eq!(
        trust_detail(&bob, "bob", &rooms[0], "alice"),
        "you trust each other",
        "PRODUCT: after the equal repeated grant and late reset completed, Bob no longer saw \
         Alice's newer grant as effective"
    );
    assert_exact_read_rows(
        &bob,
        "bob",
        &rooms[0],
        std::slice::from_ref(&last_rotated_hash),
        std::slice::from_ref(&last_rotated_text),
        "the newer equal grant and late older reset reached Bob",
    );

    // Restart with Alice unavailable. The same exact retained object still reading proves the
    // durable Consent locator advanced to grant₂; the pre-restart observation above proves the
    // live RAM sequence also rejected the late, older reset.
    alice_restarted.stop();
    bob_daemon.stop();
    bob_daemon = daemon_env(&bob, "bob-repeated-grant-restarted", &package_knob);
    attached(&bob, "bob-repeated-grant-restarted");
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
    // Keep both shipped daemons alive for the remaining user journey.
    let _running_after_repeated_grant = (&alice_restarted, &bob_daemon);

    // The test-only certificate lifetime is owned by the product source; the proof does not
    // invent a delay or use unrelated traffic as the trigger. The shipped admin page first
    // proves Bob's certificate has effective semantic meaning. In the otherwise quiet room, its
    // exact deadline must then wake the fold, remove Bob, and publish exactly one new semantic
    // revision without a command or network event to prod it.
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
    let positioning_before = room_status(&alice, "alice", &rooms[0]);
    std::fs::write(&sweep_hold, room_id(&alice, "alice", &rooms[0])).unwrap_or_else(|error| {
        panic!(
            "APPARATUS: could not arm the governance sweep after room {}: {error}",
            rooms[0]
        )
    });
    // A changed name is a causal semantic boundary. The hold is checked before this room can
    // fold it: if the published revision advances while the marker remains unrenamed, the
    // apparatus did not park the intended room and can say so without an elapsed deadline.
    let positioning = rename_hash(&alice, "alice", &rooms[0], "fx22-expiry-boundary");
    assert!(
        room_hashes(&alice, "alice", &rooms[0]).contains(&positioning),
        "PRODUCT: the exact authenticated positioning rename {positioning} was absent from room \
         {}",
        rooms[0]
    );
    while !sweep_engaged.exists() {
        let observed = room_status(&alice, "alice", &rooms[0]);
        assert_eq!(
            observed.governance_revision, positioning_before.governance_revision,
            "APPARATUS: the exact positioning rename {positioning} reached a published semantic \
             revision before the governance-sweep marker engaged for room {}; the requested \
             expiry-behind-cursor staging was not achieved: before {positioning_before:?}, \
             observed {observed:?}",
            rooms[0]
        );
        std::thread::yield_now();
    }
    let (ok, active, err) = vox(&alice, &["room", "admin", "list", &rooms[0]], None);
    assert!(
        ok && active
            .lines()
            .any(|line| line.split_whitespace().next() == Some(fps[1].as_str())),
        "APPARATUS: the source-owned administrator certificate expired before the bounded \
         governance cursor was parked after room {}; expiry-behind-cursor staging was not \
         achieved: {active}{err}",
        rooms[0]
    );
    wait_admin_membership(&alice, "alice", &rooms[0], &fps[1], false);
    let authority_expired = wait_room_status(
        &alice,
        "alice",
        &rooms[0],
        false,
        "the quiet room's exact authority-expiry deadline did not publish its semantic revision",
        |status| status.governance_revision > authority_active.governance_revision,
    );
    assert_eq!(
        authority_expired.governance_revision,
        authority_active.governance_revision + 1,
        "PRODUCT: expiry of one effective administrator certificate did not publish exactly one \
         semantic governance revision in quiet room {}: active {authority_active:?}, expired \
         {authority_expired:?}",
        rooms[0]
    );

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
