//! V210-71 (#262), finding 5 — **a long room is read in time proportional to its length**, through
//! the shipped binary. **Opt-in** (`--features optional-proofs`): its staging posts [`POSTS`] messages
//! of [`TEXT_LEN`] bytes, minutes of work, so it is not part of every CI run or release gate.
//!
//! **The defect.** A node publishes its state as one view, and every IPC `Read` page took a clone
//! of that view: every open room's whole timeline, every message's text copied. `vox room read`
//! fetches a room page by page (a page is bounded by bytes: `ipc::rows_budget`, 128 KiB), so
//! reading a room of `n` rows cost about `n / rows-per-page` clones of every row on the node:
//! quadratic in the room's length, and paid again by every read, tail and board. The actor paid
//! it too: each publish rebuilt every room's timeline. Now a room's timeline is shared
//! (`api::Timeline`): a page takes a clone of the view that copies nothing, and a publish
//! reuses a room's timeline that has not changed.
//!
//! **What a person does here.** One `vox daemon`; `vox room create`; [`POSTS`] posts of
//! [`TEXT_LEN`] bytes each, with `vox room post` (from [`WRITERS`] shells at once, to stage it
//! quickly); then `vox room read` of the whole room, timed. Messages of 16 KiB put about eight
//! rows on a page, so the read takes about [`POSTS`] / 8 pages: enough for the copy per page to
//! show at a room size a proof can stage in minutes.
//!
//! **Asserted.** `vox room read` returns every one of the [`POSTS`] messages exactly once, in
//! order, and takes less than [`READ_BOUND`]. "In order" is what the staging fixes: the shells post
//! at once, so the room interleaves them, but each shell posts its own messages one after another,
//! so each shell's messages must read in the order it posted them. `APPARATUS` (staging not achieved) if fewer than [`POSTS`] posts could be staged.
//!
//! **Measured, to set the bound** (release, a shared 18-core machine under other agents' load):
//! 12,000 rows, about 188 MiB and 1,715 pages. The candidate read it in 0.69 s, and the mutant
//! below in 13.55 s. At 4,000 rows the two were 0.36 s and 1.56 s, too close for a bound that
//! holds under load. The copy per page grows with the square of the room, so the room is sized
//! for a clear gap. [`READ_BOUND`] of 5 s leaves the candidate about 7x headroom and the
//! mutant about 2.7x past it. Staging takes about 4-5 minutes, a run about 5.
//!
//! **And a message added to the long room is readable at once (V210-120).** Each new message used
//! to rebuild the room's whole published timeline, so what a node did per message grew with the
//! room's history. After the read, [`APPENDS`] messages are posted to the long room one after
//! another, each timed from `vox room post` until `vox room read --since` shows it; then the same
//! in a fresh room on the same daemon, as the control. The long room's p95 must be under
//! [`APPEND_P95`] and its maximum under [`APPEND_MAX`]. Then [`BURST`] messages are posted to each
//! room at once, as several agents posting together, until every one is readable. The long room
//! may take at most one and a half times the fresh room's time plus a quarter second: a message's
//! cost must not depend on the room's history. A fresh room slower than [`BURST_APPARATUS`] is `APPARATUS`. Mutation: rebuild the whole timeline when a
//! room's timeline has grown (`detail_of`), as before V210-120: red on the burst assertion.
//!
//! **Mutation that must turn it red.** Copy every room's timeline again on each clone of the view
//! (and rebuild every room's timeline on each publish), as before V210-71: the read takes many
//! times longer, past the bound.

// Optional (decider, 2026-10-01): it blocks nothing and CI only compiles it. Without
// `--features optional-proofs` a stand-in takes its place and says it was not run
// (`support/optional_proof.rs`). How to run it: docs/release/optional-proofs.md.
#![cfg_attr(not(feature = "optional-proofs"), allow(dead_code, unused_imports))]
#![cfg(unix)]

#[path = "support/optional_proof.rs"]
mod optional_proof;
optional_proof::not_run!(a_long_room_is_read_in_time_proportional_to_its_length);

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/world.rs"]
mod world;

use std::io::Write as _;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use world::{args, VoxProc, IDENTITY, VOX};

/// How many messages the room holds.
const POSTS: usize = 12_000;
/// Each message's length in bytes: about eight rows to a 128 KiB page.
const TEXT_LEN: usize = 16 * 1024;
/// How many shells post at once while staging.
const WRITERS: usize = 4;
/// The whole room must be read within this.
const READ_BOUND: Duration = Duration::from_secs(5);
/// How many messages are added to the long room, and to a fresh one, timing each (V210-120).
const APPENDS: usize = 30;
/// A message added to the long room must be visible within this, at the 95th percentile ...
const APPEND_P95: Duration = Duration::from_millis(250);
/// ... and every one of them within this.
const APPEND_MAX: Duration = Duration::from_millis(1_000);
/// How many messages are posted to each room at once, as several agents posting together (V210-120).
const BURST: usize = 100;
/// A fresh room slower than this to show a burst is a machine that cannot measure this.
const BURST_APPARATUS: Duration = Duration::from_secs(20);
/// The cap on any one verb, so a stopped node is reported rather than waited on.
const VERB_CAP: Duration = Duration::from_secs(600);
const SETUP: Duration = Duration::from_secs(120);
const ROOM_PASS: &str = "room passphrase";

/// A `vox` verb as this profile, with `stdin`, waited on up to [`VERB_CAP`]. Returns whether it
/// succeeded, how long it ran, its stdout and its stderr.
fn vox(data: &Path, argv: &[&str], stdin: &str) -> (bool, Duration, String, String) {
    let t0 = Instant::now();
    let mut child = Command::new(VOX)
        .args(argv)
        .env("VOX_DATA_DIR", data)
        .env("VOX_CONFIG_DIR", data.join("cfg"))
        .env("VOX_IDENTITY_PASSPHRASE", IDENTITY)
        .env_remove("VOX_ROOM_PASSPHRASE")
        .env_remove("VOX_ROOM")
        .env_remove("VOX_SESSION")
        .env_remove("CLAUDE_CODE_SESSION_ID")
        .env_remove("CODEX_THREAD_ID")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("APPARATUS (harness): run vox");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin.as_bytes())
        .unwrap();
    // Read the pipes on their own threads: a full pipe would block the child.
    let mut out_pipe = child.stdout.take().unwrap();
    let mut err_pipe = child.stderr.take().unwrap();
    let out_t = std::thread::spawn(move || {
        let mut s = Vec::new();
        let _ = std::io::Read::read_to_end(&mut out_pipe, &mut s);
        s
    });
    let err_t = std::thread::spawn(move || {
        let mut s = Vec::new();
        let _ = std::io::Read::read_to_end(&mut err_pipe, &mut s);
        s
    });
    let ok = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status.success();
        }
        if t0.elapsed() >= VERB_CAP {
            let _ = child.kill();
            let _ = child.wait();
            break false;
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    let took = t0.elapsed();
    (
        ok,
        took,
        String::from_utf8_lossy(&out_t.join().unwrap()).into_owned(),
        String::from_utf8_lossy(&err_t.join().unwrap()).into_owned(),
    )
}

/// The text of message `i`: a findable head, then filler to [`TEXT_LEN`].
fn text(i: usize) -> String {
    let head = format!("m{i:06} ");
    let mut s = head.clone();
    s.extend(std::iter::repeat_n('x', TEXT_LEN - head.len()));
    s
}

/// Add [`APPENDS`] messages to `room`, one after another, and time each from the moment `vox room
/// post` starts until `vox room read --since <the row before it>` shows it: what a person posting
/// waits for before what they wrote is there to read. `after` is the room's newest row's hash.
fn append_to_visible(
    data: &Path,
    room: &str,
    tag: &str,
    mut after: String,
) -> (Vec<Duration>, String) {
    let mut took = Vec::with_capacity(APPENDS);
    for k in 0..APPENDS {
        let text = format!("append-{tag}-{k}");
        let t0 = Instant::now();
        let (ok, _, _, err) = vox(data, &["room", "post", room, &text], "");
        assert!(
            ok,
            "PRODUCT: `vox room post` of {text} in the {tag} room was refused: {err}"
        );
        loop {
            // The plain read: it fetches only what follows the cursor. (`--json` reads the whole
            // room for its operation index, by design, so it would time the room, not the post.)
            let (ok, _, out, err) = vox(data, &["room", "read", room, "--since", &after], "");
            assert!(
                ok,
                "PRODUCT: `vox room read --since` in the {tag} room failed: {err}"
            );
            let suffix = format!(" {text}");
            if let Some(row) = out.lines().find(|l| l.ends_with(&suffix)) {
                took.push(t0.elapsed());
                after = row
                    .split_whitespace()
                    .next()
                    .expect("a row starts with its entry hash")
                    .to_owned();
                break;
            }
            assert!(
                t0.elapsed() < Duration::from_secs(30),
                "PRODUCT: {text}, posted to the {tag} room, was not readable 30 s later"
            );
        }
    }
    (took, after)
}

/// Post [`BURST`] messages to `room` at once, one shell each, as several agents posting together
/// do, and return how long until `vox room read --since <after>` shows every one of them.
fn burst_to_visible(data: &Path, room: &str, tag: &str, after: &str) -> Duration {
    let texts: Vec<String> = (0..BURST).map(|k| format!("burst-{tag}-{k}")).collect();
    let t0 = Instant::now();
    std::thread::scope(|s| {
        for text in &texts {
            s.spawn(move || {
                let (ok, _, _, err) = vox(data, &["room", "post", room, text], "");
                assert!(
                    ok,
                    "PRODUCT: `vox room post` of {text} in the {tag} room was refused: {err}"
                );
            });
        }
    });
    loop {
        let (ok, _, out, err) = vox(data, &["room", "read", room, "--since", after], "");
        assert!(
            ok,
            "PRODUCT: `vox room read --since` in the {tag} room failed: {err}"
        );
        let shown = texts
            .iter()
            .filter(|t| out.lines().any(|l| l.ends_with(&format!(" {t}"))))
            .count();
        if shown == BURST {
            return t0.elapsed();
        }
        assert!(
            t0.elapsed() < Duration::from_secs(120),
            "PRODUCT: {shown} of {BURST} messages posted together to the {tag} room were readable \
             120 s later"
        );
    }
}

/// The 50th and 95th percentiles and the maximum of `took`.
fn spread(took: &[Duration]) -> (Duration, Duration, Duration) {
    let mut t = took.to_vec();
    t.sort_unstable();
    let at = |q: f64| t[((t.len() - 1) as f64 * q).round() as usize];
    (at(0.5), at(0.95), t[t.len() - 1])
}

#[cfg(feature = "optional-proofs")]
#[test]
#[ignore = "optional: a real daemon and thousands of 16 KiB posts; run in release"]
fn a_long_room_is_read_in_time_proportional_to_its_length() {
    // Staging thousands of posts takes minutes, past the default budget: a longer one, unless the
    // runner set its own.
    if std::env::var_os("VOX_TEST_WATCHDOG_SECS").is_none() {
        std::env::set_var("VOX_TEST_WATCHDOG_SECS", "3000");
    }
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();
    let data = tmp.path().join("alice");
    std::fs::create_dir_all(data.join("cfg")).unwrap();
    let (ok, _, _, err) = vox(&data, &["id"], "");
    assert!(ok, "APPARATUS (precondition not met): vox id: {err}");
    let pass_file = tmp.path().join("identity.pass");
    std::fs::write(&pass_file, format!("{IDENTITY}\n")).unwrap();
    let _daemon = VoxProc::spawn(
        "alice",
        &data,
        &args(&[
            "daemon",
            "--listen",
            "127.0.0.1:0",
            "--passphrase-file",
            pass_file.to_str().unwrap(),
        ]),
    );
    let deadline = Instant::now() + SETUP;
    while !vox(&data, &["room", "list"], "").0 {
        assert!(
            Instant::now() < deadline,
            "APPARATUS (precondition not met): the daemon never answered `vox room list`"
        );
        std::thread::sleep(Duration::from_millis(250));
    }
    let (ok, _, out, err) = vox(&data, &["room", "create", "--name", "long"], ROOM_PASS);
    assert!(
        ok,
        "APPARATUS (precondition not met): room create: {out}\n{err}"
    );
    let (_, _, list, _) = vox(&data, &["room", "list"], "");
    let room = list
        .split_whitespace()
        .next()
        .expect("APPARATUS (precondition not met): the room in `vox room list`")
        .to_owned();

    // ---- staging: POSTS messages, from WRITERS shells at once ---------------------------
    let t_stage = Instant::now();
    let posted: usize = std::thread::scope(|s| {
        let handles: Vec<_> = (0..WRITERS)
            .map(|w| {
                let (data, room) = (&data, &room);
                s.spawn(move || {
                    (w..POSTS)
                        .step_by(WRITERS)
                        .filter(|i| vox(data, &["room", "post", room, "-"], &text(*i)).0)
                        .count()
                })
            })
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).sum()
    });
    println!(
        "[proof] staged {posted} of {POSTS} posts of {TEXT_LEN} bytes in {:?}",
        t_stage.elapsed()
    );
    assert!(
        posted == POSTS,
        "APPARATUS (precondition not met): only {posted} of {POSTS} posts were taken"
    );

    // ---- the read -----------------------------------------------------------------------
    let (ok, took, out, err) = vox(&data, &["room", "read", &room], "");
    assert!(ok, "PRODUCT: vox room read failed after {took:?}: {err}");
    let seen: Vec<usize> = out
        .lines()
        .filter_map(|l| {
            let at = l.find(" m")? + 2;
            l.get(at..at + 6)?.parse().ok()
        })
        .collect();
    let mut sorted = seen.clone();
    sorted.sort_unstable();
    sorted.dedup();
    let pages = POSTS.div_ceil(128 * 1024 / (TEXT_LEN + 128));
    println!(
        "[proof] `vox room read` of {} rows (~{} MiB, ~{pages} pages) took {took:?} (bound \
         {READ_BOUND:?})",
        seen.len(),
        out.len() / (1024 * 1024)
    );
    assert_eq!(
        sorted.len(),
        POSTS,
        "PRODUCT: `vox room read` returned {} distinct of the {POSTS} messages",
        sorted.len()
    );
    assert_eq!(
        seen.len(),
        POSTS,
        "PRODUCT: `vox room read` returned {} rows for {POSTS} messages: some more than once",
        seen.len()
    );
    // Each shell posted messages `w, w + WRITERS, w + 2·WRITERS, …` one after another, so they
    // must read in that order however the shells interleaved.
    for w in 0..WRITERS {
        let mine: Vec<usize> = seen.iter().copied().filter(|i| i % WRITERS == w).collect();
        let out_of_order = mine.windows(2).find(|p| p[0] >= p[1]);
        assert!(
            out_of_order.is_none(),
            "PRODUCT: `vox room read` returned shell {w}'s messages out of the order it posted them: \
             {out_of_order:?}"
        );
    }
    assert!(
        took < READ_BOUND,
        "PRODUCT: `vox room read` of a room of {POSTS} messages of {TEXT_LEN} bytes took {took:?} (bound \
         {READ_BOUND:?}): each page copies every room's whole history"
    );

    // ---- V210-120: a message added to the long room is seen at once ---------------------
    // The control is a fresh room on the same daemon, measured the same way right after, so a
    // slow machine shows in both and the history in only one.
    let newest = out
        .lines()
        .last()
        .and_then(|l| l.split_whitespace().next())
        .expect("APPARATUS (precondition not met): the long room's newest row")
        .to_owned();
    let (long, long_last) = append_to_visible(&data, &room, "long", newest);
    let long_burst = burst_to_visible(&data, &room, "long", &long_last);
    let (ok, _, out, err) = vox(&data, &["room", "create", "--name", "short"], ROOM_PASS);
    assert!(
        ok,
        "APPARATUS (precondition not met): room create: {out}\n{err}"
    );
    let (_, _, list, _) = vox(&data, &["room", "list"], "");
    let short_room = list
        .lines()
        .find(|l| l.split_whitespace().nth(1) == Some("short"))
        .and_then(|l| l.split_whitespace().next())
        .expect("APPARATUS (precondition not met): the short room in `vox room list`")
        .to_owned();
    let (ok, _, _, err) = vox(&data, &["room", "post", &short_room, "first"], "");
    assert!(
        ok,
        "APPARATUS (precondition not met): the short room's first post: {err}"
    );
    let (ok, _, first, err) = vox(&data, &["room", "read", &short_room], "");
    assert!(
        ok,
        "APPARATUS (precondition not met): reading the short room: {err}"
    );
    let first = first
        .lines()
        .last()
        .and_then(|l| l.split_whitespace().next())
        .expect("APPARATUS (precondition not met): the short room's first row")
        .to_owned();
    let (short, short_last) = append_to_visible(&data, &short_room, "short", first);
    let short_burst = burst_to_visible(&data, &short_room, "short", &short_last);
    let ((l50, l95, lmax), (s50, s95, smax)) = (spread(&long), spread(&short));
    println!(
        "[proof] post to visible, {APPENDS} each: the {POSTS}-message room p50 {l50:?} p95 {l95:?} \
         max {lmax:?}; a fresh room p50 {s50:?} p95 {s95:?} max {smax:?} (bound p95 \
         {APPEND_P95:?}, max {APPEND_MAX:?})"
    );
    println!(
        "[proof] {BURST} posted at once, until all are readable: the {POSTS}-message room \
         {long_burst:?}; a fresh room {short_burst:?}"
    );
    assert!(
        short_burst < BURST_APPARATUS,
        "APPARATUS (precondition not met): {BURST} messages posted at once to a fresh room took \
         {short_burst:?} to be readable, past {BURST_APPARATUS:?} with no history at all, so this \
         machine cannot measure what history costs"
    );
    // **What history adds, not what the machine does.** The fresh room is measured the same way on
    // the same node moments later: a message's cost must not depend on how long the room is, so
    // the long room may take at most half as long again as the fresh room, and a quarter second.
    // Measured (release, a shared machine under other agents' load): the long room 0.89 s and the
    // fresh 0.96 s; with the whole timeline rebuilt per message, 2.42 s and 0.65 s.
    let allowed = short_burst * 3 / 2 + Duration::from_millis(250);
    assert!(
        long_burst < allowed,
        "PRODUCT: {BURST} messages posted at once to a room of {POSTS} messages took \
         {long_burst:?} to be readable, and {short_burst:?} in a fresh room on the same node \
         (allowed {allowed:?}): each message costs the room's whole history"
    );
    assert!(
        l95 < APPEND_P95 && lmax < APPEND_MAX,
        "PRODUCT: a message added to a room of {POSTS} messages took p95 {l95:?}, max {lmax:?} to \
         become readable (bound p95 {APPEND_P95:?}, max {APPEND_MAX:?}); in a fresh room on the \
         same node, p95 {s95:?}, max {smax:?}: each message costs the room's whole history"
    );
}
