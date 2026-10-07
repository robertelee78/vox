//! **A room past one IPC frame of history reads whole** — `vox room read`, `tail` and
//! `board`, through the shipped binary, on the node the history reached by sync.
//!
//! A `Read` reply used to be every row after the cursor in one frame, and the client
//! refuses a frame over `MAX_FRAME` (256 KiB). So once a room's rows passed 256 KiB the
//! CLI could not read it at all: `vox room tail` exited with "declared size exceeds hard
//! limit: ipc frame length" (found 2026-09-25 when `adapter_stream_proof` was made to lag
//! by bytes). A reply is now bounded by `ROWS_BUDGET` and the client pages.
//!
//! What this drives: alice posts 160 rows of 32 KiB (5 MiB) and one row of the
//! largest text a post may carry (64 KiB); bob, which received them by sync, must then
//!
//! 1. `read --json` every one of them, in full;
//! 2. `tail --since <before the first> --json` every one of them;
//! 3. answer `board --json`, which folds the whole room.
//!
//! The maximum row is the bound a page relies on: a reply always carries at least
//! one row, so the largest row must fit a frame by itself.
//!
//! **Every red names its side** (V210-106). `PRODUCT:` quotes what a `vox` command did: a row
//! missing, shown twice, out of order or cut short is the product's. `APPARATUS:` is this harness
//! failing to run a process or a runtime.

#![cfg(unix)]

#[path = "support/room.rs"]
mod support;
#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::io::{BufRead as _, BufReader};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use support::{until, Out, VOX};

/// Rows of this many bytes of body, and how many: 5 MiB, twenty frames' worth.
const ROW: usize = 32 * 1024;
const ROWS: usize = 160;

/// The largest text a post may carry (`vox_core::node::content::MAX_TEXT_LEN`). A plain
/// `vox room post` stores its body as the row's text, so this row is exactly that size.
const MAX_TEXT: usize = 64 * 1024;

fn body(i: usize, len: usize) -> String {
    let head = format!("LARGE-ROOM-{i:03} ");
    format!("{head}{}", "x".repeat(len - head.len()))
}

#[test]
#[ignore = "two networked nodes with production Argon2id and 5 MiB of history; CI runs it in release"]
fn a_room_past_one_frame_of_history_reads_whole() {
    watchdog::arm();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap_or_else(|e| panic!("APPARATUS: could not build a runtime: {e}"));
    let tmp = tempfile::tempdir()
        .unwrap_or_else(|e| panic!("APPARATUS: could not make a temporary directory: {e}"));
    let room = rt.block_on(support::room(tmp.path(), &["alice", "bob"]));
    let (alice, bob) = (&room.workers[0], &room.workers[1]);
    let r = room.id.as_str();

    // The cursor tail starts from: the last row before the large ones.
    let before = bob.vox(None, &["room", "read", r, "--json"]);
    assert!(
        before.ok,
        "PRODUCT (staging): bob's `vox room read --json` failed: {before:?}"
    );
    let start = before
        .ndjson()
        .last()
        .and_then(|x| x["entry_hash"].as_str().map(str::to_owned))
        .unwrap_or_else(|| {
            panic!("PRODUCT (staging): bob's room has no row with an entry_hash before the large ones: {before:?}")
        });

    let mut sent = Vec::new();
    for i in 0..ROWS {
        sent.push(body(i, ROW));
    }
    sent.push(body(ROWS, MAX_TEXT));
    for b in &sent {
        let o = alice.vox_in(Some("a1"), &["room", "post", r, "-"], Some(b));
        assert!(
            o.ok,
            "PRODUCT (staging): alice's `vox room post` of {} bytes was refused: {o:?}",
            b.len()
        );
    }
    let total: usize = sent.iter().map(String::len).sum();
    assert!(
        total >= 1024 * 1024,
        "APPARATUS: this proof stages at least 1 MiB of history, not {total}"
    );

    // 1. `read --json`, on the node the rows reached by sync.
    let read = until(
        bob,
        None,
        "every large row to reach bob and read back",
        &["room", "read", r, "--json"],
        |o: &Out| o.ok && o.stdout.contains(&format!("LARGE-ROOM-{ROWS:03} ")),
    );
    let got: Vec<String> = read
        .ndjson()
        .iter()
        .filter_map(|x| x["envelope"]["body"].as_str().map(str::to_owned))
        .filter(|b| b.starts_with("LARGE-ROOM-"))
        .collect();
    same_rows("read --json", &got, &sent);
    let max_row = read
        .ndjson()
        .iter()
        .find(|x| {
            x["envelope"]["body"]
                .as_str()
                .is_some_and(|b| b.starts_with(&format!("LARGE-ROOM-{ROWS:03} ")))
        })
        .and_then(|x| x["text"].as_str().map(str::len))
        .unwrap_or_else(|| {
            panic!("PRODUCT: bob's `read --json` shows no text for the largest row (LARGE-ROOM-{ROWS:03})")
        });
    eprintln!(
        "[proof] {} rows, {total} bytes of body; the largest row's text is {max_row} bytes",
        sent.len()
    );
    assert_eq!(
        max_row, MAX_TEXT,
        "PRODUCT: the largest row must carry exactly MAX_TEXT_LEN and read back whole"
    );

    // 2. `tail --since`, which pages the same history before it follows.
    let mut cmd = Command::new(VOX);
    cmd.args(["room", "tail", r, "--since", &start, "--json"])
        .env("VOX_DATA_DIR", &bob.data)
        .env("VOX_CONFIG_DIR", &bob.cfg)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    support::strip_harness_env(&mut cmd);
    let mut child = cmd
        .spawn()
        .unwrap_or_else(|e| panic!("APPARATUS: could not spawn {VOX} room tail: {e}"));
    let stdout = child
        .stdout
        .take()
        .expect("APPARATUS: tail's stdout was piped");
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            let Ok(line) = line else { return };
            if tx.send(line).is_err() {
                return;
            }
        }
    });
    let mut tailed = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(60);
    while tailed.len() < sent.len() && Instant::now() < deadline {
        let Ok(line) = rx.recv_timeout(Duration::from_secs(1)) else {
            if child.try_wait().ok().flatten().is_some() {
                break; // it exited: the frame-limit failure did exactly this
            }
            continue;
        };
        let row: serde_json::Value = serde_json::from_str(&line).unwrap_or_else(|e| {
            panic!("PRODUCT: `vox room tail --json` printed a bad NDJSON row ({e}): {line}")
        });
        if let Some(b) = row["envelope"]["body"].as_str() {
            if b.starts_with("LARGE-ROOM-") {
                tailed.push(b.to_owned());
            }
        }
    }
    let exited = child.try_wait().ok().flatten();
    let _ = child.kill();
    let out = child
        .wait_with_output()
        .unwrap_or_else(|e| panic!("APPARATUS: could not wait for tail: {e}"));
    assert!(
        exited.is_none(),
        "PRODUCT: `vox room tail` must still be running, not exit ({exited:?}): {}",
        String::from_utf8_lossy(&out.stderr)
    );
    same_rows("tail --since", &tailed, &sent);

    // 3. `board --json` folds the whole room.
    let board = bob.vox(None, &["room", "board", r, "--json"]);
    assert!(
        board.ok,
        "PRODUCT: `vox room board --json` over a large room failed: {board:?}"
    );
    assert_eq!(
        board.json()["schema"],
        "vox.room.board/1",
        "PRODUCT: `vox room board --json` over a large room answered another schema: {}",
        board.stdout
    );
}

/// Assert that `got`, the large rows `verb` showed bob, are `sent`: each once, whole and in the
/// order alice posted them. A red says which, and is the product's.
fn same_rows(verb: &str, got: &[String], sent: &[String]) {
    let name = |b: &str| b.split(' ').next().unwrap_or_default().to_owned();
    let names: Vec<String> = got.iter().map(|b| name(b)).collect();
    let mut distinct = names.clone();
    distinct.sort();
    distinct.dedup();
    assert!(
        distinct.len() == names.len(),
        "PRODUCT: `{verb}` shows {} large rows for {} distinct ones: a row shown more than once",
        names.len(),
        distinct.len()
    );
    let wanted: Vec<String> = sent.iter().map(|b| name(b)).collect();
    let missing: Vec<&String> = wanted.iter().filter(|n| !names.contains(n)).collect();
    assert!(
        missing.is_empty(),
        "PRODUCT: `{verb}` shows {} of the {} large rows; missing {missing:?}",
        names.len(),
        wanted.len()
    );
    assert!(
        names == wanted,
        "PRODUCT: `{verb}` shows every large row once, but not in the order posted: {names:?}"
    );
    for (g, s) in got.iter().zip(sent) {
        assert!(
            g == s,
            "PRODUCT: `{verb}` shows {} cut or changed: {} bytes, not the {} posted",
            name(s),
            g.len(),
            s.len()
        );
    }
}
