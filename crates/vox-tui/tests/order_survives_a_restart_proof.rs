//! ADR-021 **F19** — **a node's local order survives its restart**, through the shipped
//! `vox` binary.
//!
//! The adapter read cycle (ADR-021 §7) keeps a cursor, an entry hash, and resumes with
//! `tail --since <cursor>`: "everything after this row". That is only right if the rows
//! before the cursor are still the rows before it after the node restarts. The order is
//! local, not canonical — this node's own appends and rows that arrived by sync, in the
//! order this node took them — and the timeline is rebuilt from the sealed plaintext
//! cache when the room reopens. Nothing proved the rebuilt order is the order a reader
//! saw before.
//!
//! What this drives: alice and bob post alternately, so alice's log interleaves her own
//! appends with rows synced from bob. alice's daemon is then killed and started again, as
//! an operator restarting it would, and on alice's node
//!
//! 1. `vox room read --json` returns every row it held before, **in the same order**;
//! 2. `vox room board --json`'s `position` (entries, last) is unchanged;
//! 3. `vox room tail --since <a cursor from before the restart>` resumes with exactly the
//!    rows that followed that cursor before the restart.

#![cfg(unix)]

#[path = "support/room.rs"]
mod support;
#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::io::{BufRead as _, BufReader};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use support::{until, Out, Worker, HARNESS_SESSION_VARS, VOX};

/// Posts from each member, alternating.
const EACH: usize = 20;

fn order(w: &Worker, r: &str) -> Vec<String> {
    let o = w.vox(None, &["room", "read", r, "--json"]);
    assert!(o.ok, "{o:?}");
    o.ndjson()
        .iter()
        .map(|x| x["entry_hash"].as_str().unwrap().to_owned())
        .collect()
}

fn position(w: &Worker, r: &str) -> serde_json::Value {
    let b = w.vox(Some("reader"), &["room", "board", r, "--json"]);
    assert!(b.ok, "{b:?}");
    b.json()["position"].clone()
}

/// The entry hashes `tail --since <cursor> --json` emits, until it has `want` of them.
fn tail_since(w: &Worker, r: &str, cursor: &str, want: usize) -> Vec<String> {
    let mut cmd = Command::new(VOX);
    cmd.args(["room", "tail", r, "--since", cursor, "--json"])
        .env("VOX_DATA_DIR", &w.data)
        .env("VOX_CONFIG_DIR", &w.cfg)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    for v in HARNESS_SESSION_VARS {
        cmd.env_remove(v);
    }
    let mut child = cmd.spawn().expect("spawn tail");
    let stdout = child.stdout.take().unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            let Ok(line) = line else { return };
            if tx.send(line).is_err() {
                return;
            }
        }
    });
    let mut got = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(30);
    while got.len() < want && Instant::now() < deadline {
        if let Ok(line) = rx.recv_timeout(Duration::from_millis(500)) {
            let row: serde_json::Value = serde_json::from_str(&line).expect("NDJSON row");
            got.push(row["entry_hash"].as_str().unwrap().to_owned());
        }
    }
    let _ = child.kill();
    let _ = child.wait();
    got
}

#[test]
#[ignore = "two networked nodes with production Argon2id and a daemon restart; CI runs it in release"]
fn a_nodes_local_order_survives_its_restart() {
    watchdog::arm();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let mut room = rt.block_on(support::room(tmp.path(), &["alice", "bob"]));
    let r = room.id.clone();

    // Alternate, so alice's log interleaves her own appends with rows synced from bob.
    for i in 0..EACH {
        for (who, name) in [(0usize, "alice"), (1, "bob")] {
            let o = room.workers[who].vox_in(
                Some("s"),
                &["room", "post", &r, "-"],
                Some(&format!("F19 {name} {i:02}")),
            );
            assert!(o.ok, "{name} posts {i}: {o:?}");
        }
    }
    let last = format!("F19 bob {:02}", EACH - 1);
    until(
        &room.workers[0],
        None,
        "every post to reach alice",
        &["room", "read", &r],
        |o: &Out| o.ok && o.stdout.contains(&last),
    );

    let alice = &room.workers[0];
    let before = order(alice, &r);
    let before_position = position(alice, &r);
    // A cursor a third of the way in, and what followed it.
    let cut = before.len() / 3;
    let cursor = before[cut].clone();
    let followed: Vec<String> = before[cut + 1..].to_vec();
    eprintln!(
        "[proof] before the restart: {} rows, position {before_position}",
        before.len()
    );

    room.restart(0);
    let alice = &room.workers[0];

    // 1. The same rows, in the same order.
    let after = order(alice, &r);
    eprintln!("[proof] after the restart: {} rows", after.len());
    assert!(
        after.len() >= before.len(),
        "rows lost across the restart: {} before, {} after",
        before.len(),
        after.len()
    );
    let moved: Vec<usize> = (0..before.len())
        .filter(|&i| after[i] != before[i])
        .collect();
    assert!(
        moved.is_empty(),
        "{} of {} rows are at a different position after the restart (first at {:?})",
        moved.len(),
        before.len(),
        moved.first()
    );

    // 2. The board's position is unchanged (nothing new was posted).
    assert_eq!(
        position(alice, &r),
        before_position,
        "board.position after the restart"
    );

    // 3. A cursor from before the restart resumes with exactly what followed it.
    let resumed = tail_since(alice, &r, &cursor, followed.len());
    assert_eq!(
        resumed, followed,
        "tail --since a pre-restart cursor resumes with the rows that followed it"
    );
}
