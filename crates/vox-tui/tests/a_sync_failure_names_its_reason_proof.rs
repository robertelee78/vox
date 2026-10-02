//! V210-29 (#202) — **a sync that did not complete says why**, through the shipped binary; and,
//! since ADR-025, **two members posting at once no longer collide at all**.
//!
//! Alice and Bob are real `vox daemon`s in one room, behind a real `vox node` anchor. They post
//! at the same moment, [`ROUNDS`] times. Before ADR-025 their pushes collided: each end's session
//! for the room was running when the other's arrived, and each refused the other (#202 made that
//! refusal say "the peer was busy syncing this room" instead of a governance error, and #216 said
//! it as the peer's refusal). ADR-025 option C (the decider, 2026-09-26) admits the inbound
//! session beside the outbound one — full duplex — so a collision report cannot occur between two
//! correct members.
//!
//! What this asserts, on both daemons' stderr, over the lines printed during the rounds:
//! 1. **no** failed sync is reported as a collision ("the peer was busy syncing this room");
//! 2. no failed sync between the two members is reported as a governance or malformed-data
//!    error, or as an invalid authenticator;
//! 3. any collision that is reported is said as the peer's refusal (#216) — vacuous while (1)
//!    holds, kept so the mutant below shows both.
//!
//! Precondition (else CANNOT MEASURE): both daemons opened at least three sessions to each other
//! over the rounds (`vox status --json`). Not one per round: posts made while a session runs are
//! carried by it (measured on the change: 14 and 10 over 40 rounds).
//!
//! 4. **A dial that gave up is logged with its cause** (PRD-001 R36, #85): after the rounds Bob's
//!    daemon is killed, Alice posts, and Alice's daemon — the node nobody is watching — logs a
//!    line naming Bob and why he could not be reached. No command is waiting on it, so the log
//!    line is the only place the failure is said.
//!
//! **A red names its side.** What (1)–(4) assert is `PRODUCT:`, quoting what the daemons logged.
//! A `vox` step the scene needs that fails is `PRODUCT (staging):`; the test's own files, pipes and
//! threads are `APPARATUS:`; too few sessions to judge (1)–(3) is `CANNOT MEASURE:`.
//!
//! Mutations: restoring the busy refusal at the inbound check breaks (1); the old governance
//! wrapper in `sync_failure` breaks (2) wherever a failure is reported; a daemon that does not log
//! an unreachable peer breaks (4).

#![cfg(unix)]

#[path = "support/world.rs"]
mod world;

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::io::Write as _;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::{Arc, Barrier};
use std::time::{Duration, Instant};

use world::{args, vox_once, VoxProc, IDENTITY, VOX};

/// Rounds of both members posting at once.
const ROUNDS: usize = 40;
const TIMEOUT: Duration = Duration::from_secs(90);
/// How long Alice may take to give up on Bob, gone, and log it. Measured on the change, with
/// Alice posting three times: two such lines in the 45 s watched after Bob's daemon was killed;
/// twice that.
const UNREACHABLE_WITHIN: Duration = Duration::from_secs(90);
/// What a collision reads as, from the coded reason `SessionBusy`.
const COLLISION: &str = "the peer was busy syncing this room";
/// A collision, said as the peer's refusal.
const REFUSED_COLLISION: &str = "the peer refused: the peer was busy syncing this room";

fn vox_in(data: &Path, argv: &[&str], stdin: &str) -> (bool, String, String) {
    let mut child = Command::new(VOX)
        .args(argv)
        .env("VOX_DATA_DIR", data)
        .env("VOX_CONFIG_DIR", data.join("cfg"))
        .env("VOX_IDENTITY_PASSPHRASE", IDENTITY)
        .env_remove("VOX_ROOM_PASSPHRASE")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("APPARATUS: run vox");
    child
        .stdin
        .take()
        .expect("APPARATUS: vox's stdin")
        .write_all(stdin.as_bytes())
        .expect("APPARATUS: write vox's stdin");
    let out = child.wait_with_output().expect("APPARATUS: wait for vox");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn daemon(name: &str, data: &Path, spec: &str, pass_file: &Path) -> VoxProc {
    let p = VoxProc::spawn(
        name,
        data,
        &args(&[
            "daemon",
            "--listen",
            "127.0.0.1:0",
            "--anchor",
            spec,
            "--passphrase-file",
            pass_file.to_str().expect("APPARATUS: a UTF-8 temp path"),
        ]),
    );
    let deadline = Instant::now() + TIMEOUT;
    while Instant::now() < deadline {
        if vox_once(data, &args(&["room", "list"])).0 {
            return p;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    panic!("PRODUCT (staging): {name}'s daemon never answered `vox room list`");
}

/// The daemon's reports of syncs that did not complete, among the lines it printed after the
/// first `since` (a count from [`lines_so_far`]).
fn sync_failures(p: &mut VoxProc, since: usize) -> Vec<String> {
    p.transcript()
        .lines()
        .skip(since)
        .filter(|l| l.contains("did not complete"))
        .map(str::to_owned)
        .collect()
}

/// How many lines the daemon has printed so far. The transcript keeps every line, so what came
/// before the rounds is excluded by position, not by draining it (the drain this replaced was inert:
/// `transcript` never forgets, so join-time failures were counted as round failures).
fn lines_so_far(p: &mut VoxProc) -> usize {
    p.transcript().lines().count()
}

#[test]
#[ignore = "real vox processes with production Argon2id; CI runs it in release"]
fn a_sync_that_did_not_complete_says_why() {
    watchdog::arm();
    let tmp = tempfile::tempdir().expect("APPARATUS: a temporary directory");
    let dir = |n: &str| {
        let d = tmp.path().join(n);
        std::fs::create_dir_all(d.join("cfg")).expect("APPARATUS: a profile directory");
        d
    };
    let (anchor_dir, alice_dir, bob_dir) = (dir("anchor"), dir("alice"), dir("bob"));
    let idpass = tmp.path().join("idpass");
    std::fs::write(&idpass, IDENTITY).expect("APPARATUS: write the passphrase file");

    let mut anchor = VoxProc::spawn(
        "anchor",
        &anchor_dir,
        &args(&["node", "--listen", "127.0.0.1:0"]),
    );
    let spec = anchor
        .expect_line("an --anchor spec", |l| {
            l.trim_start().contains("@/ip4/127.0.0.1/udp/")
        })
        .trim()
        .to_owned();

    let fp = |d: &Path| {
        let (ok, out, err) = vox_once(d, &args(&["id"]));
        assert!(ok, "PRODUCT (staging): vox id: {err}");
        out.trim().to_owned()
    };
    let (alice_fp, bob_fp) = (fp(&alice_dir), fp(&bob_dir));
    for (d, other, name) in [(&alice_dir, &bob_fp, "bob"), (&bob_dir, &alice_fp, "alice")] {
        let (ok, out, err) = vox_once(d, &args(&["trust", "add", other, "--name", name]));
        assert!(ok, "PRODUCT (staging): vox trust add {name}: {out}{err}");
    }

    let mut alice = daemon("alice", &alice_dir, &spec, &idpass);
    let mut bob = daemon("bob", &bob_dir, &spec, &idpass);

    let (ok, out, err) = vox_in(
        &alice_dir,
        &["room", "create", "--name", "pair"],
        "room pass",
    );
    assert!(ok, "PRODUCT (staging): vox room create: {out}{err}");
    let (ok, list, err) = vox_once(&alice_dir, &args(&["room", "list"]));
    assert!(ok, "PRODUCT (staging): vox room list: {err}");
    let room = list
        .lines()
        .find(|l| l.contains("pair"))
        .and_then(|l| l.split_whitespace().next())
        .unwrap_or_else(|| panic!("PRODUCT (staging): the room is not listed: {list}"))
        .to_owned();
    let (ok, link, err) = vox_once(&alice_dir, &args(&["room", "invite", &room]));
    assert!(ok, "PRODUCT (staging): vox room invite: {err}");
    let (ok, out, err) = vox_in(
        &bob_dir,
        &["room", "join", link.trim(), "--name", "pair"],
        "room pass",
    );
    assert!(ok, "PRODUCT (staging): bob joins: {out}{err}");

    // Both members read each other before the rounds, so every failure below is between two
    // members that can sync, not a join still settling.
    let deadline = Instant::now() + TIMEOUT;
    let (ok, _, err) = vox_once(
        &alice_dir,
        &args(&["room", "post", &room, "hello from alice"]),
    );
    assert!(ok, "PRODUCT (staging): alice posts: {err}");
    loop {
        let (_, read, _) = vox_once(&bob_dir, &args(&["room", "read", &room]));
        if read.contains("hello from alice") {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "PRODUCT (staging): bob never read alice before the rounds"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
    // What was reported before the rounds is not what this measures.
    let (alice_from, bob_from) = (lines_so_far(&mut alice), lines_so_far(&mut bob));

    // ---- both post at the same moment, ROUNDS times ----------------------------------------
    let barrier = Arc::new(Barrier::new(2));
    let poster = |data: std::path::PathBuf, who: &'static str| {
        let (barrier, room) = (Arc::clone(&barrier), room.clone());
        std::thread::spawn(move || {
            for i in 0..ROUNDS {
                barrier.wait();
                let _ = vox_once(
                    &data,
                    &args(&["room", "post", &room, &format!("{who} {i}")]),
                );
            }
        })
    };
    let a = poster(alice_dir.clone(), "alice");
    let b = poster(bob_dir.clone(), "bob");
    a.join().expect("APPARATUS: alice's poster thread panicked");
    b.join().expect("APPARATUS: bob's poster thread panicked");
    // Let the retries of the last collisions finish and be reported.
    std::thread::sleep(Duration::from_secs(5));

    let reports: Vec<String> = sync_failures(&mut alice, alice_from)
        .into_iter()
        .map(|l| format!("alice {l}"))
        .chain(
            sync_failures(&mut bob, bob_from)
                .into_iter()
                .map(|l| format!("bob {l}")),
        )
        .collect();
    let collisions = reports.iter().filter(|l| l.contains(COLLISION)).count();
    let unattributed: Vec<&String> = reports
        .iter()
        .filter(|l| l.contains(COLLISION) && !l.contains(REFUSED_COLLISION))
        .collect();
    let misnamed: Vec<&String> = reports
        .iter()
        .filter(|l| {
            l.contains("governance") || l.contains("malformed") || l.contains("authenticator")
        })
        .collect();
    let opened = |d: &Path, other: &str| -> u64 {
        let (ok, out, err) = vox_once(d, &args(&["status", "--json"]));
        assert!(ok, "PRODUCT (staging): vox status --json: {err}");
        let v: serde_json::Value = serde_json::from_str(out.trim()).unwrap_or_else(|e| {
            panic!("PRODUCT (staging): vox status --json printed {out:?}: {e}")
        });
        v["sync"]
            .as_array()
            .map(|rows| {
                rows.iter()
                    .filter(|r| r["peer"].as_str().is_some_and(|p| other.starts_with(p)))
                    .map(|r| r["opened"].as_u64().unwrap_or(0))
                    .sum()
            })
            .unwrap_or(0)
    };
    let (a_opened, b_opened) = (opened(&alice_dir, &bob_fp), opened(&bob_dir, &alice_fp));
    println!(
        "[proof] {} failed-sync report(s) over {ROUNDS} simultaneous rounds: {collisions} named as a \
         collision ({} not said as the peer's refusal), {} misnamed; sessions opened alice->bob \
         {a_opened}, bob->alice {b_opened}",
        reports.len(),
        unattributed.len(),
        misnamed.len()
    );
    for l in reports.iter().take(12) {
        println!("[report] {l}");
    }
    assert!(
        a_opened >= 3 && b_opened >= 3,
        "CANNOT MEASURE: the members opened {a_opened} and {b_opened} sessions to each other over \
         {ROUNDS} rounds"
    );
    assert_eq!(
        collisions, 0,
        "PRODUCT: two members posting at once refused each other as busy {collisions} time(s): \
         {reports:?}"
    );
    assert!(
        misnamed.is_empty(),
        "PRODUCT: a failed sync between two members was reported as a governance, malformed-data \
         or authenticator failure: {misnamed:?}"
    );
    assert!(
        unattributed.is_empty(),
        "PRODUCT: a collision was not reported as the peer's refusal: {unattributed:?}"
    );

    // ---- (4) a dial that gave up, in the background: Bob is gone, Alice's daemon says why ------
    let alice_mark = lines_so_far(&mut alice);
    drop(bob); // killed by its own PID, and reaped
    let bob12 = &bob_fp[..12];
    let deadline = Instant::now() + UNREACHABLE_WITHIN;
    let mut posted = 0;
    let logged = loop {
        let line = alice
            .transcript()
            .lines()
            .skip(alice_mark)
            .find(|l| l.contains("could not reach ") && l.contains(bob12))
            .map(str::to_owned);
        if line.is_some() || Instant::now() >= deadline {
            break line;
        }
        // Something to carry to Bob, every few seconds: what makes Alice dial him.
        let (ok, _, err) = vox_once(
            &alice_dir,
            &args(&["room", "post", &room, &format!("for bob, gone {posted}")]),
        );
        assert!(
            ok,
            "PRODUCT (staging): alice posts while bob is gone: {err}"
        );
        posted += 1;
        std::thread::sleep(Duration::from_secs(3));
    };
    let Some(logged) = logged else {
        panic!(
            "PRODUCT: (4) bob's daemon was killed and alice posted {posted} time(s), yet over \
             {UNREACHABLE_WITHIN:?} alice's daemon logged no line saying it could not reach him; it \
             logged:\n{}",
            alice
                .transcript()
                .lines()
                .skip(alice_mark)
                .collect::<Vec<_>>()
                .join("\n")
        );
    };
    println!("[proof] (4) alice's daemon logged: {logged}");
    let cause = logged.split_once(" — ").map_or("", |(_, why)| why.trim());
    assert!(
        cause.contains("unreachable") || cause.contains("timed out") || cause.contains("refused"),
        "PRODUCT: (4) alice's daemon logged that it could not reach bob without the specific \
         cause: {logged:?}"
    );
    drop(anchor);
}
