//! V210-29 (#202) — **a sync that did not complete says why**, through the shipped binary.
//!
//! Alice and Bob are real `vox daemon`s in one room, behind a real `vox node` anchor. They post
//! at the same moment, [`ROUNDS`] times, so their pushes collide: each end's session for the room
//! is running when the other's arrives, and each refuses the other. That collision is the
//! commonest failure between two live members, and the push retry resolves it.
//!
//! Before #202 the daemon said nothing about a failed sync. Inside, every one was wrapped as
//! "malformed governance struct: sync failed: transport": the refusal was sent with the code for
//! an invalid authenticator, and the initiator never read the code at all. So a collision could
//! not be told from a dead path, and whatever reported it pointed at corrupt data.
//!
//! What this asserts, on both daemons' stderr:
//! 1. at least one failed sync is reported **as a collision**: "the peer was busy syncing this
//!    room";
//! 2. no failed sync between the two members is reported as a governance or malformed-data
//!    error, or as an invalid authenticator.
//!
//! If no collision happened in all the rounds, the run proves nothing, and it fails as CANNOT
//! MEASURE rather than passing.
//!
//! Mutations: the old governance wrapper in `sync_failure` breaks (2); a collision refused with the
//! uninformative code breaks (1) and (2).

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
/// What a collision reads as, from the coded reason `SessionBusy`.
const COLLISION: &str = "the peer was busy syncing this room";

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
        .expect("run vox");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin.as_bytes())
        .unwrap();
    let out = child.wait_with_output().expect("vox finished");
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
            pass_file.to_str().unwrap(),
        ]),
    );
    let deadline = Instant::now() + TIMEOUT;
    while Instant::now() < deadline {
        if vox_once(data, &args(&["room", "list"])).0 {
            return p;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    panic!("{name}'s daemon never answered `vox room list`");
}

/// The daemon's reports of syncs that did not complete.
fn sync_failures(p: &mut VoxProc) -> Vec<String> {
    p.transcript()
        .lines()
        .filter(|l| l.contains("did not complete"))
        .map(str::to_owned)
        .collect()
}

#[test]
#[ignore = "real vox processes with production Argon2id; CI runs it in release"]
fn a_sync_that_did_not_complete_says_why() {
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();
    let dir = |n: &str| {
        let d = tmp.path().join(n);
        std::fs::create_dir_all(d.join("cfg")).unwrap();
        d
    };
    let (anchor_dir, alice_dir, bob_dir) = (dir("anchor"), dir("alice"), dir("bob"));
    let idpass = tmp.path().join("idpass");
    std::fs::write(&idpass, IDENTITY).unwrap();

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
        assert!(ok, "vox id: {err}");
        out.trim().to_owned()
    };
    let (alice_fp, bob_fp) = (fp(&alice_dir), fp(&bob_dir));
    for (d, other, name) in [(&alice_dir, &bob_fp, "bob"), (&bob_dir, &alice_fp, "alice")] {
        let (ok, out, err) = vox_once(d, &args(&["trust", "add", other, "--name", name]));
        assert!(ok, "vox trust add {name}: {out}{err}");
    }

    let mut alice = daemon("alice", &alice_dir, &spec, &idpass);
    let mut bob = daemon("bob", &bob_dir, &spec, &idpass);

    let (ok, out, err) = vox_in(
        &alice_dir,
        &["room", "create", "--name", "pair"],
        "room pass",
    );
    assert!(ok, "vox room create: {out}{err}");
    let (ok, list, err) = vox_once(&alice_dir, &args(&["room", "list"]));
    assert!(ok, "vox room list: {err}");
    let room = list
        .lines()
        .find(|l| l.contains("pair"))
        .and_then(|l| l.split_whitespace().next())
        .unwrap_or_else(|| panic!("room not listed: {list}"))
        .to_owned();
    let (ok, link, err) = vox_once(&alice_dir, &args(&["room", "invite", &room]));
    assert!(ok, "vox room invite: {err}");
    let (ok, out, err) = vox_in(
        &bob_dir,
        &["room", "join", link.trim(), "--name", "pair"],
        "room pass",
    );
    assert!(ok, "bob joins: {out}{err}");

    // Both members read each other before the rounds, so every failure below is between two
    // members that can sync, not a join still settling.
    let deadline = Instant::now() + TIMEOUT;
    let (ok, _, err) = vox_once(
        &alice_dir,
        &args(&["room", "post", &room, "hello from alice"]),
    );
    assert!(ok, "alice posts: {err}");
    loop {
        let (_, read, _) = vox_once(&bob_dir, &args(&["room", "read", &room]));
        if read.contains("hello from alice") {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "CANNOT MEASURE: bob never read alice before the rounds"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
    // What was reported before the rounds is not what this measures.
    let _ = sync_failures(&mut alice);
    let _ = sync_failures(&mut bob);

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
    a.join().unwrap();
    b.join().unwrap();
    // Let the retries of the last collisions finish and be reported.
    std::thread::sleep(Duration::from_secs(5));

    let reports: Vec<String> = sync_failures(&mut alice)
        .into_iter()
        .map(|l| format!("alice {l}"))
        .chain(
            sync_failures(&mut bob)
                .into_iter()
                .map(|l| format!("bob {l}")),
        )
        .collect();
    let collisions = reports.iter().filter(|l| l.contains(COLLISION)).count();
    let misnamed: Vec<&String> = reports
        .iter()
        .filter(|l| {
            l.contains("governance") || l.contains("malformed") || l.contains("authenticator")
        })
        .collect();
    println!(
        "[proof] {} failed-sync report(s) over {ROUNDS} simultaneous rounds: {collisions} named as a \
         collision, {} misnamed",
        reports.len(),
        misnamed.len()
    );
    for l in reports.iter().take(12) {
        println!("[report] {l}");
    }
    assert!(
        misnamed.is_empty(),
        "a failed sync between two members was reported as a governance, malformed-data or \
         authenticator failure: {misnamed:?}"
    );
    assert!(
        collisions > 0,
        "no failed sync was reported as a collision over {ROUNDS} simultaneous rounds (reports: \
         {reports:?}). If there are no reports at all, the node reported nothing, or no collision \
         happened: CANNOT MEASURE either way"
    );
    drop(anchor);
}
