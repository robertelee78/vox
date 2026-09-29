//! PRD-001 R14 (decider, 2026-09-28; #226) — **a superseded sender key kept for someone who has
//! not joined is kept for a while, not forever**, driven through the **shipped `vox` binary**.
//!
//! **The rule.** A trusted identity that has not joined a room is owed the room's history, so the
//! superseded generations of the author's sender key are kept for it (1d06e9b). Kept until it
//! joins, that is kept forever for someone who never does. The decider's rule: keep them for the
//! room's retention when it has one, otherwise 30 days, then delete them.
//!
//! **What this drives, as an operator would type it:**
//!
//! ```text
//! vox id; vox trust add dave …, bob …   # alice trusts dave (who never joins) and bob
//! vox daemon; vox room create; post     # alice's room, kept forever (no retention)
//! vox room invite / join                # bob joins and reads
//! vox trust remove bob                  # rotates alice's sender key: two generations
//! (restart alice, clock stepped 29 days) # control: both still held
//! (restart alice, clock stepped 31 days) # the claim: only the live one is held
//! ```
//!
//! The clock step is `VOX_TEST_CLOCK_STEP_MS`, which moves the node's whole clock; nothing in a
//! real deployment sets it. `vox status --json` reports `key_generations`.
//!
//! **Asserted:** at +29 days alice holds 2 generations for 10 s of prune ticks (the hold still
//! runs); at +31 days she holds 1 within 30 s. Precondition, or `CANNOT MEASURE`: before any
//! restart alice holds 2 (the rotation happened and dave's wait is keeping the old one).
//!
//! **Not driven here:** a room with a retention setting, whose hold is that retention.
//!
//! **Mutation:** take the hold out of `oldest_generation_needed` (keep until joined, as 1d06e9b
//! did) and this goes red at +31 days, still holding 2.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::io::Write;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const VOX: &str = env!("CARGO_BIN_EXE_vox");
const IDENTITY: &str = "an identity passphrase";
const ROOMPASS: &str = "the room passphrase";
const DAY_MS: i64 = 24 * 60 * 60 * 1000;

/// A `vox daemon`, killed by its own PID when dropped.
struct Daemon(Child);

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn vox(dir: &Path, args: &[&str], stdin: Option<&str>) -> (bool, String, String) {
    let mut cmd = Command::new(VOX);
    cmd.args(args)
        .env("VOX_DATA_DIR", dir)
        .env("VOX_CONFIG_DIR", dir.join("cfg"))
        .env("VOX_IDENTITY_PASSPHRASE", IDENTITY)
        .env_remove("VOX_ROOM")
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().expect("spawn vox");
    if let Some(text) = stdin {
        child
            .stdin
            .as_mut()
            .expect("stdin")
            .write_all(text.as_bytes())
            .expect("write stdin");
        drop(child.stdin.take());
    }
    // Bounded: a node that stops answering must fail this proof by name, not hang it.
    let deadline = Instant::now() + Duration::from_secs(120);
    while child.try_wait().expect("try_wait").is_none() {
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!(
                "`vox {}` got no answer in 120 s — the node stopped answering",
                args.join(" ")
            );
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let out = child.wait_with_output().expect("wait");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// Start `vox daemon` with the identity passphrase, its clock stepped by `step_ms`, and wait
/// until it answers.
fn daemon(dir: &Path, tag: &str, step_ms: i64) -> Daemon {
    let out = std::fs::File::create(dir.join(format!("daemon-{tag}.out"))).unwrap();
    let err = std::fs::File::create(dir.join(format!("daemon-{tag}.err"))).unwrap();
    let mut cmd = Command::new(VOX);
    cmd.args(["daemon", "--listen", "127.0.0.1:0"])
        .env("VOX_DATA_DIR", dir)
        .env("VOX_CONFIG_DIR", dir.join("cfg"))
        .env_remove("VOX_ROOM")
        .env_remove("VOX_TEST_CLOCK_SKEW_MS")
        .stdin(Stdio::piped())
        .stdout(Stdio::from(out))
        .stderr(Stdio::from(err));
    if step_ms == 0 {
        cmd.env_remove("VOX_TEST_CLOCK_STEP_MS");
    } else {
        cmd.env("VOX_TEST_CLOCK_STEP_MS", step_ms.to_string());
    }
    let mut child = cmd.spawn().expect("spawn vox daemon");
    let mut pipe = child.stdin.take().expect("daemon stdin");
    pipe.write_all(format!("{IDENTITY}\n").as_bytes()).unwrap();
    drop(pipe);
    let d = Daemon(child);
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        if vox(dir, &["room", "list"], None).0 {
            return d;
        }
        assert!(
            Instant::now() < deadline,
            "{tag}'s daemon never answered: {}",
            std::fs::read_to_string(dir.join(format!("daemon-{tag}.err"))).unwrap_or_default()
        );
        std::thread::sleep(Duration::from_millis(200));
    }
}

fn identity(tmp: &Path, name: &str) -> (std::path::PathBuf, String) {
    let dir = tmp.join(name);
    std::fs::create_dir_all(dir.join("cfg")).unwrap();
    let (ok, out, err) = vox(&dir, &["id"], None);
    assert!(ok, "vox id {name}: {err}");
    (dir, out.trim().to_owned())
}

fn trust(dir: &Path, fp: &str, name: &str) {
    let (ok, _, err) = vox(dir, &["trust", "add", fp, "--name", name], None);
    assert!(ok, "vox trust add {name}: {err}");
}

/// `key_generations` for the room, from `vox status --json`.
fn generations(dir: &Path) -> Option<u64> {
    let (ok, out, _) = vox(dir, &["status", "--json"], None);
    if !ok {
        return None;
    }
    let v: serde_json::Value = serde_json::from_str(&out).ok()?;
    v["rooms"][0]["key_generations"].as_u64()
}

/// Poll until alice's store holds `want` generations; the last reading otherwise.
fn until_generations(dir: &Path, want: u64, secs: u64) -> Option<u64> {
    let deadline = Instant::now() + Duration::from_secs(secs);
    let mut last = None;
    while Instant::now() < deadline {
        last = generations(dir);
        if last == Some(want) {
            return last;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    last
}

/// Every reading of alice's generations over `secs`, which a prune tick (1 s) runs through.
fn readings_over(dir: &Path, secs: u64) -> Vec<Option<u64>> {
    let deadline = Instant::now() + Duration::from_secs(secs);
    let mut seen = Vec::new();
    while Instant::now() < deadline {
        seen.push(generations(dir));
        std::thread::sleep(Duration::from_millis(500));
    }
    seen
}

#[test]
#[ignore = "real vox daemons and production Argon2id; CI runs it in release"]
fn a_key_kept_for_someone_who_never_joins_is_deleted_after_thirty_days() {
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();
    let (alice, _) = identity(tmp.path(), "alice");
    let (bob, bob_fp) = identity(tmp.path(), "bob");
    // Dave is an identity and nothing more: no daemon, never joins.
    let (_dave, dave_fp) = identity(tmp.path(), "dave");
    // Trusted before the room exists: every generation of it is dave's to be released.
    trust(&alice, &dave_fp, "dave");
    trust(&alice, &bob_fp, "bob");

    let a = daemon(&alice, "alice", 0);
    let _b = daemon(&bob, "bob", 0);
    let (ok, _, err) = vox(
        &alice,
        &["room", "create", "--name", "r"],
        Some(&format!("{ROOMPASS}\n")),
    );
    assert!(ok, "vox room create: {err}");
    let (_, listed, _) = vox(&alice, &["room", "list"], None);
    let room = listed.split_whitespace().next().expect("a room").to_owned();
    let (ok, link, err) = vox(&alice, &["room", "invite", &room], None);
    assert!(ok, "vox room invite: {err}");
    let (ok, _, err) = vox(
        &bob,
        &["room", "join", link.trim(), "--name", "r"],
        Some(&format!("{ROOMPASS}\n")),
    );
    assert!(ok, "vox room join: {err}");
    let (ok, _, err) = vox(&alice, &["room", "post", &room, "hello bob"], None);
    assert!(ok, "vox room post: {err}");
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        let (_, out, _) = vox(&bob, &["room", "read", &room], None);
        if out.contains("hello bob") {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "CANNOT MEASURE: bob never read alice's post, so he held no key to rotate away from"
        );
        std::thread::sleep(Duration::from_millis(250));
    }
    // Removing bob, who held alice's key, rotates it: a second generation.
    let (ok, _, err) = vox(&alice, &["trust", "remove", &bob_fp], None);
    assert!(ok, "vox trust remove bob: {err}");
    let before = until_generations(&alice, 2, 30);
    println!("[proof] after the rotation, unstepped: alice holds {before:?} generations");
    assert_eq!(
        before,
        Some(2),
        "CANNOT MEASURE: alice does not hold two generations after the rotation, so there is \
         nothing kept for dave to see deleted"
    );

    // ---- control: 29 days on, the hold still runs -------------------------------------
    drop(a);
    let a = daemon(&alice, "alice-29d", 29 * DAY_MS);
    let control = readings_over(&alice, 10);
    println!("[proof] +29 days: alice's generations over 10 s: {control:?}");
    assert!(
        !control.is_empty() && control.iter().all(|g| *g == Some(2)),
        "at +29 days the generation kept for dave must still be held (30-day hold); saw \
         {control:?}"
    );

    // ---- the claim: 31 days on, it is gone ----------------------------------------------
    drop(a);
    let _a = daemon(&alice, "alice-31d", 31 * DAY_MS);
    let after = until_generations(&alice, 1, 30);
    println!("[proof] +31 days: alice holds {after:?} generations");
    assert_eq!(
        after,
        Some(1),
        "at +31 days the generation kept for dave, who never joined, must be deleted (R14); \
         alice's stderr: {}",
        std::fs::read_to_string(alice.join("daemon-alice-31d.err")).unwrap_or_default()
    );
}
