//! ADR-023 M23.4 and R14 / PRD-001 R12, R14 — history per grant, and sender keys deleted
//! once nothing needs them, driven through the **shipped `vox` binary**.
//!
//! **R12.** Approving a newcomer (`vox trust add`) releases the approver's sender key. By
//! default it releases it where it stands, so the newcomer reads from the approval onward;
//! with `--history full` it releases every generation the approver still holds, at its origin,
//! so the newcomer reads what was written before too. The choice covers the approver's own
//! messages only.
//!
//! **R14.** A superseded generation's key is deleted, except while a full-history grant is
//! still owed to somebody, because that grant is the one thing it is kept for.
//!
//! What runs:
//!
//! - (a) alice posts 10, then trusts bob with `--history full` and carol with the default, and
//!   posts once more. Bob shows all 11; carol shows the later one and **none** of the 10.
//! - (b) two rotations (removing and re-trusting carol, twice): alice's `vox status` reports one
//!   generation held after each.
//!
//! **Not proved here:** that a generation is *kept* while a full-history grant is still owed,
//! and released when it is delivered. An owed grant needs a member whose node is down, and on
//! this tree trusting a member whose node is down stops the trusting node answering (reported;
//! it is in the consent delivery path, not in this change), so that half cannot be observed yet.
//!
//! Mutations (each red): `--history full` releasing only the current position; pruning disabled;
//! the grant-arrival backfill removed.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const VOX: &str = env!("CARGO_BIN_EXE_vox");
const IDENTITY: &str = "an identity passphrase";
const ROOMPASS: &str = "the room passphrase";

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

fn daemon(dir: &Path, tag: &str, stdin_lines: &str) -> Daemon {
    let out = std::fs::File::create(dir.join(format!("daemon-{tag}.out"))).unwrap();
    let err = std::fs::File::create(dir.join(format!("daemon-{tag}.err"))).unwrap();
    let mut child = Command::new(VOX)
        .args(["daemon", "--listen", "127.0.0.1:0"])
        .env("VOX_DATA_DIR", dir)
        .env("VOX_CONFIG_DIR", dir.join("cfg"))
        .env_remove("VOX_ROOM")
        .stdin(Stdio::piped())
        .stdout(Stdio::from(out))
        .stderr(Stdio::from(err))
        .spawn()
        .expect("spawn vox daemon");
    let mut pipe = child.stdin.take().expect("daemon stdin");
    pipe.write_all(stdin_lines.as_bytes()).unwrap();
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

fn identity(tmp: &Path, name: &str) -> (PathBuf, String) {
    let dir = tmp.join(name);
    std::fs::create_dir_all(dir.join("cfg")).unwrap();
    let (ok, out, err) = vox(&dir, &["id"], None);
    assert!(ok, "vox id {name}: {err}");
    (dir, out.trim().to_owned())
}

/// The texts `vox room read` returns.
fn read(dir: &Path, room: &str) -> Vec<String> {
    let (ok, out, err) = vox(dir, &["room", "read", room], None);
    assert!(ok, "vox room read: {err}");
    out.lines()
        .filter_map(|l| l.splitn(3, ' ').nth(2).map(str::to_owned))
        .collect()
}

fn count(texts: &[String], prefix: &str) -> usize {
    texts.iter().filter(|t| t.starts_with(prefix)).count()
}

fn until(dir: &Path, room: &str, what: &str, secs: u64, done: impl Fn(&[String]) -> bool) {
    let deadline = Instant::now() + Duration::from_secs(secs);
    let mut last = Vec::new();
    while Instant::now() < deadline {
        last = read(dir, room);
        if done(&last) {
            return;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    panic!("timed out waiting for {what}; `room read` shows {last:?}");
}

fn post(dir: &Path, room: &str, text: &str) {
    let (ok, _, err) = vox(dir, &["room", "post", room, text], None);
    assert!(ok, "vox room post {text:?}: {err}");
}

fn trust(dir: &Path, fp: &str, name: &str, history: &str) {
    let (ok, out, err) = vox(
        dir,
        &["trust", "add", fp, "--name", name, "--history", history],
        None,
    );
    assert!(ok, "vox trust add {name} --history {history}: {err}");
    print!("{out}");
}

fn untrust(dir: &Path, fp: &str) {
    let (ok, _, err) = vox(dir, &["trust", "remove", fp], None);
    assert!(ok, "vox trust remove: {err}");
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

fn until_generations(dir: &Path, want: u64, secs: u64) -> u64 {
    let deadline = Instant::now() + Duration::from_secs(secs);
    let mut last = None;
    while Instant::now() < deadline {
        last = generations(dir);
        if last == Some(want) {
            return want;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    panic!("alice's key store never held {want} generation(s); last saw {last:?}");
}

fn join(creator: &Path, joiner: &Path, room: &str) {
    let (ok, link, err) = vox(creator, &["room", "invite", room], None);
    assert!(ok, "vox room invite: {err}");
    let (ok, _, err) = vox(
        joiner,
        &["room", "join", link.trim(), "--name", "r"],
        Some(&format!("{ROOMPASS}\n")),
    );
    assert!(ok, "vox room join: {err}");
}

#[test]
#[ignore = "four real vox daemons and production Argon2id; CI runs it in release"]
fn an_approval_chooses_history_and_superseded_keys_are_deleted_once_no_grant_needs_them() {
    watchdog::arm();
    // `VOX_PROOF_KEEP=<dir>` keeps every profile and daemon log there, for diagnosis.
    let _guard;
    let root: PathBuf = match std::env::var("VOX_PROOF_KEEP") {
        Ok(dir) => {
            let p = PathBuf::from(dir);
            std::fs::create_dir_all(&p).unwrap();
            p
        }
        Err(_) => {
            let t = tempfile::tempdir().unwrap();
            let p = t.path().to_path_buf();
            _guard = t;
            p
        }
    };
    let tmp = root.as_path();
    let (alice, _) = identity(tmp, "alice");
    let (bob, bob_fp) = identity(tmp, "bob");
    let (carol, carol_fp) = identity(tmp, "carol");
    let _a = daemon(&alice, "alice", &format!("{IDENTITY}\n"));
    let _b = daemon(&bob, "bob", &format!("{IDENTITY}\n"));
    let _c = daemon(&carol, "carol", &format!("{IDENTITY}\n"));

    let (ok, _, err) = vox(
        &alice,
        &["room", "create", "--name", "r"],
        Some(&format!("{ROOMPASS}\n")),
    );
    assert!(ok, "vox room create: {err}");
    let (_, listed, _) = vox(&alice, &["room", "list"], None);
    let room = listed.split_whitespace().next().expect("a room").to_owned();
    for who in [&bob, &carol] {
        join(&alice, who, &room);
    }

    // ---- (a) history per grant --------------------------------------------------------
    for i in 1..=10 {
        post(&alice, &room, &format!("before {i}"));
    }
    trust(&alice, &bob_fp, "bob", "full");
    trust(&alice, &carol_fp, "carol", "now");
    post(&alice, &room, "after");
    until(&bob, &room, "bob to read all 11", 90, |t| {
        count(t, "before ") == 10 && count(t, "after") == 1
    });
    until(&carol, &room, "carol to read the later post", 90, |t| {
        count(t, "after") == 1
    });
    let (b, c) = (read(&bob, &room), read(&carol, &room));
    println!(
        "(a) bob (--history full) reads {} of 10 earlier + {} later; carol (default) reads {} of \
         10 earlier + {} later",
        count(&b, "before "),
        count(&b, "after"),
        count(&c, "before "),
        count(&c, "after")
    );
    assert_eq!(
        count(&c, "before "),
        0,
        "the default grant must not reveal history"
    );

    // ---- (b) R14: superseded generations go, unless a full grant still needs them -------
    let g0 = until_generations(&alice, 1, 30);
    println!("(b) before any rotation alice holds {g0} generation");
    for round in 1..=2 {
        untrust(&alice, &carol_fp); // rotates: carol held a key here
        let held = until_generations(&alice, 1, 30);
        println!("(b) after rotation {round}: alice holds {held} generation");
        trust(&alice, &carol_fp, "carol", "now");
    }
}
