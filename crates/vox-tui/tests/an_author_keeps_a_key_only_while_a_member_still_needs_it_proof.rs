//! ADR-023 R14 / PRD-001 R14, design-4 R6 — **an author keeps a superseded generation of its
//! sender key only while a member still entitled to it has not taken it**, driven through the
//! **shipped `vox` binary**. (Formerly `history_grant_proof`; its `--history full` arm is gone
//! with the option, by the owner's ruling of 2026-11-27: nobody is given older history.)
//!
//! What runs: alice's room, with bob, carol and dave. Bob and dave trust alice and she trusts
//! all three. Carol does not trust alice, so she never takes alice's key and is owed it.
//!
//! - Alice posts under generation 0 and bob reads it; then bob's node stops.
//! - Alice stops trusting dave, which rotates her key (generation 1), and posts.
//! - Carol leaves the room (`vox room leave`).
//! - Alice trusts dave again, posts, stops trusting him again (generation 2) and posts.
//! - Bob's node starts again.
//!
//! **PRODUCT:** bob, trusted before all of it and offline across both rotations, reads every
//! post written after his trust; and once he has taken those keys alice's `vox status --json`
//! reports **one** generation held (`key_generations`). Carol, who left, pins nothing: her
//! untaken debt keeps no generation at alice.
//!
//! Mutation (red): `VOX_TEST_FWD_MUTANT=departed-pins` (a departed member's history floor pins
//! origins, `oldest_generation_needed`) → "alice still holds 3 generations".

#![cfg(unix)]

#[path = "support/typed.rs"]
mod typed;
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
    // A keyring change's passphrase is typed at a terminal, as a person types it (ADR-028 K-13).
    if typed::is_keyring_change(args) {
        let (ok, shown) = typed::keyring(&cmd);
        return (ok, shown.clone(), shown);
    }
    let mut child = cmd.spawn().expect("APPARATUS: spawn vox");
    if let Some(text) = stdin {
        child
            .stdin
            .as_mut()
            .expect("APPARATUS: vox stdin")
            .write_all(text.as_bytes())
            .expect("APPARATUS: write vox stdin");
        drop(child.stdin.take());
    }
    // Bounded: a node that stops answering must fail this proof by name, not hang it.
    let deadline = Instant::now() + Duration::from_secs(120);
    while child.try_wait().expect("APPARATUS: try_wait").is_none() {
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!(
                "PRODUCT: `vox {}` got no answer in 120 s — the node stopped answering",
                args.join(" ")
            );
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let out = child.wait_with_output().expect("APPARATUS: wait for vox");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn daemon(dir: &Path, tag: &str) -> Daemon {
    let out = std::fs::File::create(dir.join(format!("daemon-{tag}.out")))
        .expect("APPARATUS: daemon stdout file");
    let err = std::fs::File::create(dir.join(format!("daemon-{tag}.err")))
        .expect("APPARATUS: daemon stderr file");
    let mut cmd = Command::new(VOX);
    // The run's mutant selector reaches the daemon only by name: a proof process keeps no
    // `VOX_TEST_*` of the shell that runs it (`temp_home.rs`).
    if let Some(mutant) = std::env::var_os("VOX_MUTANT_FWD") {
        cmd.env("VOX_TEST_FWD_MUTANT", mutant);
    }
    let mut child = cmd
        .args(["daemon", "--listen", "127.0.0.1:0"])
        .env("VOX_DATA_DIR", dir)
        .env("VOX_CONFIG_DIR", dir.join("cfg"))
        .env_remove("VOX_ROOM")
        .stdin(Stdio::piped())
        .stdout(Stdio::from(out))
        .stderr(Stdio::from(err))
        .spawn()
        .expect("APPARATUS: spawn vox daemon");
    let mut pipe = child.stdin.take().expect("APPARATUS: daemon stdin");
    pipe.write_all(format!("{IDENTITY}\n").as_bytes())
        .expect("APPARATUS: write daemon stdin");
    drop(pipe);
    let d = Daemon(child);
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        if vox(dir, &["room", "list"], None).0 {
            return d;
        }
        assert!(
            Instant::now() < deadline,
            "PRODUCT (staging): {tag}'s daemon never answered: {}",
            std::fs::read_to_string(dir.join(format!("daemon-{tag}.err"))).unwrap_or_default()
        );
        std::thread::sleep(Duration::from_millis(200));
    }
}

fn identity(tmp: &Path, name: &str) -> (PathBuf, String) {
    let dir = tmp.join(name);
    std::fs::create_dir_all(dir.join("cfg")).expect("APPARATUS: profile directory");
    let (ok, out, err) = vox(&dir, &["id"], None);
    assert!(ok, "PRODUCT (staging): vox id {name}: {err}");
    (dir, out.trim().to_owned())
}

/// The texts `vox room read` returns.
fn read(dir: &Path, room: &str) -> Vec<String> {
    let (ok, out, err) = vox(dir, &["room", "read", room], None);
    assert!(ok, "PRODUCT: vox room read: {err}");
    out.lines()
        .filter_map(|l| l.splitn(3, ' ').nth(2).map(str::to_owned))
        .collect()
}

fn count(texts: &[String], prefix: &str) -> usize {
    texts.iter().filter(|t| t.starts_with(prefix)).count()
}

/// Read `room` on `dir` until `done`, for at most `secs`; the last read either way.
fn read_until(
    dir: &Path,
    room: &str,
    secs: u64,
    done: impl Fn(&[String]) -> bool,
) -> (bool, Vec<String>) {
    let deadline = Instant::now() + Duration::from_secs(secs);
    loop {
        let last = read(dir, room);
        if done(&last) {
            return (true, last);
        }
        if Instant::now() >= deadline {
            return (false, last);
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

fn post(dir: &Path, room: &str, text: &str) {
    let (ok, _, err) = vox(dir, &["room", "post", room, text], None);
    assert!(ok, "PRODUCT (staging): vox room post {text:?}: {err}");
}

fn trust(dir: &Path, fp: &str, name: &str) {
    let (ok, _, err) = vox(dir, &["trust", "add", fp, "--name", name], None);
    assert!(ok, "PRODUCT (staging): vox trust add {name}: {err}");
}

fn untrust(dir: &Path, fp: &str) {
    let (ok, _, err) = vox(dir, &["trust", "remove", fp], None);
    assert!(ok, "PRODUCT (staging): vox trust remove: {err}");
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

/// Poll alice's generations until `want`, for at most `secs`; the last reading either way.
fn until_generations(dir: &Path, want: u64, secs: u64) -> Option<u64> {
    let deadline = Instant::now() + Duration::from_secs(secs);
    let mut last = generations(dir);
    while last != Some(want) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(250));
        last = generations(dir);
    }
    last
}

fn join(creator: &Path, joiner: &Path, room: &str) {
    let (ok, link, err) = vox(creator, &["room", "link", room], None);
    assert!(ok, "PRODUCT (staging): vox room link: {err}");
    let (ok, _, err) = vox(
        joiner,
        &["room", "join", "--passphrase-file", "-", link.trim()],
        Some(&format!("{ROOMPASS}\n")),
    );
    assert!(ok, "PRODUCT (staging): vox room join: {err}");
}

#[test]
#[ignore = "four real vox daemons and production Argon2id; CI runs it in release"]
fn an_author_keeps_a_key_only_while_a_member_still_needs_it() {
    watchdog::arm();
    let mut tmp = tempfile::tempdir().expect("APPARATUS: tempdir");
    if std::env::var_os("VOX_PROOF_KEEP_DIRS").is_some() {
        tmp.disable_cleanup(true);
        println!("[proof] daemon dirs kept under {}", tmp.path().display());
    }
    let tmp = tmp.path();
    let (alice, alice_fp) = identity(tmp, "alice");
    let (bob, bob_fp) = identity(tmp, "bob");
    let (carol, carol_fp) = identity(tmp, "carol");
    let (dave, dave_fp) = identity(tmp, "dave");
    let _a = daemon(&alice, "alice");
    let b = daemon(&bob, "bob");
    let _c = daemon(&carol, "carol");
    let _d = daemon(&dave, "dave");

    let (ok, _, err) = vox(
        &alice,
        &["room", "create", "--passphrase-file", "-", "--name", "r"],
        Some(&format!("{ROOMPASS}\n")),
    );
    assert!(ok, "PRODUCT (staging): vox room create: {err}");
    let (_, listed, _) = vox(&alice, &["room", "list"], None);
    let room = listed
        .split_whitespace()
        .next()
        .expect("PRODUCT (staging): `vox room list` shows no room")
        .to_owned();
    for who in [&bob, &carol, &dave] {
        join(&alice, who, &room);
    }
    // Trust runs one way: bob and dave take alice's key once they trust her; carol never does,
    // so whatever alice owes carol stays owed.
    trust(&bob, &alice_fp, "alice");
    trust(&dave, &alice_fp, "alice");
    trust(&alice, &bob_fp, "bob");
    trust(&alice, &carol_fp, "carol");
    trust(&alice, &dave_fp, "dave");

    post(&alice, &room, "p0 1");
    for (who, name) in [(&bob, "bob"), (&dave, "dave")] {
        let (ok, t) = read_until(who, &room, 90, |t| count(t, "p0 1") == 1);
        assert!(
            ok,
            "PRODUCT (staging): {name}, trusted, never read alice's first post in 90 s: {t:?}"
        );
    }
    // Bob's node stops: he stays a member, entitled, and is owed every later generation.
    drop(b);

    // Rotation 1: dave held alice's generation 0.
    untrust(&alice, &dave_fp);
    post(&alice, &room, "p1 1");
    // Carol leaves after it: she is owed alice's key from generation 0 and never took it.
    let (ok, _, err) = vox(&carol, &["room", "leave", &room], None);
    assert!(
        ok,
        "PRODUCT (staging): carol's `vox room leave` failed: {err}"
    );
    let short = &carol_fp[..carol_fp.len().min(16)];
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        let (ok, roster, _) = vox(&alice, &["room", "roster", &room], None);
        if ok && !roster.contains(short) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "PRODUCT (staging): alice's roster still lists carol 90 s after she left: {roster}"
        );
        std::thread::sleep(Duration::from_millis(250));
    }
    // Rotation 2: dave, trusted again, takes the live generation; removing him again rotates.
    trust(&alice, &dave_fp, "dave");
    post(&alice, &room, "p1 2");
    let (ok, t) = read_until(&dave, &room, 90, |t| count(t, "p1 2") == 1);
    assert!(
        ok,
        "PRODUCT (staging): dave, trusted again, never read alice's next post in 90 s: {t:?}"
    );
    untrust(&alice, &dave_fp);
    post(&alice, &room, "p2 1");
    let offline = generations(&alice);
    println!("[proof] with bob offline and carol gone, alice holds {offline:?} generation(s)");

    // Bob comes back: he reads everything written after his trust.
    let _b = daemon(&bob, "bob-back");
    let (ok, t) = read_until(&bob, &room, 120, |t| {
        count(t, "p0 1") == 1 && count(t, "p1 ") == 2 && count(t, "p2 1") == 1
    });
    println!("[proof] bob, back, shows {t:?}");
    assert!(
        ok,
        "PRODUCT: bob, trusted before and offline across two rotations, never read every post \
         alice wrote after his trust (p0 1, p1 1, p1 2, p2 1) in 120 s: {t:?}"
    );
    let held = until_generations(&alice, 1, 60);
    println!("[proof] once bob took his keys, alice holds {held:?} generation(s)");
    assert_eq!(
        held,
        Some(1),
        "PRODUCT: alice still holds {held:?} generations 60 s after bob took every key he was \
         owed: carol, who left, must pin nothing (alice still holds 3 generations when she does)"
    );
}
