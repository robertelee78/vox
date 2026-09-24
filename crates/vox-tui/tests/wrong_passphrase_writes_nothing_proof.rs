//! A **wrong identity passphrase writes nothing** to the profile — driven through the shipped
//! binary, for every one-shot verb that opens a profile itself.
//!
//! Found the hard way on 2026-09-25: a one-shot verb run against a profile with the wrong
//! passphrase refused, correctly — and had already committed a write to that profile's
//! `store.redb`. The store was opened and its schema check committed as a write transaction
//! *before* the passphrase was tried, so the file's bytes and mtime changed for a command that
//! was refused. Nothing a person could see was lost, but a refused command has no business
//! writing, and a profile that changes when nobody could unlock it is one whose timestamps
//! cannot be trusted as evidence.
//!
//! What it asserts, for `serve`, `forward`, `up`, `connect`, `service add` and `daemon`, each run with
//! the wrong identity passphrase against a real profile with an identity in it:
//!
//! 1. the verb refuses and says the passphrase is wrong;
//! 2. `store.redb` is **byte-identical** afterwards, with an **unchanged mtime**;
//! 3. and the single-writer rule still holds: with a `vox daemon` holding the profile, a
//!    one-shot verb is still refused as busy — deferring the write must not have loosened the
//!    lock.
//!
//! Mutation: committing the schema check on every open (the old order) turns (2) red.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime};

const VOX: &str = env!("CARGO_BIN_EXE_vox");
const IDPASS: &str = "the right identity passphrase";

fn vox(dir: &std::path::Path, pass: &str, args: &[&str], stdin: &str) -> (bool, String) {
    let mut child = Command::new(VOX)
        .args(args)
        .env("VOX_DATA_DIR", dir)
        .env("VOX_CONFIG_DIR", dir.join("cfg"))
        .env("VOX_IDENTITY_PASSPHRASE", pass)
        .env_remove("VOX_ROOM")
        .env_remove("VOX_ROOM_PASSPHRASE")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn vox");
    let mut pipe = child.stdin.take().expect("stdin");
    pipe.write_all(stdin.as_bytes()).expect("write");
    drop(pipe);
    let out = child.wait_with_output().expect("wait");
    (
        out.status.success(),
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    )
}

fn snapshot(store: &std::path::Path) -> (Vec<u8>, SystemTime) {
    let bytes = std::fs::read(store).expect("read store.redb");
    let mtime = std::fs::metadata(store)
        .and_then(|m| m.modified())
        .expect("mtime");
    (bytes, mtime)
}

#[test]
#[ignore = "production Argon2id per verb; CI runs it in release"]
fn a_wrong_identity_passphrase_writes_nothing_to_the_profile() {
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("profile");
    std::fs::create_dir_all(dir.join("cfg")).unwrap();
    let (ok, fp) = vox(&dir, IDPASS, &["id"], "");
    assert!(ok, "vox id: {fp}");
    let fp = fp.trim().lines().next().unwrap_or_default().to_owned();
    assert_eq!(fp.len(), 52, "a fingerprint: {fp:?}");
    let store = dir.join("default").join("store.redb");
    assert!(
        store.is_file(),
        "the profile has a store: {}",
        store.display()
    );

    // A syntactically whole address, so `connect` gets as far as opening the profile.
    let link = format!("vox://{fp}?a={fp}&b=/ip4/127.0.0.1/udp/1");
    let verbs: [(&str, Vec<&str>); 5] = [
        ("serve", vec!["serve", "9", "--listen", "127.0.0.1:0"]),
        (
            "forward",
            vec![
                "forward",
                "aaaa",
                &fp,
                "22",
                "127.0.0.1:0",
                "--passphrase",
                "x",
                "--listen",
                "127.0.0.1:0",
            ],
        ),
        (
            "up",
            vec![
                "up",
                "aaaa",
                "--passphrase",
                "x",
                "--bind",
                "127.0.0.1:0",
                "--listen",
                "127.0.0.1:0",
            ],
        ),
        (
            "connect",
            vec![
                "connect",
                &link,
                "--passphrase",
                "x",
                "--listen",
                "127.0.0.1:0",
            ],
        ),
        (
            "service add",
            vec![
                "service",
                "add",
                "aaaa",
                "ssh",
                "127.0.0.1:22",
                "--passphrase",
                "x",
                "--listen",
                "127.0.0.1:0",
            ],
        ),
    ];

    // Past the filesystem's mtime granularity, so a write in the next second shows.
    std::thread::sleep(Duration::from_millis(1100));
    let (before_bytes, before_mtime) = snapshot(&store);
    let mut refused = 0usize;
    for (name, args) in &verbs {
        let (ok, said) = vox(&dir, "not the passphrase", args, "");
        assert!(
            !ok,
            "`vox {name}` with the wrong passphrase must fail: {said}"
        );
        assert!(
            said.contains("passphrase is wrong"),
            "`vox {name}` must say the passphrase is wrong: {said}"
        );
        let (bytes, mtime) = snapshot(&store);
        assert!(
            bytes == before_bytes,
            "`vox {name}` with a WRONG passphrase changed store.redb's bytes ({} -> {} bytes)",
            before_bytes.len(),
            bytes.len()
        );
        assert_eq!(
            mtime, before_mtime,
            "`vox {name}` with a WRONG passphrase changed store.redb's mtime"
        );
        refused += 1;
        eprintln!("[{name}] refused; store.redb byte-identical, mtime unchanged");
    }
    // `vox daemon` reads its passphrase on stdin rather than from the environment.
    let (ok, said) = vox(
        &dir,
        IDPASS,
        &["daemon", "--listen", "127.0.0.1:0"],
        "not the passphrase\n",
    );
    assert!(
        !ok,
        "`vox daemon` with the wrong passphrase must fail: {said}"
    );
    assert!(
        said.contains("passphrase is wrong"),
        "`vox daemon` must say the passphrase is wrong: {said}"
    );
    let (bytes, mtime) = snapshot(&store);
    assert!(
        bytes == before_bytes && mtime == before_mtime,
        "`vox daemon` with a WRONG passphrase changed store.redb"
    );
    refused += 1;
    eprintln!("[daemon] refused; store.redb byte-identical, mtime unchanged");
    eprintln!("{refused} of {} verbs wrote nothing", verbs.len() + 1);

    // (3) The lock still holds: a daemon has the profile, a one-shot verb is refused as busy.
    let mut daemon = Command::new(VOX)
        .args(["daemon", "--listen", "127.0.0.1:0"])
        .env("VOX_DATA_DIR", &dir)
        .env("VOX_CONFIG_DIR", dir.join("cfg"))
        .env_remove("VOX_ROOM")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn the daemon");
    let mut pipe = daemon.stdin.take().expect("stdin");
    pipe.write_all(format!("{IDPASS}\n").as_bytes()).unwrap();
    drop(pipe);
    let out = daemon.stdout.take().expect("stdout");
    let deadline = Instant::now() + Duration::from_secs(90);
    let mut lines = BufReader::new(out).lines();
    loop {
        assert!(Instant::now() < deadline, "the daemon never came up");
        match lines.next() {
            Some(Ok(l)) if l.contains("control socket") => break,
            Some(_) => {}
            None => panic!("the daemon exited before coming up"),
        }
    }
    let (ok, said) = vox(&dir, IDPASS, &["serve", "9", "--listen", "127.0.0.1:0"], "");
    let _ = daemon.kill();
    let _ = daemon.wait();
    assert!(
        !ok,
        "a second process on a held profile must be refused: {said}"
    );
    assert!(
        said.contains("already running for this profile"),
        "the refusal must say the profile is held: {said}"
    );
    eprintln!("[lock] a one-shot verb against a held profile is still refused");
}
