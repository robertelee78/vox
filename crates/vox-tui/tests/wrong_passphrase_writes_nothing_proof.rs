//! A **wrong identity passphrase writes nothing** to the profile — driven through the shipped
//! binary, for every verb that opens a node with the identity passphrase.
//!
//! Found the hard way on 2026-09-25: a one-shot verb run against a profile with the wrong
//! passphrase refused, correctly — and had already committed a write to that profile's
//! `store.redb`. The store was opened and its schema check committed as a write transaction
//! *before* the passphrase was tried, so the file's bytes and mtime changed for a command that
//! was refused. Nothing a person could see was lost, but a refused command has no business
//! writing, and a profile that changes when nobody could unlock it is one whose timestamps
//! cannot be trusted as evidence.
//!
//! What it asserts, for `serve`, `forward`, `up`, `connect`, `node attach` and `daemon`, each run with
//! the wrong identity passphrase against a real profile with an identity in it:
//!
//! 1. the verb refuses, for the passphrase;
//! 2. `store.redb` is **byte-identical** afterwards, with an **unchanged mtime**;
//! 3. (withdrawn: the single-writer rule is ADR-026's one daemon per data root, D-1, proved in
//!    `the_daemon_and_its_nodes_proof`; a verb is a client and opens no node.)
//!
//! Mutation: committing the schema check on every open (the old order) turns (2) red.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/layout.rs"]
mod layout;

use std::io::Write;
use std::process::{Command, Stdio};
use std::time::{Duration, SystemTime};

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
        .unwrap_or_else(|e| panic!("APPARATUS: could not spawn `vox {}`: {e}", args.join(" ")));
    let mut pipe = child
        .stdin
        .take()
        .expect("APPARATUS: the child's stdin was not piped");
    pipe.write_all(stdin.as_bytes()).unwrap_or_else(|e| {
        panic!(
            "PRODUCT (staging): vox exited without reading its stdin (could not write `vox {}`'s stdin): {e}",
            args.join(" ")
        )
    });
    drop(pipe);
    let out = child.wait_with_output().unwrap_or_else(|e| {
        panic!(
            "APPARATUS: could not wait for `vox {}`: {e}",
            args.join(" ")
        )
    });
    (
        out.status.success(),
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    )
}

/// Refused because of the passphrase, in either wording: v0.2.9 prints the `WrongPassphrase`
/// token, and the R36 work (PRD-001) replaces it with "the passphrase is wrong". What this
/// gate proves is that nothing was written, not how the refusal reads.
fn refused_for_the_passphrase(said: &str) -> bool {
    // Since ADR-026 the daemon refuses the attach: "that passphrase does not open node <n>'s
    // identity".
    said.contains("passphrase is wrong")
        || said.contains("WrongPassphrase")
        || said.contains("passphrase does not open")
}

fn snapshot(store: &std::path::Path) -> (Vec<u8>, SystemTime) {
    let bytes = std::fs::read(store)
        .unwrap_or_else(|e| panic!("APPARATUS: could not read {}: {e}", store.display()));
    let mtime = std::fs::metadata(store)
        .and_then(|m| m.modified())
        .unwrap_or_else(|e| panic!("APPARATUS: could not read {}'s mtime: {e}", store.display()));
    (bytes, mtime)
}

#[test]
#[ignore = "production Argon2id per verb; CI runs it in release"]
fn a_wrong_identity_passphrase_writes_nothing_to_the_profile() {
    watchdog::arm();
    let tmp = tempfile::tempdir().expect("APPARATUS: tempdir");
    let dir = tmp.path().join("profile");
    std::fs::create_dir_all(dir.join("cfg")).expect("APPARATUS: create the profile's config dir");
    // Staging: a real profile with an identity in it. Without one nothing below is measured.
    let (ok, said) = vox(&dir, IDPASS, &["id"], "");
    assert!(
        ok,
        "PRODUCT (staging): `vox id` did not make the profile: {said}"
    );
    let fp = said.trim().lines().next().unwrap_or_default().to_owned();
    assert_eq!(
        fp.len(),
        52,
        "PRODUCT (staging): `vox id`'s first line is not a fingerprint: {said}"
    );
    let store = layout::node_dir(&dir, layout::DEFAULT_NODE).join("store.redb");
    assert!(
        store.is_file(),
        "PRODUCT (staging): `vox id` left no {} to watch: {said}",
        store.display()
    );

    // The room passphrase from a file: argv and the environment are refused (V210-72).
    let room_pass_at = tmp.path().join("room.pass");
    std::fs::write(&room_pass_at, "x").expect("APPARATUS: write the room passphrase file");
    let room_pass = room_pass_at
        .to_str()
        .expect("APPARATUS: a non-UTF-8 temp path");
    // A syntactically whole address, so `connect` gets as far as opening the profile.
    let link = format!("vox://{fp}?a={fp}&b=/ip4/127.0.0.1/udp/1");
    // The forward's address names a room the profile does not hold: the identity passphrase is
    // refused before any name is resolved.
    let forward_to = format!("22.{fp}.aaaa.vox");
    let verbs: [(&str, Vec<&str>); 5] = [
        ("serve", vec!["serve", "9=9", "--listen", "127.0.0.1:0"]),
        (
            "forward",
            vec![
                "forward",
                &forward_to,
                "127.0.0.1:0",
                "--listen",
                "127.0.0.1:0",
            ],
        ),
        (
            "up",
            vec![
                "up",
                "aaaa",
                "--passphrase-file",
                room_pass,
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
                "--passphrase-file",
                room_pass,
                "--listen",
                "127.0.0.1:0",
            ],
        ),
        // Since ADR-026 a one-shot verb (`vox service add`) opens no node and asks for no
        // passphrase (L-2); `vox node attach` is the verb that opens it with one.
        ("node attach", vec!["node", "attach", "default"]),
    ];

    // Past the filesystem's mtime granularity, so a write in the next second shows.
    std::thread::sleep(Duration::from_millis(1100));
    let (before_bytes, before_mtime) = snapshot(&store);
    let mut refused = 0usize;
    for (name, args) in &verbs {
        let (ok, said) = vox(&dir, "not the passphrase", args, "");
        assert!(
            !ok,
            "PRODUCT: `vox {name}` with the wrong passphrase succeeded; it said: {said}"
        );
        assert!(
            refused_for_the_passphrase(&said),
            "PRODUCT: `vox {name}` failed, but not for the passphrase; it said: {said}"
        );
        let (bytes, mtime) = snapshot(&store);
        assert!(
            bytes == before_bytes,
            "PRODUCT: `vox {name}` with a WRONG passphrase changed store.redb's bytes \
             ({} -> {} bytes); it said: {said}",
            before_bytes.len(),
            bytes.len()
        );
        assert_eq!(
            mtime, before_mtime,
            "PRODUCT: `vox {name}` with a WRONG passphrase changed store.redb's mtime; it said: \
             {said}"
        );
        refused += 1;
        eprintln!("[{name}] refused; store.redb byte-identical, mtime unchanged");
    }
    // `vox daemon` is given the wrong passphrase where it reads one with no terminal: from
    // VOX_IDENTITY_PASSPHRASE (v0.2.10: it never reads stdin unasked). Given the right one there
    // and the wrong one on stdin, it unlocked and ran until the watchdog.
    let (ok, said) = vox(
        &dir,
        "not the passphrase",
        &["daemon", "--listen", "127.0.0.1:0"],
        "",
    );
    assert!(
        !ok,
        "PRODUCT: `vox daemon` with the wrong passphrase succeeded; it said: {said}"
    );
    assert!(
        refused_for_the_passphrase(&said),
        "PRODUCT: `vox daemon` failed, but not for the passphrase; it said: {said}"
    );
    let (bytes, mtime) = snapshot(&store);
    assert!(
        bytes == before_bytes && mtime == before_mtime,
        "PRODUCT: `vox daemon` with a WRONG passphrase changed store.redb (bytes changed: {}, \
         mtime changed: {}); it said: {said}",
        bytes != before_bytes,
        mtime != before_mtime
    );
    refused += 1;
    eprintln!("[daemon] refused; store.redb byte-identical, mtime unchanged");
    eprintln!("{refused} of {} verbs wrote nothing", verbs.len() + 1);

    // (3) withdrawn: since ADR-026 a verb is a client and only the data root's one daemon opens
    // a node, so there is no second opener to refuse; one daemon per data root (D-1) is
    // `the_daemon_and_its_nodes_proof`'s.
}
