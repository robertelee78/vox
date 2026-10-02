//! **V210-30 — a key taken for a consent that was withdrawn is never delivered**, through the
//! shipped `vox` binary.
//!
//! V210-30 holds each consent's sender key from the moment it is decided until it can be
//! delivered. That held key must not outlive the trust it came from: with bob unreachable (the
//! anchor's relay frozen), carol trusts bob, **removes** him, posts, then trusts him again and
//! posts again. Bob must read the post made after the re-trust, and must **not** read the one
//! made while he was untrusted, which only the withdrawn key could open.
//!
//! Two arms, one per way a consent's key can reach bob:
//!
//! - **the pairwise stream**: the relay is frozen for 4 s, and carol's key goes to bob directly
//!   once he can be reached (most runs; the dial can also fail, and then it goes the other way);
//! - **the room's log** (ADR-023 M23.3): the relay is frozen for longer than a dial takes to give
//!   up, so carol's dial to bob **must** fail and the key goes to him as a key-package in the log.
//!   The arm checks that the dial did fail, so it measures the log path and nothing else.
//!
//! Both must deliver the key taken when the consent was decided. The log path used to take a new
//! one when the dial failed, after the post, so bob could never read it: red in 9 of 20 runs of
//! the one-arm proof on the v0.3.0 merge (#226), and in every run of the log arm.
//!
//! Mutations: `untrust_identity` not forgetting the pending consents lets bob read the post made
//! while he was untrusted (red, both arms); `deliver_through_log` taking a fresh key instead of the
//! held one leaves the post unreadable (red, the log arm). Written by agent_comms while verifying
//! #203; the log arm was added in #226.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/world.rs"]
mod world;

#[path = "support/relay.rs"]
mod relay;

use std::io::{Read, Write};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use relay::{Anchor, Split};

const VOX: &str = env!("CARGO_BIN_EXE_vox");
const IDPASS: &str = "an identity passphrase";
const ROOMPASS: &str = "room passphrase";
/// How long the relay is held frozen for the pairwise arm: carol's decisions are made while bob is
/// unreachable, and he is reachable again well inside a dial's patience.
const FREEZE: Duration = Duration::from_secs(4);
/// How long it is held frozen for the log arm: past a dial's patience (10 s per attempt, and carol
/// makes two), so the key cannot go by the pairwise stream.
const LONG_FREEZE: Duration = Duration::from_secs(30);

fn vox(dir: &std::path::Path, args: &[&str], stdin: Option<&str>) -> (bool, String, String) {
    let mut child = Command::new(VOX)
        .args(args)
        .env("VOX_DATA_DIR", dir)
        .env("VOX_CONFIG_DIR", dir.join("cfg"))
        .env("VOX_IDENTITY_PASSPHRASE", IDPASS)
        .env_remove("VOX_ROOM")
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("APPARATUS: cannot spawn vox: {e}"));
    if let Some(text) = stdin {
        let mut pipe = child.stdin.take().expect("APPARATUS: no stdin pipe");
        pipe.write_all(text.as_bytes())
            .unwrap_or_else(|e| panic!("APPARATUS: cannot write vox's stdin: {e}"));
    }
    let out = child
        .wait_with_output()
        .unwrap_or_else(|e| panic!("APPARATUS: cannot wait for vox: {e}"));
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn reads(dir: &std::path::Path, room: &str, text: &str) -> bool {
    vox(dir, &["room", "read", room], None).1.contains(text)
}

fn until(what: &str, secs: u64, ok: impl Fn() -> bool) -> bool {
    let deadline = Instant::now() + Duration::from_secs(secs);
    while Instant::now() < deadline {
        if ok() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    eprintln!("[proof] {what}: not within {secs} s");
    false
}

/// A daemon, killed by its own PID however the test ends, its output kept.
struct Daemon(Child, Arc<Mutex<String>>);

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn daemon(dir: &std::path::Path, listen: &str, anchor: &str) -> Daemon {
    let mut child = Command::new(VOX)
        .args(["daemon", "--listen", listen, "--anchor", anchor])
        .env("VOX_DATA_DIR", dir)
        .env("VOX_CONFIG_DIR", dir.join("cfg"))
        .env_remove("VOX_ROOM")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("APPARATUS: cannot spawn a daemon: {e}"));
    let mut pipe = child.stdin.take().expect("APPARATUS: no daemon stdin pipe");
    pipe.write_all(format!("{IDPASS}\n").as_bytes())
        .unwrap_or_else(|e| panic!("APPARATUS: cannot write the daemon's stdin: {e}"));
    drop(pipe);
    let said = Arc::new(Mutex::new(String::new()));
    for stream in [
        child
            .stdout
            .take()
            .map(|s| Box::new(s) as Box<dyn Read + Send>),
        child
            .stderr
            .take()
            .map(|s| Box::new(s) as Box<dyn Read + Send>),
    ]
    .into_iter()
    .flatten()
    {
        let sink = Arc::clone(&said);
        let mut stream = stream;
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            loop {
                match stream.read(&mut buf) {
                    Ok(0) | Err(_) => return,
                    Ok(n) => sink
                        .lock()
                        .unwrap()
                        .push_str(&String::from_utf8_lossy(&buf[..n])),
                }
            }
        });
    }
    let d = Daemon(child, said);
    let deadline = Instant::now() + Duration::from_secs(90);
    while !d.1.lock().unwrap().contains("control socket") {
        assert!(
            Instant::now() < deadline,
            "PRODUCT: a daemon never served its control socket:\n{}",
            d.1.lock().unwrap()
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    d
}

fn signal(pid: u32, sig: &str) {
    let ok = Command::new("kill")
        .args([sig, &pid.to_string()])
        .status()
        .is_ok_and(|s| s.success());
    assert!(ok, "APPARATUS: kill {sig} {pid} did not take");
}

#[test]
#[ignore = "three daemons and a relay anchor with production Argon2id; CI runs it in release"]
fn a_retrust_does_not_inherit_a_withdrawn_key() {
    retrust(FREEZE, false);
}

#[test]
#[ignore = "three daemons and a relay anchor with production Argon2id; CI runs it in release"]
fn a_retrust_through_the_log_does_not_inherit_a_withdrawn_key_either() {
    retrust(LONG_FREEZE, true);
}

/// Freeze the relay for `freeze`, and have carol trust, untrust, post, re-trust and post while bob
/// is unreachable. `through_log`: the dial to bob must have failed, so the key went by the log.
fn retrust(freeze: Duration, through_log: bool) {
    watchdog::arm();
    let tmp = tempfile::tempdir().expect("APPARATUS: no temp dir");
    let dirs: Vec<std::path::PathBuf> = ["alice", "bob", "carol"]
        .iter()
        .map(|n| tmp.path().join(n))
        .collect();
    for d in &dirs {
        std::fs::create_dir_all(d.join("cfg")).expect("APPARATUS: cannot make a profile directory");
    }
    let (alice_dir, bob_dir, carol_dir) = (&dirs[0], &dirs[1], &dirs[2]);
    let anchor = Anchor::start(&tmp.path().join("anchor"));
    let mut fps = Vec::new();
    for d in &dirs {
        let (ok, out, err) = vox(d, &["id"], None);
        assert!(ok, "PRODUCT (staging): vox id failed: {err}");
        fps.push(out.trim().to_owned());
    }
    let _alice = daemon(alice_dir, "127.0.0.1:0", &anchor.v4_spec);
    let bob = daemon(bob_dir, "127.0.0.1:0", &anchor.v4_spec);
    let carol_spec = Split::Families.guest_spec(&anchor).to_owned();
    let carol = daemon(carol_dir, Split::Families.guest_listen(), &carol_spec);
    let said = |d: &Daemon| d.1.lock().unwrap_or_else(|e| e.into_inner()).clone();

    for (i, name) in [(1usize, "bob"), (2, "carol")] {
        let (ok, _, err) = vox(alice_dir, &["trust", "add", &fps[i], "--name", name], None);
        assert!(ok, "PRODUCT (staging): alice trusts {name} failed: {err}");
        let (ok, _, err) = vox(
            &dirs[i],
            &["trust", "add", &fps[0], "--name", "alice"],
            None,
        );
        assert!(ok, "PRODUCT (staging): {name} trusts alice failed: {err}");
    }
    let (ok, _, err) = vox(
        alice_dir,
        &["room", "create", "--name", "late"],
        Some(&format!("{ROOMPASS}\n")),
    );
    assert!(ok, "PRODUCT (staging): room create failed: {err}");
    let listed = vox(alice_dir, &["room", "list"], None).1;
    let room = listed
        .split_whitespace()
        .find(|w| w.len() >= 12 && w.chars().all(|c| c.is_ascii_alphanumeric()))
        .unwrap_or_else(|| panic!("PRODUCT (staging): no room id in `vox room list`: {listed:?}"))
        .to_owned();
    let (ok, link, err) = vox(alice_dir, &["room", "invite", &room], None);
    assert!(ok, "PRODUCT (staging): room invite failed: {err}");
    for d in [bob_dir, carol_dir] {
        let (ok, _, err) = vox(
            d,
            &["room", "join", link.trim(), "--name", "late"],
            Some(&format!("{ROOMPASS}\n")),
        );
        assert!(ok, "PRODUCT (staging): a join failed: {err}");
    }
    // Bob trusts carol from the start: a node reads only whom its owner trusts (V210-118), so
    // what this measures is carol's decision alone.
    let (ok, _, err) = vox(bob_dir, &["trust", "add", &fps[2], "--name", "carol"], None);
    assert!(ok, "PRODUCT (staging): bob trusts carol failed: {err}");
    // Both hold the room and each other's admission before carol decides anything.
    let (ok, _, err) = vox(
        carol_dir,
        &["room", "post", &room, "CAROL-BEFORE-TRUST"],
        None,
    );
    assert!(ok, "PRODUCT (staging): carol's first post failed: {err}");
    assert!(
        until("bob holds carol's entry (unreadable yet)", 60, || {
            vox(bob_dir, &["room", "read", &room, "--json"], None)
                .1
                .contains(&fps[2][..20])
                || reads(alice_dir, &room, "CAROL-BEFORE-TRUST")
        }),
        "PRODUCT (staging): carol's first post never reached the room"
    );
    std::thread::sleep(Duration::from_secs(3));
    assert!(
        !reads(bob_dir, &room, "CAROL-BEFORE-TRUST"),
        "PRODUCT: bob reads carol's post before carol trusts him — a confidentiality breach\n\
         ---- bob ----\n{}",
        said(&bob)
    );

    // ---- with bob unreachable: trust, untrust, post, re-trust, post ----
    let anchor_pid = anchor.proc.child.id();
    signal(anchor_pid, "-STOP");
    let frozen = Instant::now();
    let (ok, _, err) = vox(carol_dir, &["trust", "add", &fps[1], "--name", "bob"], None);
    assert!(ok, "PRODUCT: carol trusts bob: {err}");
    let (ok, o, err) = vox(carol_dir, &["trust", "remove", &fps[1]], None);
    assert!(ok, "PRODUCT: carol untrusts bob: {o}{err}");
    let (ok, _, err) = vox(
        carol_dir,
        &["room", "post", &room, "CAROL-WHILE-UNTRUSTED"],
        None,
    );
    assert!(
        ok,
        "PRODUCT: carol's post while bob is untrusted failed: {err}"
    );
    let (ok, _, err) = vox(carol_dir, &["trust", "add", &fps[1], "--name", "bob"], None);
    assert!(ok, "PRODUCT: carol re-trusts bob: {err}");
    let (ok, _, err) = vox(
        carol_dir,
        &["room", "post", &room, "CAROL-AFTER-RETRUST"],
        None,
    );
    assert!(ok, "PRODUCT: carol's post after the re-trust failed: {err}");
    std::thread::sleep(freeze.saturating_sub(frozen.elapsed()));
    signal(anchor_pid, "-CONT");
    let after = until("bob reads CAROL-AFTER-RETRUST", 90, || {
        reads(bob_dir, &room, "CAROL-AFTER-RETRUST")
    });
    std::thread::sleep(Duration::from_secs(5));
    let leaked = reads(bob_dir, &room, "CAROL-WHILE-UNTRUSTED");
    eprintln!("[proof] after-retrust read = {after}; while-untrusted read (a leak) = {leaked}");
    let said = |d: &Daemon| d.1.lock().unwrap().clone();
    if !after {
        // Each daemon's own report, so a red names its cause.
        for (name, d) in [("alice", &alice_d), ("bob", &bob_d), ("carol", &carol_d)] {
            eprintln!("---- {name}'s daemon ----\n{}", said(d));
        }
    }
    if through_log {
        // The log arm measures the log path only if the pairwise one was closed.
        let bob_short: String = fps[1].chars().take(26).collect();
        let dial_failed = said(&carol_d)
            .lines()
            .any(|l| l.contains("could not reach") && l.contains(&bob_short));
        eprintln!("[proof] carol's dial to bob failed (the key went by the log) = {dial_failed}");
        assert!(
            dial_failed,
            "CANNOT MEASURE: carol reached bob directly, so the log path was not taken:\n{}",
            said(&carol_d)
        );
    }
    assert!(
        !leaked,
        "PRODUCT: a re-trust inherited the pending key from before the untrust: bob reads what \
         carol posted while he was untrusted\n---- bob ----\n{}\n---- carol ----\n{}",
        said(&bob),
        said(&carol)
    );
    assert!(
        after,
        "PRODUCT: bob never read the post carol made after she re-trusted him\n---- bob ----\n{}\n\
         ---- carol ----\n{}",
        said(&bob),
        said(&carol)
    );
    assert!(
        !reads(bob_dir, &room, "CAROL-BEFORE-TRUST"),
        "PRODUCT: bob reads the post carol made before she ever trusted him (trust is \
         forward-only)\n---- bob ----\n{}",
        said(&bob)
    );
}
