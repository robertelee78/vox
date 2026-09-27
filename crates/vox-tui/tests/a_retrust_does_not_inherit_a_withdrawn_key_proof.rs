//! **V210-30 — a key taken for a consent that was withdrawn is never delivered**, through the
//! shipped `vox` binary.
//!
//! V210-30 holds each consent's sender key from the moment it is decided until it can be
//! delivered. That held key must not outlive the trust it came from: with bob unreachable (the
//! anchor's relay frozen), carol trusts bob, **removes** him, posts, then trusts him again and
//! posts again. Bob must read the post made after the re-trust, and must **not** read the one
//! made while he was untrusted, which only the withdrawn key could open.
//!
//! Mutation: `untrust_identity` not forgetting the pending consents lets bob read the post made
//! while he was untrusted (red). Written by agent_comms while verifying #203; not part of the
//! candidate aaf3e2c.

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
/// How long the relay is held frozen while both members open their sessions.
const FREEZE: Duration = Duration::from_secs(4);

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
        .expect("spawn vox");
    if let Some(text) = stdin {
        let mut pipe = child.stdin.take().expect("stdin");
        pipe.write_all(text.as_bytes()).expect("write");
    }
    let out = child.wait_with_output().expect("wait");
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
        .expect("spawn a daemon");
    let mut pipe = child.stdin.take().expect("stdin");
    pipe.write_all(format!("{IDPASS}\n").as_bytes()).unwrap();
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
            "a daemon never served its socket:\n{}",
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
    assert!(ok, "kill {sig} {pid}");
}

#[test]
#[ignore = "three daemons and a relay anchor with production Argon2id; CI runs it in release"]
fn a_retrust_does_not_inherit_a_withdrawn_key() {
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();
    let dirs: Vec<std::path::PathBuf> = ["alice", "bob", "carol"]
        .iter()
        .map(|n| tmp.path().join(n))
        .collect();
    for d in &dirs {
        std::fs::create_dir_all(d.join("cfg")).unwrap();
    }
    let (alice_dir, bob_dir, carol_dir) = (&dirs[0], &dirs[1], &dirs[2]);
    let anchor = Anchor::start(&tmp.path().join("anchor"));
    let mut fps = Vec::new();
    for d in &dirs {
        let (ok, out, err) = vox(d, &["id"], None);
        assert!(ok, "vox id: {err}");
        fps.push(out.trim().to_owned());
    }
    let _alice = daemon(alice_dir, "127.0.0.1:0", &anchor.v4_spec);
    let _bob = daemon(bob_dir, "127.0.0.1:0", &anchor.v4_spec);
    let carol_spec = Split::Families.guest_spec(&anchor).to_owned();
    let _carol = daemon(carol_dir, Split::Families.guest_listen(), &carol_spec);

    for (i, name) in [(1usize, "bob"), (2, "carol")] {
        let (ok, _, err) = vox(alice_dir, &["trust", "add", &fps[i], "--name", name], None);
        assert!(ok, "alice trusts {name}: {err}");
        let (ok, _, err) = vox(
            &dirs[i],
            &["trust", "add", &fps[0], "--name", "alice"],
            None,
        );
        assert!(ok, "{name} trusts alice: {err}");
    }
    let (ok, _, err) = vox(
        alice_dir,
        &["room", "create", "--name", "late"],
        Some(&format!("{ROOMPASS}\n")),
    );
    assert!(ok, "room create: {err}");
    let listed = vox(alice_dir, &["room", "list"], None).1;
    let room = listed
        .split_whitespace()
        .find(|w| w.len() >= 12 && w.chars().all(|c| c.is_ascii_alphanumeric()))
        .expect("a room id in `room list`")
        .to_owned();
    let (ok, link, err) = vox(alice_dir, &["room", "invite", &room], None);
    assert!(ok, "invite: {err}");
    for d in [bob_dir, carol_dir] {
        let (ok, _, err) = vox(
            d,
            &["room", "join", link.trim(), "--name", "late"],
            Some(&format!("{ROOMPASS}\n")),
        );
        assert!(ok, "CANNOT MEASURE: a join failed: {err}");
    }
    // Both hold the room and each other's admission before carol decides anything.
    let (ok, _, _) = vox(
        carol_dir,
        &["room", "post", &room, "CAROL-BEFORE-TRUST"],
        None,
    );
    assert!(ok);
    assert!(
        until("bob holds carol's entry (unreadable yet)", 60, || {
            vox(bob_dir, &["room", "read", &room, "--json"], None)
                .1
                .contains(&fps[2][..20])
                || reads(alice_dir, &room, "CAROL-BEFORE-TRUST")
        }),
        "CANNOT MEASURE: carol's first post never reached the room"
    );
    std::thread::sleep(Duration::from_secs(3));
    assert!(
        !reads(bob_dir, &room, "CAROL-BEFORE-TRUST"),
        "CANNOT MEASURE: bob reads carol before carol trusts him"
    );

    // ---- with bob unreachable: trust, untrust, post, re-trust, post ----
    let anchor_pid = anchor.proc.child.id();
    signal(anchor_pid, "-STOP");
    let frozen = Instant::now();
    let (ok, _, err) = vox(carol_dir, &["trust", "add", &fps[1], "--name", "bob"], None);
    assert!(ok, "carol trusts bob: {err}");
    let (ok, o, err) = vox(carol_dir, &["trust", "remove", &fps[1]], None);
    assert!(ok, "carol untrusts bob: {o}{err}");
    let (ok, _, err) = vox(
        carol_dir,
        &["room", "post", &room, "CAROL-WHILE-UNTRUSTED"],
        None,
    );
    assert!(ok, "carol posts: {err}");
    let (ok, _, err) = vox(carol_dir, &["trust", "add", &fps[1], "--name", "bob"], None);
    assert!(ok, "carol re-trusts bob: {err}");
    let (ok, _, err) = vox(
        carol_dir,
        &["room", "post", &room, "CAROL-AFTER-RETRUST"],
        None,
    );
    assert!(ok, "carol posts again: {err}");
    std::thread::sleep(FREEZE.saturating_sub(frozen.elapsed()));
    signal(anchor_pid, "-CONT");
    let after = until("bob reads CAROL-AFTER-RETRUST", 90, || {
        reads(bob_dir, &room, "CAROL-AFTER-RETRUST")
    });
    std::thread::sleep(Duration::from_secs(5));
    let leaked = reads(bob_dir, &room, "CAROL-WHILE-UNTRUSTED");
    eprintln!("[proof] after-retrust read = {after}; while-untrusted read (a leak) = {leaked}");
    assert!(
        after,
        "CANNOT MEASURE: bob never read the post made after the re-trust"
    );
    assert!(!leaked, "a re-trust inherited the pending key from before the untrust: bob reads what carol posted while he was untrusted");
    assert!(!reads(bob_dir, &room, "CAROL-BEFORE-TRUST"), "forward-only");
}
