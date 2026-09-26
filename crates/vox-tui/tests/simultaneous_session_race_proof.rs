//! **V210-27 — two members who open their pairwise session to each other at once converge on
//! one, and read each other**, forced on every run, through the shipped `vox` binary.
//!
//! Two members who trust each other auto-consent: each finds no pairwise session, opens one,
//! and sends its hello and sender key over it. If both do it before either has the other's
//! hello, each holds a session the other did not accept. Before `56f9763`, each kept its own,
//! ignored the other's hello, and could not open the key sealed under it: neither ever read the
//! other (ADR-021 F12). The fix has both ends keep the session the lower fingerprint opened.
//!
//! That race used to be caught by chance: about one run in three. Here it is forced. bob and
//! carol reach each other only through the anchor's relay (bob on `127.0.0.1`, carol on `[::1]`,
//! the anchor on `[::]`), so **freezing the anchor** (SIGSTOP) holds everything between them.
//! Both then trust each other at once: each opens its session and sends its hello into the
//! frozen relay. When the anchor is released, the two hellos cross, and each end receives the
//! other's only after it has opened its own. That is the race, on every run.
//!
//! What it asserts: before the trust, bob cannot read carol (so the keys come from this
//! exchange and nothing earlier); after it, each comes to read the other. Each keeps posting a
//! fresh probe until the other reads one, so what is measured is whether the two sessions
//! converged, not whether one particular post fell inside the window before a key arrived.
//! A consent that could not be delivered while the relay was frozen releases its key from the
//! chain's position when it IS delivered, so a post made in between is never readable to that
//! member (a separate defect, V210-29); a probe made after delivery is.

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
fn two_members_who_open_sessions_at_once_converge_and_read_each_other() {
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
    // alice and bob on IPv4, carol on IPv6: bob and carol reach each other only through
    // the anchor's relay.
    let _alice = daemon(alice_dir, "127.0.0.1:0", &anchor.v4_spec);
    let _bob = daemon(bob_dir, "127.0.0.1:0", &anchor.v4_spec);
    let carol_spec = Split::Families.guest_spec(&anchor).to_owned();
    let _carol = daemon(carol_dir, Split::Families.guest_listen(), &carol_spec);

    // alice's room; alice and each joiner trust each other. bob and carol do NOT, yet.
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
        &["room", "create", "--name", "race"],
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
            &["room", "join", link.trim(), "--name", "race"],
            Some(&format!("{ROOMPASS}\n")),
        );
        assert!(ok, "CANNOT MEASURE: a join failed: {err}");
    }

    // ---- precondition: bob and carol cannot read each other yet ----
    let (ok, _, _) = vox(carol_dir, &["room", "post", &room, "CAROL-BEFORE"], None);
    assert!(ok);
    assert!(
        until("alice reads carol", 60, || reads(
            alice_dir,
            &room,
            "CAROL-BEFORE"
        )),
        "CANNOT MEASURE: carol's post never reached alice"
    );
    std::thread::sleep(Duration::from_secs(3));
    assert!(
        !reads(bob_dir, &room, "CAROL-BEFORE"),
        "CANNOT MEASURE: bob already reads carol before either trusts the other, so this \
         run's keys did not come from the exchange it means to race"
    );

    // ---- the race: both open their sessions while the relay between them is frozen ----
    let anchor_pid = anchor.proc.child.id();
    signal(anchor_pid, "-STOP");
    let frozen = Instant::now();
    let (b, c) = std::thread::scope(|s| {
        let b = s.spawn(|| vox(bob_dir, &["trust", "add", &fps[2], "--name", "carol"], None));
        let c = s.spawn(|| vox(carol_dir, &["trust", "add", &fps[1], "--name", "bob"], None));
        (b.join().unwrap(), c.join().unwrap())
    });
    assert!(b.0, "bob trusts carol: {}", b.2);
    assert!(c.0, "carol trusts bob: {}", c.2);
    std::thread::sleep(FREEZE.saturating_sub(frozen.elapsed()));
    signal(anchor_pid, "-CONT");
    eprintln!(
        "[proof] relay frozen {:?} while both trusted",
        frozen.elapsed()
    );

    // ---- they converge and read each other ----
    // Each posts a fresh probe every 2 s until the other reads one of them.
    let deadline = Instant::now() + Duration::from_secs(90);
    let (mut bob_reads_carol, mut carol_reads_bob) = (false, false);
    let mut n = 0;
    while !(bob_reads_carol && carol_reads_bob) && Instant::now() < deadline {
        let (ok, _, _) = vox(
            bob_dir,
            &["room", "post", &room, &format!("BOB-PROBE-{n:02}")],
            None,
        );
        assert!(ok);
        let (ok, _, _) = vox(
            carol_dir,
            &["room", "post", &room, &format!("CAROL-PROBE-{n:02}")],
            None,
        );
        assert!(ok);
        std::thread::sleep(Duration::from_secs(2));
        carol_reads_bob |= reads(carol_dir, &room, "BOB-PROBE-");
        bob_reads_carol |= reads(bob_dir, &room, "CAROL-PROBE-");
        n += 1;
    }
    eprintln!(
        "[proof] after the race ({n} probe rounds): bob reads carol = {bob_reads_carol}, \
         carol reads bob = {carol_reads_bob}"
    );
    assert!(
        bob_reads_carol && carol_reads_bob,
        "two members who opened their sessions at once did not converge: bob reads carol = \
         {bob_reads_carol}, carol reads bob = {carol_reads_bob}"
    );
}
