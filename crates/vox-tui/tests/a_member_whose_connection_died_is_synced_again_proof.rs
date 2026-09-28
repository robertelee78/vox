//! V210-58 (#246) — **a member whose connection was declared dead is synced with again**, through
//! the shipped binary.
//!
//! A connection silent past `SILENCE_IS_DEATH` (30 s) is dropped as dead: a laptop lid, a frozen
//! process, a network that went away for a while. ADR-025's scheduler runs a room's sync only over
//! a connection that exists, and nothing dialled a member for sync. Members were dialled for key
//! work, and reached each other through the room's anchor. So once the anchor was gone too, two
//! members whose connection had been dropped never synced again. CI run 36452063803
//! (two_backlogs, bob frozen 31.3 s) sat 150 s with bob and carol each holding a backlog for the
//! other and neither dialling. Now a port that needs a session and has no connection reaches its
//! peer (ADR-025 D2), off the actor, one reach per peer, and backs off as Unreachable when that
//! fails.
//!
//! **The scene**, all real `vox` processes:
//! 1. An anchor, and two `vox daemon`s, carol and bob, trusting each other in one room. Each
//!    reads the other's latest hello.
//! 2. Bob is frozen (`SIGSTOP`) for [`FREEZE`], past QUIC's 60 s idle timeout, so the connection
//!    between them is **gone at both ends**, whatever either node did meanwhile. Carol posts
//!    [`POSTS`] rows meanwhile. (A freeze just past the 30 s silence line was not enough to stage it:
//!    a node drops a silent connection only when it next looks at it, and a port in backoff
//!    does not look. With the reach removed, bob still read carol's rows over the surviving
//!    connection, 2 runs of 2. CI's 31.3 s happened to be looked at.)
//! 3. The anchor is stopped, so no board or relay is left between them. Then bob is continued.
//!
//! **What must hold:** bob reads every one of carol's rows within [`BACK_WITHIN`] of being
//! continued. Before the fix he never did.
//!
//! Mutation: the scheduler's reach removed (nothing dials a member for sync) → red.

#![cfg(unix)]

#[path = "support/world.rs"]
mod world;

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::io::Write as _;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use world::{args, vox_once, VoxProc};

const VOX: &str = env!("CARGO_BIN_EXE_vox");
const IDENTITY: &str = "identity passphrase";
/// Past QUIC's idle timeout (`MAX_IDLE_MS`, 60 s): the connection is closed at both ends.
const FREEZE: Duration = Duration::from_secs(70);
/// Rows carol posts while bob is frozen.
const POSTS: usize = 20;
/// How soon after bob is continued he must read all of carol's rows: a periodic request (at most
/// 30 s) and one dial. The old code never got there.
const BACK_WITHIN: Duration = Duration::from_secs(60);
const SETUP: Duration = Duration::from_secs(90);

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

fn signal(p: &VoxProc, sig: &str) {
    let ok = Command::new("kill")
        .args([sig, &p.child.id().to_string()])
        .status()
        .is_ok_and(|s| s.success());
    assert!(ok, "kill {sig} {}", p.name);
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
    let deadline = Instant::now() + SETUP;
    while Instant::now() < deadline {
        if vox_once(data, &args(&["room", "list"])).0 {
            return p;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    panic!("{name}'s daemon never answered `vox room list`");
}

/// How many of carol's `SILENT-` rows `data`'s node reads.
fn rows_read(data: &Path, room: &str) -> usize {
    let (_, out, _) = vox_once(data, &args(&["room", "read", room]));
    (0..POSTS)
        .filter(|i| out.contains(&format!("SILENT-{i:03}")))
        .count()
}

#[test]
#[ignore = "real vox processes and a 70 s freeze; CI runs it in release"]
fn a_member_whose_connection_died_is_synced_again() {
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();
    let dir = |n: &str| {
        let d = tmp.path().join(n);
        std::fs::create_dir_all(d.join("cfg")).unwrap();
        d
    };
    let (anchor_dir, bob_dir, carol_dir) = (dir("anchor"), dir("bob"), dir("carol"));
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
    let (bob_fp, carol_fp) = (fp(&bob_dir), fp(&carol_dir));
    for (d, other, name) in [(&bob_dir, &carol_fp, "carol"), (&carol_dir, &bob_fp, "bob")] {
        let (ok, out, err) = vox_once(d, &args(&["trust", "add", other, "--name", name]));
        assert!(ok, "vox trust add {name}: {out}{err}");
    }
    let mut carol = daemon("carol", &carol_dir, &spec, &idpass);
    let mut bob = daemon("bob", &bob_dir, &spec, &idpass);

    let (ok, out, err) = vox_in(&carol_dir, &["room", "create", "--name", "r"], "room pass");
    assert!(ok, "vox room create: {out}{err}");
    let (ok, list, err) = vox_once(&carol_dir, &args(&["room", "list"]));
    assert!(ok, "vox room list: {err}");
    let room = list
        .lines()
        .find(|l| l.contains(" r"))
        .and_then(|l| l.split_whitespace().next())
        .unwrap_or_else(|| panic!("room not listed: {list}"))
        .to_owned();
    let (ok, link, err) = vox_once(&carol_dir, &args(&["room", "invite", &room]));
    assert!(ok, "vox room invite: {err}");
    let (ok, out, err) = vox_in(
        &bob_dir,
        &["room", "join", link.trim(), "--name", "r"],
        "room pass",
    );
    assert!(ok, "bob joins: {out}{err}");

    // ---- 1. each reads the other's latest hello ------------------------------------------------
    let deadline = Instant::now() + SETUP;
    let mut round = 0u32;
    'warm: loop {
        round += 1;
        for (name, d) in [("carol", &carol_dir), ("bob", &bob_dir)] {
            let (ok, _, err) = vox_once(
                d,
                &args(&[
                    "room",
                    "post",
                    &room,
                    &format!("hello from {name} r{round}"),
                ]),
            );
            assert!(ok, "{name} posts: {err}");
        }
        let round_ends = Instant::now() + Duration::from_secs(10);
        while Instant::now() < round_ends {
            let (_, b, _) = vox_once(&bob_dir, &args(&["room", "read", &room]));
            let (_, c, _) = vox_once(&carol_dir, &args(&["room", "read", &room]));
            if b.contains(&format!("hello from carol r{round}"))
                && c.contains(&format!("hello from bob r{round}"))
            {
                eprintln!("[setup] each reads the other's hello of round {round}");
                break 'warm;
            }
            assert!(
                Instant::now() < deadline,
                "CANNOT MEASURE: bob and carol never read each other's hellos\n---- bob ----\n{}\n\
                 ---- carol ----\n{}",
                bob.transcript(),
                carol.transcript()
            );
            std::thread::sleep(Duration::from_millis(250));
        }
    }

    // ---- 2. bob frozen past the 30 s line; carol posts -----------------------------------------
    signal(&bob, "-STOP");
    let frozen = Instant::now();
    for i in 0..POSTS {
        let (ok, out, err) = vox_once(
            &carol_dir,
            &args(&["room", "post", &room, &format!("SILENT-{i:03}")]),
        );
        assert!(ok, "carol post {i}: {out}{err}");
    }
    std::thread::sleep(FREEZE.saturating_sub(frozen.elapsed()));

    // ---- 3. no anchor left; bob continued -------------------------------------------------------
    let anchor_said = anchor.transcript();
    signal(&anchor, "-INT");
    let stopping = Instant::now();
    while anchor.child.try_wait().ok().flatten().is_none() {
        assert!(
            stopping.elapsed() < Duration::from_secs(20),
            "CANNOT MEASURE: the anchor did not stop"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    signal(&bob, "-CONT");
    let back = Instant::now();
    println!("[proof] bob was frozen for {:.1?}", frozen.elapsed());
    let early = rows_read(&bob_dir, &room);
    assert_eq!(
        early, 0,
        "CANNOT MEASURE: bob already read {early}/{POSTS} of carol's rows before he could sync"
    );
    let mut read = 0;
    while back.elapsed() < BACK_WITHIN {
        read = rows_read(&bob_dir, &room);
        if read == POSTS {
            break;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    let took = back.elapsed();
    println!("[proof] {took:.1?} after bob was continued: he reads {read}/{POSTS} of carol's rows");
    if read < POSTS {
        println!("---- bob said ----\n{}", bob.transcript());
        println!("---- carol said ----\n{}", carol.transcript());
        println!("---- the anchor said (until stopped) ----\n{anchor_said}");
    }
    assert_eq!(
        read, POSTS,
        "a member whose connection was dropped as dead was not synced with again within \
         {BACK_WITHIN:?}: bob reads {read}/{POSTS} of carol's rows"
    );
}
