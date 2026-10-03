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
//! **The scene** follows CI's red, all real `vox` processes:
//! 1. An anchor, and two `vox daemon`s, carol and bob, trusting each other in one room. Each
//!    reads the other's latest hello.
//! 2. Bob is frozen (`SIGSTOP`) for [`FREEZE`], past the 30 s silence line, and carol posts
//!    [`POSTS`] rows meanwhile.
//! 3. The anchor is stopped, so no board or relay is left between them. Carol is frozen and bob
//!    is continued: he tries her, fails, and posts his own [`POSTS`] rows.
//! 4. Carol is continued. Each now holds rows the other lacks, with no connection between them.
//!
//! **What must hold:** within [`BACK_WITHIN`] of carol's return, bob reads every one of carol's rows
//! and carol reads every one of bob's. Without the port's own reach they waited about 20 s in this
//! scene, for something else to dial (a key to deliver). In CI's red nothing else did, and they
//! never synced.
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
/// Past the 30 s silence line, as in CI's red (31.3 s).
const FREEZE: Duration = Duration::from_secs(35);
/// How long carol stays frozen while bob, back, tries her and posts (CI's red: 7.5 s).
const CAROL_FROZEN: Duration = Duration::from_secs(10);
/// Rows carol posts while bob is frozen.
const POSTS: usize = 20;
/// How soon after both are back each must read the other's rows. The port's own reach does it
/// within a second or two. Without it they waited for some other reason to dial each other
/// (a key to deliver, the periodic request): about 20 s in this scene, and in CI's, where no such
/// reason came, never.
const BACK_WITHIN: Duration = Duration::from_secs(10);
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

/// How many of the `<tag>-NNN` rows `data`'s node reads.
fn rows_read(data: &Path, room: &str, tag: &str) -> usize {
    let (_, out, _) = vox_once(data, &args(&["room", "read", room]));
    (0..POSTS)
        .filter(|i| out.contains(&format!("{tag}-{i:03}")))
        .count()
}

#[test]
#[ignore = "real vox processes and 45 s of freezes; CI runs it in release"]
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

    let (ok, out, err) = vox_in(
        &carol_dir,
        &["room", "create", "--passphrase-file", "-", "--name", "r"],
        "room pass",
    );
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
        &[
            "room",
            "join",
            "--passphrase-file",
            "-",
            link.trim(),
            "--name",
            "r",
        ],
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

    // ---- 3. no anchor left; carol frozen while bob comes back and tries her -----------------
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
    signal(&carol, "-STOP");
    signal(&bob, "-CONT");
    println!("[proof] bob was frozen for {:.1?}", frozen.elapsed());
    let carol_frozen = Instant::now();
    for i in 0..POSTS {
        let (ok, out, err) = vox_once(
            &bob_dir,
            &args(&["room", "post", &room, &format!("RETURNED-{i:03}")]),
        );
        assert!(ok, "bob post {i}: {out}{err}");
    }
    std::thread::sleep(CAROL_FROZEN.saturating_sub(carol_frozen.elapsed()));
    let early = rows_read(&bob_dir, &room, "SILENT");
    assert_eq!(
        early, 0,
        "CANNOT MEASURE: bob already read {early}/{POSTS} of carol's rows before they could sync"
    );

    // ---- 4. carol continued: each holds rows the other lacks ------------------------------------
    signal(&carol, "-CONT");
    let back = Instant::now();
    println!(
        "[proof] carol was frozen for {:.1?}",
        carol_frozen.elapsed()
    );
    let (mut bob_has, mut carol_has) = (0, 0);
    while back.elapsed() < BACK_WITHIN {
        bob_has = rows_read(&bob_dir, &room, "SILENT");
        carol_has = rows_read(&carol_dir, &room, "RETURNED");
        if bob_has == POSTS && carol_has == POSTS {
            break;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    let took = back.elapsed();
    let read = bob_has.min(carol_has);
    println!(
        "[proof] {took:.1?} after both were back: bob reads {bob_has}/{POSTS} of carol's rows, \
         carol reads {carol_has}/{POSTS} of bob's"
    );
    if read < POSTS {
        println!("---- bob said ----\n{}", bob.transcript());
        println!("---- carol said ----\n{}", carol.transcript());
        println!("---- the anchor said (until stopped) ----\n{anchor_said}");
    }
    assert_eq!(
        read, POSTS,
        "members whose connection was dropped as dead were not synced with each other again within \
         {BACK_WITHIN:?}: bob reads {bob_has}/{POSTS} of carol's rows, carol {carol_has}/{POSTS} of \
         bob's"
    );
}
