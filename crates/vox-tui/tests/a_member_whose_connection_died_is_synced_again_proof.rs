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
//! **The dead connection is observed, not assumed**: bob's `SIGSTOP` took (`ps` reports him
//! stopped) and he stayed frozen past the 30 s silence line on this proof's clock (else CANNOT
//! MEASURE), and carol's own `vox status --json` shows a session to bob that failed while he was
//! frozen (else PRODUCT (staging)). The product exposes no line or counter for the close itself, so
//! the premise rests on those three.
//!
//! **Apparatus clock.** From carol's `SIGCONT`, a thread of this process sleeps 10 ms at a time and
//! keeps the most it overslept: the runner's own stall, which vox cannot move. If it overslept more
//! than [`APPARATUS_BUDGET`] and the rows were late, the runner owned the time: `CANNOT MEASURE:
//! the runner stalled`. Otherwise a late sync is `PRODUCT: took X (runner stalled at most Y)`. The
//! slowest poll (two `vox room read`s) and when carol first answered after `SIGCONT` are vox's own
//! timing: printed, never the clock.
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
/// `SILENCE_IS_DEATH`: a connection silent this long is dropped as dead.
const SILENCE_LINE: Duration = Duration::from_secs(30);
/// The most the runner may oversleep one 10 ms sleep before a late sync is the runner's, not
/// vox's.
const APPARATUS_BUDGET: Duration = Duration::from_secs(2);

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
        .unwrap_or_else(|e| panic!("APPARATUS: spawn vox {}: {e}", argv.join(" ")));
    child
        .stdin
        .take()
        .expect("APPARATUS: vox's stdin")
        .write_all(stdin.as_bytes())
        .unwrap_or_else(|e| panic!("APPARATUS: write vox's stdin: {e}"));
    let out = child
        .wait_with_output()
        .unwrap_or_else(|e| panic!("APPARATUS: wait for vox {}: {e}", argv.join(" ")));
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
    assert!(ok, "APPARATUS: kill {sig} {} did not take", p.name);
}

/// Whether `ps` reports `p` stopped (state `T`).
fn stopped(p: &VoxProc) -> bool {
    Command::new("ps")
        .args(["-o", "state=", "-p", &p.child.id().to_string()])
        .output()
        .is_ok_and(|o| {
            String::from_utf8_lossy(&o.stdout)
                .trim_start()
                .starts_with('T')
        })
}

/// `data`'s node's sync row for `peer` (a fingerprint), from the shipped `vox status --json`.
fn port_to(data: &Path, peer: &str) -> serde_json::Value {
    let (ok, out, err) = vox_once(data, &args(&["status", "--json"]));
    assert!(ok, "PRODUCT (staging): `vox status --json` failed: {err}");
    let status: serde_json::Value = serde_json::from_str(out.trim())
        .unwrap_or_else(|e| panic!("PRODUCT (staging): `vox status --json` printed {out:?}: {e}"));
    status["sync"]
        .as_array()
        .and_then(|rows| {
            rows.iter()
                .find(|r| r["peer"].as_str().is_some_and(|p| peer.starts_with(p)))
                .cloned()
        })
        .unwrap_or(serde_json::Value::Null)
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
            pass_file.to_str().expect("APPARATUS: a UTF-8 path"),
        ]),
    );
    let deadline = Instant::now() + SETUP;
    while Instant::now() < deadline {
        if vox_once(data, &args(&["room", "list"])).0 {
            return p;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    panic!("PRODUCT (staging): {name}'s daemon never answered `vox room list` within {SETUP:?}");
}

/// How many of the `<tag>-NNN` rows `data`'s node reads, or what `vox room read` said when it
/// failed.
fn rows_read(data: &Path, room: &str, tag: &str) -> Result<usize, String> {
    let (ok, out, err) = vox_once(data, &args(&["room", "read", room]));
    if !ok {
        return Err(format!("`vox room read` failed: {out}{err}"));
    }
    Ok((0..POSTS)
        .filter(|i| out.contains(&format!("{tag}-{i:03}")))
        .count())
}

/// The runner's own clock: a thread that sleeps 10 ms at a time and keeps the most it overslept.
/// It measures whether this process was scheduled, never vox: a slow vox does not move it, so a
/// late result with this clock quiet is the product's.
struct RunnerStall {
    worst_us: std::sync::Arc<std::sync::atomic::AtomicU64>,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl RunnerStall {
    fn start() -> Self {
        use std::sync::atomic::Ordering;
        let worst_us = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (worst, stopped) = (
            std::sync::Arc::clone(&worst_us),
            std::sync::Arc::clone(&stop),
        );
        std::thread::spawn(move || {
            while !stopped.load(Ordering::Relaxed) {
                let asked = Instant::now();
                std::thread::sleep(Duration::from_millis(10));
                let over = asked.elapsed().saturating_sub(Duration::from_millis(10));
                worst.fetch_max(
                    u64::try_from(over.as_micros()).unwrap_or(u64::MAX),
                    Ordering::Relaxed,
                );
            }
        });
        Self { worst_us, stop }
    }

    /// The most the runner overslept one 10 ms sleep since [`RunnerStall::start`].
    fn worst(&self) -> Duration {
        Duration::from_micros(self.worst_us.load(std::sync::atomic::Ordering::Relaxed))
    }
}

impl Drop for RunnerStall {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
    }
}

#[test]
#[ignore = "real vox processes and 45 s of freezes; CI runs it in release"]
fn a_member_whose_connection_died_is_synced_again() {
    watchdog::arm();
    let tmp = tempfile::tempdir().expect("APPARATUS: tempdir");
    let dir = |n: &str| {
        let d = tmp.path().join(n);
        std::fs::create_dir_all(d.join("cfg")).expect("APPARATUS: create a profile dir");
        d
    };
    let (anchor_dir, bob_dir, carol_dir) = (dir("anchor"), dir("bob"), dir("carol"));
    let idpass = tmp.path().join("idpass");
    std::fs::write(&idpass, IDENTITY).expect("APPARATUS: write the passphrase file");

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
        assert!(ok, "PRODUCT (staging): `vox id` failed: {err}");
        out.trim().to_owned()
    };
    let (bob_fp, carol_fp) = (fp(&bob_dir), fp(&carol_dir));
    for (d, other, name) in [(&bob_dir, &carol_fp, "carol"), (&carol_dir, &bob_fp, "bob")] {
        let (ok, out, err) = vox_once(d, &args(&["trust", "add", other, "--name", name]));
        assert!(
            ok,
            "PRODUCT (staging): `vox trust add {name}` failed: {out}{err}"
        );
    }
    let mut carol = daemon("carol", &carol_dir, &spec, &idpass);
    let mut bob = daemon("bob", &bob_dir, &spec, &idpass);

    let (ok, out, err) = vox_in(&carol_dir, &["room", "create", "--name", "r"], "room pass");
    assert!(
        ok,
        "PRODUCT (staging): `vox room create` failed: {out}{err}"
    );
    let (ok, list, err) = vox_once(&carol_dir, &args(&["room", "list"]));
    assert!(ok, "PRODUCT (staging): `vox room list` failed: {err}");
    let room = list
        .lines()
        .find(|l| l.contains(" r"))
        .and_then(|l| l.split_whitespace().next())
        .unwrap_or_else(|| {
            panic!("PRODUCT (staging): carol's `vox room list` names no room r: {list}")
        })
        .to_owned();
    let (ok, link, err) = vox_once(&carol_dir, &args(&["room", "invite", &room]));
    assert!(ok, "PRODUCT (staging): `vox room invite` failed: {err}");
    let (ok, out, err) = vox_in(
        &bob_dir,
        &["room", "join", link.trim(), "--name", "r"],
        "room pass",
    );
    assert!(
        ok,
        "PRODUCT (staging): bob's `vox room join` failed: {out}{err}"
    );

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
            assert!(ok, "PRODUCT (staging): {name}'s warm-up post failed: {err}");
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
                "PRODUCT (staging): bob and carol never read each other's hellos\n---- bob ----\n{}\n\
                 ---- carol ----\n{}",
                bob.transcript(),
                carol.transcript()
            );
            std::thread::sleep(Duration::from_millis(250));
        }
    }

    // ---- 2. bob frozen past the 30 s line; carol posts -----------------------------------------
    let carol_to_bob_before = port_to(&carol_dir, &bob_fp)["failed"].as_u64().unwrap_or(0);
    signal(&bob, "-STOP");
    let frozen = Instant::now();
    assert!(
        stopped(&bob),
        "APPARATUS: kill -STOP bob did not take: ps does not report him stopped"
    );
    for i in 0..POSTS {
        let (ok, out, err) = vox_once(
            &carol_dir,
            &args(&["room", "post", &room, &format!("SILENT-{i:03}")]),
        );
        assert!(ok, "PRODUCT: carol's post {i} was refused: {out}{err}");
    }
    std::thread::sleep(FREEZE.saturating_sub(frozen.elapsed()));
    // The premise: bob stopped answering carol, long enough to be dropped as dead.
    let carol_to_bob = port_to(&carol_dir, &bob_fp);
    let failed = carol_to_bob["failed"].as_u64().unwrap_or(0);
    println!(
        "[proof] carol's port to frozen bob after {:.1?}: failed {carol_to_bob_before} -> {failed}, \
         last failure {}",
        frozen.elapsed(),
        carol_to_bob["last_failure"]
    );
    assert!(
        failed > carol_to_bob_before,
        "PRODUCT (staging): no session of carol's to frozen bob failed within {:.1?}, so his \
         connection is not shown dead (her port: {carol_to_bob})",
        frozen.elapsed()
    );
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
    assert!(
        stopped(&carol),
        "APPARATUS: kill -STOP carol did not take: ps does not report her stopped"
    );
    let bob_frozen = frozen.elapsed();
    signal(&bob, "-CONT");
    println!("[proof] bob was frozen for {bob_frozen:.1?}");
    assert!(
        bob_frozen > SILENCE_LINE,
        "CANNOT MEASURE: bob was frozen only {bob_frozen:.1?}, not past the {SILENCE_LINE:?} \
         silence line"
    );
    let carol_frozen = Instant::now();
    for i in 0..POSTS {
        let (ok, out, err) = vox_once(
            &bob_dir,
            &args(&["room", "post", &room, &format!("RETURNED-{i:03}")]),
        );
        assert!(
            ok,
            "PRODUCT: bob's post {i} after he was continued was refused: {out}{err}"
        );
    }
    std::thread::sleep(CAROL_FROZEN.saturating_sub(carol_frozen.elapsed()));
    let early = rows_read(&bob_dir, &room, "SILENT")
        .unwrap_or_else(|e| panic!("PRODUCT: bob, continued, cannot read his room: {e}"));
    assert_eq!(
        early, 0,
        "CANNOT MEASURE: bob already read {early}/{POSTS} of carol's rows before they could sync"
    );

    // ---- 4. carol continued: each holds rows the other lacks ------------------------------------
    let stall = RunnerStall::start();
    signal(&carol, "-CONT");
    let back = Instant::now();
    println!(
        "[proof] carol was frozen for {:.1?}",
        carol_frozen.elapsed()
    );
    let (mut bob_has, mut carol_has) = (0, 0);
    // Vox's own timing, printed: each poll's duration, and when carol first answered a read.
    let (mut slowest, mut carol_answered, mut last_err) = (Duration::ZERO, None, None);
    while back.elapsed() < BACK_WITHIN {
        let poll = Instant::now();
        let b = rows_read(&bob_dir, &room, "SILENT");
        let c = rows_read(&carol_dir, &room, "RETURNED");
        slowest = slowest.max(poll.elapsed());
        if c.is_ok() {
            carol_answered.get_or_insert(back.elapsed());
        }
        match (b, c) {
            (Ok(b), Ok(c)) => {
                (bob_has, carol_has) = (b, c);
                last_err = None;
            }
            (Err(e), _) | (_, Err(e)) => last_err = Some(e),
        }
        if bob_has == POSTS && carol_has == POSTS {
            break;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    let took = back.elapsed();
    let read = bob_has.min(carol_has);
    let apparatus = stall.worst();
    println!(
        "[proof] {took:.1?} after both were back: bob reads {bob_has}/{POSTS} of carol's rows, \
         carol reads {carol_has}/{POSTS} of bob's; slowest poll {slowest:.1?}, carol first \
         answered {carol_answered:.1?} after SIGCONT; the runner overslept at most {apparatus:?}"
    );
    if read < POSTS {
        println!("---- bob said ----\n{}", bob.transcript());
        println!("---- carol said ----\n{}", carol.transcript());
        println!("---- the anchor said (until stopped) ----\n{anchor_said}");
    }
    if read < POSTS {
        assert!(
            apparatus <= APPARATUS_BUDGET,
            "CANNOT MEASURE: the runner stalled: it overslept a 10 ms sleep by {apparatus:?} \
             (budget {APPARATUS_BUDGET:?}) while bob read {bob_has}/{POSTS} and carol \
             {carol_has}/{POSTS} within {BACK_WITHIN:?}"
        );
        panic!(
            "PRODUCT: took more than {took:?} (runner stalled at most {apparatus:?}): members whose connection \
             was dropped as dead were not synced with each other again within {BACK_WITHIN:?}: bob \
             reads {bob_has}/{POSTS} of carol's rows, carol {carol_has}/{POSTS} of bob's{}",
            last_err.map_or_else(String::new, |e| format!("; the last read: {e}"))
        );
    }
}
