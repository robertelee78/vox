//! V210-100 (#296) — **a vox that waits for another one's profile lock says so**, through the
//! shipped binary.
//!
//! Creating an identity (V210-91) and migrating a v0.2.9 profile (V210-100) each hold the profile
//! directory's lock, and a second vox on the same profile waits for it. That is a second or two
//! when the holder is working; but a holder that is stopped (Ctrl-Z) holds the lock until it is
//! resumed, and the vox waiting on it printed nothing at all — a person saw a hung `vox`. The wait
//! now says, once, after a second, that it is waiting for another vox using this profile, and how
//! to resume a stopped one.
//!
//! Staging, in two arms, one per path that takes the lock:
//! 1. **Create.** On a fresh profile, `vox id` A takes the lock and holds it
//!    (`VOX_TEST_LOCK_HOLD_MS`, proof-only, inert when unset, says when it has the lock). A is
//!    stopped with SIGSTOP, by its PID, and `vox id` B is started.
//! 2. **Migration.** The same on a profile the **released v0.2.9 binary** wrote, with
//!    `vox trust add` for A and B: A holds the lock to migrate it.
//!
//! Asserted, per arm: B says it is waiting for another vox using this profile within
//! [`SAYS_WITHIN`], exactly once, and is still running [`STOPPED_FOR`] later (it waits; it does not
//! fail). After SIGCONT to A, both finish within [`FINISHES_WITHIN`]: at least one exits 0, and
//! any that does not refuses with a reason that names the other vox (the concurrent creation, or
//! a vox holding the profile) — never anything else. A run that never saw A take the lock is CANNOT
//! MEASURE.
//!
//! Mutation that must turn it red: the waiting notice removed from the lock helper — B waits in
//! silence.

#![cfg(unix)]

#[path = "support/world.rs"]
mod world;

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/previous_release.rs"]
mod previous_release;

#[path = "support/test_knobs.rs"]
mod test_knobs;

use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

use previous_release::previous_release;
use world::{args, VoxProc, IDENTITY};

/// B must say it is waiting within this of starting (its own start-up, then the one-second
/// patience).
const SAYS_WITHIN: Duration = Duration::from_secs(15);
/// How long A stays stopped once B has said so: B must still be waiting at the end of it.
const STOPPED_FOR: Duration = Duration::from_secs(5);
/// Both must finish within this of A being resumed (production Argon2id, in a debug build too).
const FINISHES_WITHIN: Duration = Duration::from_secs(240);
/// How long A holds the lock once it has it, so it can be stopped holding it.
const HOLD_MS: &str = "4000";
const HOLDING: &str = "holding the profile lock";
const WAITING: &str = "waiting for another vox that is using this profile";
/// What a refused B may say: the concurrent creation, or a vox holding the profile.
const NAMED: [&str; 3] = [
    "another vox created this profile's identity at the same time",
    "a vox is already running for this profile",
    "another vox holds this profile open",
];

fn signal(pid: u32, sig: &str) {
    let ok = Command::new("kill")
        .args([sig, &pid.to_string()])
        .status()
        .is_ok_and(|s| s.success());
    assert!(ok, "APPARATUS: kill {sig} {pid}");
}

/// Wait up to `within` for `p` to exit; its status, or `None` if it is still running.
fn exited_within(p: &mut VoxProc, within: Duration) -> Option<std::process::ExitStatus> {
    let deadline = Instant::now() + within;
    loop {
        if let Some(s) = p.child.try_wait().expect("APPARATUS: poll a child process") {
            return Some(s);
        }
        if Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// One arm: A takes the lock and is stopped holding it, B waits; then A is resumed.
fn arm(label: &str, data: &Path, a_args: &[&str], b_args: &[&str]) -> Vec<String> {
    test_knobs::require(&["VOX_TEST_LOCK_HOLD_MS"]);
    let mut a = VoxProc::spawn_env(
        &format!("{label} A"),
        data,
        &args(a_args),
        &[("VOX_TEST_LOCK_HOLD_MS", HOLD_MS)],
    );
    a.expect_within(
        Duration::from_secs(180),
        "A holding the profile lock",
        |l| l.contains(HOLDING),
    );
    let a_pid = a.child.id();
    signal(a_pid, "-STOP");
    let t0 = Instant::now();
    let mut b = VoxProc::spawn(&format!("{label} B"), data, &args(b_args));
    // Not `expect_within`: a B that says nothing must be a red with counts, not a timeout panic.
    let mut said_at = None;
    while t0.elapsed() < SAYS_WITHIN && said_at.is_none() {
        if let Ok(line) = b.lines.recv_timeout(Duration::from_millis(100)) {
            eprintln!("[{label} B] {line}");
            if line.contains(WAITING) {
                said_at = Some(t0.elapsed());
            }
            b.seen.push(line);
        }
    }
    std::thread::sleep(STOPPED_FOR);
    let b_still_waiting = b
        .child
        .try_wait()
        .expect("APPARATUS: poll a child process")
        .is_none();
    let waited = t0.elapsed();
    signal(a_pid, "-CONT");
    let resumed = Instant::now();
    let a_status = exited_within(&mut a, FINISHES_WITHIN);
    let b_status = exited_within(&mut b, FINISHES_WITHIN.saturating_sub(resumed.elapsed()));
    let finished = resumed.elapsed();
    let b_said = b.transcript();
    let a_said = a.transcript();
    let notices = b_said.matches(WAITING).count();
    let b_named = NAMED.iter().any(|n| b_said.contains(n));
    let a_named = NAMED.iter().any(|n| a_said.contains(n));
    println!(
        "[proof] {label}: A held the lock and was stopped; B said it was waiting after {said_at:?} \
         (bound {SAYS_WITHIN:?}), {notices} time(s); B still waiting after {waited:?} = \
         {b_still_waiting}; after SIGCONT both finished in {finished:?}: A {a_status:?}, B \
         {b_status:?}, refusals name the other vox: A {a_named}, B {b_named}"
    );
    let mut red = Vec::new();
    if said_at.is_none() {
        red.push(format!(
            "{label}: B did not say it was waiting within {SAYS_WITHIN:?}; it said:\n{b_said}"
        ));
    }
    if notices > 1 {
        red.push(format!("{label}: B said it was waiting {notices} times"));
    }
    if !b_still_waiting {
        red.push(format!(
            "{label}: B exited while A was stopped, instead of waiting: {b_said}"
        ));
    }
    match (a_status, b_status) {
        (Some(sa), Some(sb)) => {
            // A B that held the store open while it waited can leave A refused for a busy
            // profile; that is named, and B goes on. What may not happen: an unnamed failure, or
            // neither getting through.
            if !sa.success() && !a_named {
                red.push(format!(
                    "{label}: A failed without naming the other vox: {a_said}"
                ));
            }
            if !sb.success() && !b_named {
                red.push(format!(
                    "{label}: B failed without naming the other vox: {b_said}"
                ));
            }
            if !sa.success() && !sb.success() {
                red.push(format!("{label}: neither A nor B got through"));
            }
        }
        _ => red.push(format!(
            "{label}: not finished {FINISHES_WITHIN:?} after SIGCONT: A {a_status:?}, B {b_status:?}"
        )),
    }
    red
}

#[test]
#[ignore = "real vox processes with production Argon2id, and the v0.2.9 release; CI runs it in release"]
fn a_vox_waiting_for_the_profile_says_so() {
    watchdog::arm_for(Duration::from_secs(if cfg!(debug_assertions) {
        1800
    } else {
        600
    }));
    let tmp = tempfile::tempdir().expect("APPARATUS: no temp dir");
    let dir = |n: &str| {
        let d = tmp.path().join(n);
        std::fs::create_dir_all(d.join("cfg")).expect("APPARATUS: create a staging directory");
        d
    };
    let mut red = Vec::new();

    // ---- 1. create: two `vox id`s on a fresh profile -------------------------------------
    red.extend(arm("create", &dir("fresh"), &["id"], &["id"]));

    // ---- 2. migration: two `vox trust add`s on a profile v0.2.9 wrote ------------------------
    let old = previous_release();
    let (carol, x, y) = (dir("carol"), dir("x"), dir("y"));
    let run_old = |data: &Path, argv: &[&str]| {
        let out = Command::new(&old)
            .args(argv)
            .env("VOX_DATA_DIR", data)
            .env("VOX_CONFIG_DIR", data.join("cfg"))
            .env("VOX_IDENTITY_PASSPHRASE", IDENTITY)
            .output()
            .expect("APPARATUS: run a process");
        assert!(
            out.status.success(),
            "CANNOT MEASURE: v0.2.9 `vox {argv:?}` failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).trim().to_owned()
    };
    run_old(&carol, &["id"]);
    let x_fp = run_old(&x, &["id"]);
    let y_fp = run_old(&y, &["id"]);
    red.extend(arm(
        "migration",
        &carol,
        &["trust", "add", &x_fp, "--name", "x"],
        &["trust", "add", &y_fp, "--name", "y"],
    ));

    assert!(red.is_empty(), "PRODUCT: {red:#?}");
}
